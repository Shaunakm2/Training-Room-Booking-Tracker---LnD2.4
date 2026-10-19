// js/api/bookings.js
// Every booking write goes through a Postgres RPC that runs as ONE
// transaction (see supabase/schema.sql section 14). A multi-row action either
// fully succeeds or changes nothing — there is no partial-save state for the
// UI to reconcile. The database also enforces the Confirmed-overlap rule and
// writes the audit trail, so neither depends on this file being correct.
//
// Each function throws on failure and marks the write-debounce timestamp on
// success. UI-layer code (ui/*.js) owns optimistic updates and messages.
import { supabase, markWriteCompleted } from './supabase-client.js';
import { isOvernight, addDaysStr } from '../domain/time.js';

// One random key per user submission. Sending the same key again (double
// click, retry, second tab) returns the first result instead of creating the
// bookings twice. 18 random bytes -> 36 hex chars; the server accepts
// [A-Za-z0-9_-]{16,100}.
export function newRequestKey() {
  const bytes = new Uint8Array(18);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, x => x.toString(16).padStart(2, '0')).join('');
}

// App booking object -> database row.
function toRow(b, statusOverride) {
  const endDate = b.endDate || (isOvernight(b) ? addDaysStr(b.date, 1) : b.date);
  const att = b.attendees === '' || b.attendees == null ? null : Number(b.attendees);
  return {
    booking_id: b.id,
    room: b.room,
    booked_by: b.booker,
    purpose: b.purpose || '',
    booking_date: b.date,
    start_time: b.start,
    end_time: b.end,
    attendees: Number.isFinite(att) ? att : null,
    status: statusOverride || b.status || 'Confirmed',
    end_date: endDate,
    conflict_resolved: !!b.conflictResolved,
    conflict_note: b.conflictNote || '',
  };
}

async function callRpc(name, args) {
  const { data, error } = await supabase.rpc(name, args);
  if (error) throw error;
  if (!data || data.ok !== true) throw new Error((data && data.error) || `${name} failed.`);
  markWriteCompleted();
  return data;
}

// Human-readable reason for a failed write. Server messages are safe to show
// as text (callers put them in textContent / toast, never innerHTML).
export function describeWriteError(e) {
  const code = e && e.code;
  const msg = String((e && e.message) || '');
  if (code === '23P01' || msg.includes('ROOM_CONFLICT')) {
    return 'Another confirmed booking already occupies this room at that time. Nothing was saved.';
  }
  if (code === '23514') return 'The booking details are invalid (check the dates, times and name). Nothing was saved.';
  if (code === '42501') return 'You are not allowed to do that. Please log in again if you are the admin.';
  if (code === 'P0002') return msg || 'One of the selected bookings no longer exists. Nothing was changed.';
  if (msg.startsWith('Rate limit')) return msg;
  if (msg.includes('holds up to')) return msg;
  if (msg.includes('past date')) return msg;
  return 'The change could not be saved. Check your connection and try again. Nothing was changed.';
}

// ---- Create ----
export async function apiCreateBatch(bookingsArr, { allowConflicts = false, requestKey = newRequestKey() } = {}) {
  return callRpc('create_bookings_atomic', {
    p_rows: bookingsArr.map(b => toRow(b)),
    p_request_key: requestKey,
    p_allow_conflicts: !!allowConflicts,
  });
}

export async function apiCreate(b) {
  return apiCreateBatch([b]);
}

// Public request form: always Pending (the server enforces this too).
export async function apiCreateRequestBatch(bookingsArr, requestKey = newRequestKey()) {
  return callRpc('create_bookings_atomic', {
    p_rows: bookingsArr.map(b => toRow(b, 'Pending')),
    p_request_key: requestKey,
    p_allow_conflicts: false,
  });
}

// ---- Update ----
// allowConflicts = the admin explicitly chose "Approve anyway".
export async function apiUpdate(b, allowConflicts = false) {
  return callRpc('update_booking_atomic', { p_row: toRow(b), p_allow_conflicts: !!allowConflicts });
}

export async function apiUpdateStatusBatch(ids, status, allowConflicts = false) {
  return callRpc('update_booking_statuses_atomic', {
    p_ids: ids, p_status: status, p_allow_conflicts: !!allowConflicts,
  });
}

export async function apiUpdateStatus(id, status, allowConflicts = false) {
  return apiUpdateStatusBatch([id], status, allowConflicts);
}

// items: [{ id, room|null, override: boolean }] — one transaction for all.
export async function apiApproveWithResolutions(items) {
  return callRpc('approve_bookings_atomic', {
    p_items: items.map(it => ({ booking_id: it.id, room: it.room || null, override: !!it.override })),
  });
}

// Only touches conflict_resolved / conflict_note; RLS limits it to the admin
// and the audit trigger records it.
export async function apiSetConflictResolved(id, resolved, note) {
  const { error } = await supabase.from('bookings')
    .update({ conflict_resolved: !!resolved, conflict_note: note || '' })
    .eq('booking_id', id);
  if (error) throw error;
  markWriteCompleted();
}

// Recurring edit: delete the original and create the replacements in one
// transaction. If anything fails, the original is untouched.
export async function apiReplaceRecurring(originalId, bookingsArr, requestKey = newRequestKey()) {
  return callRpc('replace_booking_atomic', {
    p_original_id: originalId,
    p_rows: bookingsArr.map(b => toRow(b)),
    p_request_key: requestKey,
  });
}

// ---- Delete ----
export async function apiDeleteBatch(ids) {
  return callRpc('delete_bookings_atomic', { p_ids: ids });
}

export async function apiDelete(id) {
  return apiDeleteBatch([id]);
}

// ---- Public self-service (unchanged) ----
// SECURITY DEFINER functions that re-verify the name server-side. Both are
// recorded in the audit trail with the caller's role and IP.
export async function apiCancelOwn(id, bookerName) {
  const { data, error } = await supabase.rpc('cancel_own_booking', {
    p_booking_id: id, p_booker_name: bookerName
  });
  if (error) throw error;
  if (!data.ok) throw new Error(data.error);
  markWriteCompleted();
}

export async function apiReleaseOwn(id, bookerName, endTime, endDate) {
  const { data, error } = await supabase.rpc('release_own_booking', {
    p_booking_id: id, p_booker_name: bookerName, p_end_time: endTime, p_end_date: endDate
  });
  if (error) throw error;
  if (!data.ok) throw new Error(data.error);
  markWriteCompleted();
}
