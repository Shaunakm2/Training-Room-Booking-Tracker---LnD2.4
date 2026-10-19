// js/api/supabase-client.js
// Client init + the one function that loads all booking data. Everything
// else in api/ assumes `supabase` (exported here) is already initialized.

import { SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY } from '../config.js';
import { bookings, setBookings } from '../state.js';
import { createdSortKey } from '../utils/ids.js';

import { toast, showLoadingOverlay } from '../utils/dom-helpers.js';

// `window.supabase` here is the global injected by the Supabase JS SDK
// script tag in index.html. Exported so api/bookings.js, api/auth.js etc.
// can import and reuse the same client instance rather than each creating
// their own.
export const supabase = window.supabase.createClient(SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY);

let _writeCompletedAt = 0;
export function markWriteCompleted() { _writeCompletedAt = Date.now(); }

// Prevent a silent background refresh from wiping out an optimistic local
// update before the database write has actually landed.
function writeRecentlyCompleted() {
  return (Date.now() - _writeCompletedAt) < 3000;
}

// ---- Change marker ----
// The 60-second poll and every tab focus used to download the WHOLE bookings
// table, even when nothing had changed. bookings_change_marker() (schema.sql
// section 9) returns two small counters that move on every booking change.
// Background refreshes ask for it first and download bookings only when it
// differs from the value seen at the last full load.
//
// Safety nets:
//   - The marker is read BEFORE the rows. A change landing between the two
//     is then included in the rows AND makes the next probe differ, so it
//     costs at most one extra reload — it can never be missed.
//   - If the marker cannot be read (network, or the SQL not deployed yet),
//     the poll falls back to a full reload, i.e. the old behaviour.
//   - A full reload still happens at least every FULL_RELOAD_MS regardless.
// Pre-flight checks before a save do NOT use this: they always call
// loadData(true, true) directly, because a decision is about to be made.
const FULL_RELOAD_MS = 10 * 60 * 1000;
let _lastMarker = null;      // JSON of the marker that matches `bookings`
let _lastFullLoadAt = 0;

async function readMarker() {
  try {
    const { data, error } = await supabase.rpc('bookings_change_marker');
    if (error || data == null) return null;
    return JSON.stringify(data);
  } catch (_) {
    return null;
  }
}

// Background refresh. Returns true when bookings were re-downloaded.
export async function refreshIfChanged() {
  const marker = await readMarker();
  const fresh = Date.now() - _lastFullLoadAt < FULL_RELOAD_MS;
  if (marker !== null && marker === _lastMarker && fresh) return false;
  return (await loadData(true)) === true;
}

// Returns true when fresh data was loaded, false when the fetch failed (the
// previous data is kept). Pre-flight callers use this to refuse to make a
// decision on stale data. Returns undefined when a silent poll was skipped by
// the write debounce — only possible without force=true.
//
// silent: no loading overlay, and subject to the write debounce.
// force:  bypass the debounce. Use for a DELIBERATE pre-flight refresh before
//         a conflict check — that is not the same thing as a background poll.
//         The debounce exists to stop the 60s poll clobbering an in-flight
//         optimistic update, but it also silently no-op'd the refresh that
//         runs just before a save, so two bookings created within 3 seconds
//         of each other could miss a conflict between them.
export async function loadData(silent = false, force = false) {
  if (silent && !force && writeRecentlyCompleted()) return;
  try {
    if (!silent) showLoadingOverlay(true);
    // Read BEFORE the rows — see the note on the change marker above.
    const marker = await readMarker();
    const { data, error } = await supabase
      .from('bookings')
      .select('*')
      // Most relevant/recent dates first, so if the row cap below is ever
      // hit again, today's and future bookings are prioritized over old
      // history rather than silently missing.
      .order('booking_date', { ascending: false })
      // Supabase/PostgREST defaults to a silent 1000-row cap on unpaginated
      // selects — that was a real bug found earlier: today's bookings
      // simply weren't in the first 1000 rows returned, and the app showed
      // an empty schedule with no error. This explicitly requests up to
      // 5000. (Also requires "Max Rows" raised in the Supabase dashboard —
      // this alone is necessary but not sufficient.)
      .range(0, 4999);

    if (error) throw error;
    // Second layer of defence for the booking_id XSS (the first is a CHECK
    // constraint in the database). booking_id is pasted directly into
    // onclick="..." attributes by the admin table and pending list, so a value
    // containing a quote mark would break out and run as JavaScript in the
    // admin's session. genId() only ever produces [a-z0-9]; anything else has
    // no legitimate source, so drop the row rather than render it.
    const ID_OK = /^[A-Za-z0-9_-]{1,40}$/;
    const mapped = (data || []).filter(r => {
      const raw = String(r.booking_id || '').trim();
      if (ID_OK.test(raw)) return true;
      console.error('Dropped booking with unsafe booking_id:', JSON.stringify(raw));
      return false;
    }).map(r => ({
      id: String(r.booking_id || '').trim(),
      room: String(r.room || '').trim(),
      booker: String(r.booked_by || '').trim(),
      purpose: String(r.purpose || '').trim(),
      date: String(r.booking_date || '').trim(),
      start: String(r.start_time || '00:00:00').trim().substring(0, 5),
      end: String(r.end_time || '00:00:00').trim().substring(0, 5),
      attendees: r.attendees != null ? String(r.attendees) : '',
      status: String(r.status || 'Confirmed').trim(),
      endDate: String(r.end_date || '').trim(),
      conflictResolved: !!r.conflict_resolved,
      conflictNote: String(r.conflict_note || '').trim(),
      // Real creation time from the column, in ms, or null.
      //
      // created_at is NULLABLE by design: rows predating the column have no
      // recoverable creation time, and defaulting them to now() would make
      // the oldest rows look newest. It is NOT fully backfilled — a null was
      // found in production when it broke an archive run. So every consumer
      // must handle null, which is why creationMs() stays as the fallback
      // rather than being deleted.
      createdAtMs: r.created_at ? Date.parse(r.created_at) : null
    }));
    // Newest created first. Prefers the created_at column and falls back to
    // decoding the id, for rows where created_at is null.
    //
    // NEVER compare id strings directly: legacy ids have no 'b' prefix and
    // 'z...' beats every 'b...' lexicographically, which pinned the same old
    // rows to the top of "Recently Added" forever. That bug shipped twice.
    mapped.sort((a, b) => createdSortKey(b) - createdSortKey(a));
    setBookings(mapped);
    _lastMarker = marker;
    _lastFullLoadAt = Date.now();
    return true;
  } catch (e) {
    console.error('Load error', e);
    // Do NOT blank the list. This used to call setBookings([]), and since
    // loadData(true) runs every 60 seconds, one dropped packet emptied every
    // room card, the timeline and the admin table until the next successful
    // poll up to a minute later. Showing slightly stale data beats throwing
    // away good data because a refresh failed.
    if (bookings.length === 0) setBookings([]);
    toast(silent
      ? 'Refresh failed — showing last known data.'
      : 'Could not load bookings. Check connection.', true);
    return false;
  } finally {
    if (!silent) showLoadingOverlay(false);
  }
}
