// js/app.js — THE ENTRY POINT
// index.html loads this as: <script type="module" src="js/app.js"></script>
//
// CRITICAL: index.html has hundreds of inline onclick="functionName(...)"
// attributes. ES modules are scoped by default — a function inside a
// module is NOT automatically callable from an inline onclick anymore.
// Every single handler referenced anywhere in index.html's onclick/
// onchange/onkeydown attributes MUST be explicitly exposed on `window`
// below, or that button/input silently stops working with no error.
// If you add a new onclick in index.html later, add its function here too.

import { bookings, adminLoggedIn } from './state.js';
import { todayStr } from './domain/time.js';
import { toast, updateClock } from './utils/dom-helpers.js';
import { loadData, refreshIfChanged } from './api/supabase-client.js';
import { doLogin, doLogout, closeLogin, requireAdmin, restoreSession, expireSession, adminHeartbeat, ACTIVITY_KEY } from './api/auth.js';
import { ADMIN_IDLE_TIMEOUT_MIN, ADMIN_IDLE_WARNING_MIN, ADMIN_HEARTBEAT_SEC } from './config.js';
import { notifyTeams } from './api/notifications.js';

import { showPage } from './ui/pages.js';
import { renderStatusGrid } from './ui/status-grid.js';
import {
  renderTable, goToPage, renderActiveNow, adminReleaseEarly,
  populateRoomSelects, updateFCapacityHint, resetForm, editBooking,
  showError, toggleRecurring, submitBooking, deleteBooking, confirmDelete,
  getSelectedIds, updateBulkBar, onRowCbChange, toggleSelectAll,
  clearBulkSelection, bulkApprove, bulkCancel, bulkDelete, exportExcel,
  onFilterChange, onSortChange,
} from './ui/admin-table.js';
import {
  updatePendingDot, renderPendingRequests, toggleModifyForm, approvePending,
  modifyAndApprove, openRejectModal, confirmReject, getPendingSelectedIds,
  updatePendingBulkBar, onPendingCbChange, togglePendingSelectAll,
  clearPendingSelection, bulkApprovePending, bulkRejectPending,
} from './ui/pending-list.js';
import {
  openConflictModal, selectAlt, selectApprovalResolution,
  openApprovalConflictModal, closeConflictModal, confirmConflictResolution,
} from './ui/conflict-picker.js';
import {
  openRequestModal, closeRequestModal, validateReqTimes, toggleReqRecurring,
  updateReqCapacityHint, submitRequest,
} from './ui/request-form.js';
import { openSchedModal, closeSchedModal, closeSchedIfBg } from './ui/schedule-modal.js';
import { openCancelModal, openReleaseModal, closeCancelModal, confirmCancelOrRelease } from './ui/cancel-release.js';
import {
  renderTimeline, showTlTooltip, hideTlTooltip, hideTlTooltipDelayed,
  setTimelineDay, shiftTimelineDay, toggleTimeline, initTimelineListeners,
} from './ui/timeline.js';
import { toggleSunflowerFaq, toggleSunflowerHelp, initSunflowerListeners } from './ui/sunflower-help.js';
import { showConfirmModal, resolveConfirmModal } from './utils/dom-helpers.js';

// toggleConflictResolved lives conceptually with conflicts, but touches
// state/UI directly — kept here rather than in domain/conflicts.js to
// avoid that file needing UI-layer imports.
import { getLiveConflicts } from './domain/conflicts.js';
import { apiSetConflictResolved } from './api/bookings.js';

let _resolveConflictBookingId = null;

async function toggleConflictResolved(bookingId) {
  const b = bookings.find(x => x.id === bookingId);
  if (!b) return;

  if (b.conflictResolved) {
    const prevNote = b.conflictNote;
    b.conflictResolved = false;
    b.conflictNote = '';
    renderPendingRequests(); renderTable(); renderStatusGrid();
    try {
      await apiSetConflictResolved(bookingId, false, '');
      toast('Conflict warning restored.');
    } catch (e) {
      b.conflictResolved = true; b.conflictNote = prevNote;
      renderPendingRequests(); renderTable(); renderStatusGrid();
      toast('Could not update — check connection.', true);
    }
    return;
  }

  _resolveConflictBookingId = bookingId;
  const liveConflicts = getLiveConflicts(b);
  const { fmtTime, fmtDate } = await import('./utils/formatting.js');
  const thisOne = `${b.booker}, ${fmtTime(b.start)}–${fmtTime(b.end)} on ${fmtDate(b.date)}`;
  const otherOnes = liveConflicts.map(c => `${c.booker}, ${fmtTime(c.start)}–${fmtTime(c.end)} on ${fmtDate(c.date)} (${c.status})`).join('\n');
  document.getElementById('resolve-conflict-details').textContent = `Resolving conflict for:\n  ${thisOne}\nagainst:\n  ${otherOnes}`;
  document.getElementById('resolve-conflict-note').value = b.conflictNote || '';
  document.getElementById('resolve-conflict-modal').style.display = 'flex';
}

function closeResolveConflictModal() {
  document.getElementById('resolve-conflict-modal').style.display = 'none';
  _resolveConflictBookingId = null;
}

async function confirmResolveConflict() {
  const bookingId = _resolveConflictBookingId;
  const b = bookings.find(x => x.id === bookingId);
  if (!b) { closeResolveConflictModal(); return; }
  const trimmedNote = document.getElementById('resolve-conflict-note').value.trim();
  closeResolveConflictModal();
  b.conflictResolved = true;
  b.conflictNote = trimmedNote;
  renderPendingRequests(); renderTable(); renderStatusGrid();
  try {
    await apiSetConflictResolved(bookingId, true, trimmedNote);
    toast('Marked as resolved.');
  } catch (e) {
    b.conflictResolved = false; b.conflictNote = '';
    renderPendingRequests(); renderTable(); renderStatusGrid();
    toast('Could not update — check connection.', true);
  }
}

// ============================================================
// EXPOSE every function referenced by an inline onclick/onchange/onkeydown
// in index.html. Names on the left MUST match exactly what index.html calls.
// ============================================================
Object.assign(window, {
  // pages / auth
  showPage, doLogin, doLogout, closeLogin, requireAdmin,
  // status grid / timeline / schedule
  renderStatusGrid, renderTimeline, showTlTooltip, hideTlTooltip, hideTlTooltipDelayed,
  setTimelineDay, shiftTimelineDay, toggleTimeline,
  openSchedModal, closeSchedModal, closeSchedIfBg,
  // request form
  openRequestModal, closeRequestModal, validateReqTimes, toggleReqRecurring,
  updateReqCapacityHint, submitRequest,
  // cancel/release
  openCancelModal, openReleaseModal, closeCancelModal, confirmCancelOrRelease,
  // admin table
  renderTable, goToPage, renderActiveNow, adminReleaseEarly,
  populateRoomSelects, updateFCapacityHint, resetForm, editBooking,
  showError, toggleRecurring, submitBooking, deleteBooking, confirmDelete,
  getSelectedIds, updateBulkBar, onRowCbChange, toggleSelectAll,
  clearBulkSelection, bulkApprove, bulkCancel, bulkDelete, exportExcel,
  onFilterChange, onSortChange,
  // pending list
  updatePendingDot, renderPendingRequests, toggleModifyForm, approvePending,
  modifyAndApprove, openRejectModal, confirmReject, getPendingSelectedIds,
  updatePendingBulkBar, onPendingCbChange, togglePendingSelectAll,
  clearPendingSelection, bulkApprovePending, bulkRejectPending,
  // conflict picker
  openConflictModal, selectAlt, selectApprovalResolution,
  openApprovalConflictModal, closeConflictModal, confirmConflictResolution,
  // conflict-resolved toggle (defined in this file)
  toggleConflictResolved, closeResolveConflictModal, confirmResolveConflict,
  // sunflower
  toggleSunflowerFaq, toggleSunflowerHelp,
  // generic confirm modal — NOTE: index.html's button almost certainly
  // calls this with its ORIGINAL underscore-prefixed name from before the
  // refactor. Exposed under BOTH names so it works regardless of which
  // one index.html actually has, without needing to also edit the HTML.
  showConfirmModal,
  _resolveConfirmModal: resolveConfirmModal,
  resolveConfirmModal,
});

// ============================================================
// Admin idle timeout — configured in js/config.js (ADMIN_IDLE_*).
// Kept here rather than in state.js because it needs showPage/toast and the
// state setters together, which would create a circular import.
//
// TWO LAYERS
//   Browser (this file): signs out after ADMIN_IDLE_TIMEOUT_MIN without
//     activity, warns ADMIN_IDLE_WARNING_MIN before. Clicks, keys, scroll,
//     mouse move and touch count; the clock is shared across tabs.
//   Server (schema.sql section 10b): real activity is reported with
//     admin_heartbeat() at most every ADMIN_HEARTBEAT_SEC. is_admin() refuses
//     any session not heard from within the server limit (timeout + 2 min),
//     so the timeout holds even if this code is bypassed, the tab is frozen,
//     or the token is copied elsewhere. Background refreshes do NOT send
//     heartbeats — only a person using the page keeps the session alive.
//
// The last-activity timestamp is mirrored into localStorage because the
// setInterval below only runs while a tab is open. Without persistence the
// clock restarts at zero on every page load, so the timeout could only ever
// fire in a tab left open and untouched — which is not how an unattended
// session actually happens. Closing the browser overnight and returning to a
// live admin panel was the symptom.
// ============================================================
const SESSION_TIMEOUT_MS = ADMIN_IDLE_TIMEOUT_MIN * 60 * 1000;
const SESSION_WARNING_MS = ADMIN_IDLE_WARNING_MIN * 60 * 1000;
const HEARTBEAT_MS = ADMIN_HEARTBEAT_SEC * 1000;
let _lastActivityAt = 0;      // set from storage at startup / on activity
let _sessionWarningShown = false;
let _lastTouchWrite = 0;
let _lastHeartbeatAt = 0;
let _ending = false;

// Last activity across ALL tabs. _lastActivityAt is per-tab; the localStorage
// stamp is shared. Taking the max stops a second tab that has been sitting
// idle from expiring a session the user has been actively using elsewhere.
function _lastActivitySeen() {
  let stored = 0;
  try { stored = Number(localStorage.getItem(ACTIVITY_KEY)) || 0; } catch (_) {}
  return Math.max(_lastActivityAt || 0, stored);
}

// Report activity to the server, throttled. Fire-and-forget: only an
// explicit 'expired' ends the session; a network blip is retried on the
// next activity (and the server enforces the limit regardless).
function _maybeHeartbeat(now) {
  if (!adminLoggedIn || now - _lastHeartbeatAt < HEARTBEAT_MS) return;
  _lastHeartbeatAt = now;
  adminHeartbeat().then(r => { if (r === 'expired') _endSession(); });
}

function _touchActivity() {
  const now = Date.now();
  // mousemove fires dozens of times a second; throttle first, for cost.
  if (now - _lastTouchWrite < 5000) return;
  _lastTouchWrite = now;

  // CHECK BEFORE RESETTING. This is the whole point of the function.
  //
  // The watchdog below only samples every 15 seconds, but activity events
  // arrive instantly. So the first mousemove after the laptop woke from an
  // overnight sleep used to set _lastActivityAt = now BEFORE the interval
  // ever observed the gap — the act of returning to the machine erased the
  // evidence of having been away, and the session survived indefinitely.
  // Suspended tabs have frozen timers, so the interval cannot win that race
  // reliably.
  //
  // An event arriving after the timeout has already elapsed IS the return
  // from an idle period, not activity during one.
  const last = _lastActivitySeen();
  if (adminLoggedIn && last && now - last > SESSION_TIMEOUT_MS) {
    _endSession();
    return;
  }

  _lastActivityAt = now;
  _sessionWarningShown = false;
  try { localStorage.setItem(ACTIVITY_KEY, String(now)); } catch (_) {}
  _maybeHeartbeat(now);
}

// scroll and mousemove count as activity: at 10 minutes, someone reading a
// long pending list without clicking is not idle, and logging them out
// mid-task is the fastest way to get the timeout disabled again.
['click', 'keydown', 'scroll', 'mousemove', 'touchstart'].forEach(
  ev => document.addEventListener(ev, _touchActivity, { passive: true })
);

async function _endSession() {
  if (_ending) return;           // several triggers can fire together
  _ending = true;
  try {
    // expireSession() ends the session at the SERVER (admin_end_session),
    // then signs this browser out. Clearing only the in-memory flags would
    // leave the persisted session intact, and restoreSession() in init()
    // would log the admin straight back in on the next refresh.
    await expireSession();
    // Reload as anon: the admin view includes Rejected/Cancelled rows that
    // the public must not keep seeing on this screen after sign-out.
    try { await loadData(); } catch (_) {}
    window.dispatchEvent(new CustomEvent('ldrooms:data-refreshed'));
  } finally {
    _sessionWarningShown = false;
    _lastHeartbeatAt = 0;
    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) logoutBtn.style.display = 'none';
    showPage('status');
    toast('Session expired. Please log in again.');
    _ending = false;
  }
}

// The server refused an admin call (session ended there: idle limit, or
// signed out on another tab). Sign this browser out too.
window.addEventListener('ldrooms:admin-session-invalid', () => {
  if (adminLoggedIn) _endSession();
});

// Another tab logged out or timed out: it removed the shared stamp.
window.addEventListener('storage', e => {
  if (e.key === ACTIVITY_KEY && e.newValue === null && adminLoggedIn) _endSession();
});

setInterval(() => {
  if (!adminLoggedIn) return;
  const idleFor = Date.now() - _lastActivitySeen();
  if (idleFor > SESSION_TIMEOUT_MS) {
    _endSession();
  } else if (idleFor > SESSION_TIMEOUT_MS - SESSION_WARNING_MS && !_sessionWarningShown) {
    _sessionWarningShown = true;
    toast(`Your session will expire in ${ADMIN_IDLE_WARNING_MIN} minutes due to inactivity — click anywhere to stay logged in.`, false, 7000);
  }
}, 15000);

// Decide, BEFORE any admin screen is shown, whether a session restored from
// storage may continue. Fails CLOSED: no activity stamp (storage cleared,
// first run after an upgrade) is treated as stale, and the server must agree
// the session is still live.
async function _resumeAdminSessionIfFresh() {
  if (!(await restoreSession())) return false;
  let stored = 0;
  try { stored = Number(localStorage.getItem(ACTIVITY_KEY)) || 0; } catch (_) {}
  if (!stored || Date.now() - stored > SESSION_TIMEOUT_MS) {
    await _endSession();
    return false;
  }
  _lastActivityAt = stored;
  const hb = await adminHeartbeat();
  if (hb === 'expired') {
    await _endSession();
    return false;
  }
  _lastHeartbeatAt = Date.now();
  return true;
}

window.addEventListener('beforeunload', e => {
  const booker = document.getElementById('f-booker')?.value;
  if (booker && adminLoggedIn) {
    e.preventDefault();
    e.returnValue = '';
  }
});

// ============================================================
// INIT
// ============================================================
async function init() {
  // Before anything else: if an admin session survived the reload and is
  // still fresh (browser stamp AND server agree), pick it back up so a
  // refresh doesn't log the admin out. Checked BEFORE showing the admin page,
  // so a stale session never flashes the panel.
  if (await _resumeAdminSessionIfFresh()) showPage('admin');

  populateRoomSelects();
  document.getElementById('f-date').value = todayStr();
  updateClock();
  setInterval(updateClock, 1000);
  await loadData();
  updatePendingDot();
  renderStatusGrid();
  renderTimeline();
  initSunflowerListeners();
  initTimelineListeners();

  // Every 60s: re-render (room cards and "ending soon" depend on the clock),
  // but only re-DOWNLOAD bookings if something changed — refreshIfChanged()
  // asks a tiny change-marker RPC first. See api/supabase-client.js.
  setInterval(async () => {
    if (document.hidden) return;
    await refreshIfChanged();
    updatePendingDot();
    if (document.getElementById('page-status').classList.contains('active')) {
      renderStatusGrid();
      const tlWrap = document.getElementById('timeline-wrap');
      if (tlWrap && tlWrap.style.display !== 'none') renderTimeline();
    }
    if (document.getElementById('page-admin').classList.contains('active')) {
      renderTable();
      renderActiveNow();
      renderPendingRequests();
    }
  }, 60000);

  // auth.js refetches after sign-in and sign-out, because the restrictive
  // policy "Public sees only active bookings" makes the visible row set
  // role-dependent. It fires this event rather than calling renders itself,
  // which would mean importing the ui layer into the api layer.
  window.addEventListener('ldrooms:data-refreshed', () => {
    updatePendingDot();
    renderStatusGrid();
    renderTimeline();
    renderTable();
    renderActiveNow();
    renderPendingRequests();
  });

  document.addEventListener('visibilitychange', async () => {
    if (!document.hidden) {
      await refreshIfChanged();
      updatePendingDot();
      if (document.getElementById('page-status').classList.contains('active')) renderStatusGrid();
      if (document.getElementById('page-admin').classList.contains('active')) {
        renderTable(); renderActiveNow(); renderPendingRequests();
      }
    }
  });

  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('sw.js').catch(err => {
      console.error('Service worker registration failed:', err);
    });
  }
}

init();
