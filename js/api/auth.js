// js/api/auth.js
// Admin sign-in/out. Note: this imports showPage/toast (UI-layer concerns)
// because the original login flow directly navigates on success — a
// stricter architecture would have the UI layer call doLogin() and handle
// navigation itself via the return value, but that's a bigger behavioral
// change than a straight refactor should make. Flagged here for later.

import { supabase, loadData } from './supabase-client.js';
import { ADMIN_EMAIL } from '../config.js';
import {
  adminLoggedIn,
  loginAttempts, setLoginAttempts, loginLockedUntil, setLoginLockedUntil,
  MAX_LOGIN_ATTEMPTS, LOCKOUT_MS,
  setAdminLoggedIn
} from '../state.js';

// Shared last-activity stamp (all tabs). Owned here; js/app.js imports it.
export const ACTIVITY_KEY = 'ldrooms-last-activity';

// ---- Server-side session (schema.sql section 10b) ----
// The browser timer alone is advice: the Supabase session survives in
// localStorage and the server would honour it. These calls make the server
// track real activity and refuse an idle session (is_admin() = false).

// Report real user activity. Returns 'ok', 'expired' (the server has ended
// this session: sign out now) or 'error' (network etc.: keep going, the next
// activity retries; the server still enforces the limit on its own).
export async function adminHeartbeat() {
  try {
    const { data, error } = await supabase.rpc('admin_heartbeat');
    if (error) return error.code === '42501' ? 'expired' : 'error';
    return data && data.ok === true ? 'ok' : 'expired';
  } catch (_) {
    return 'error';
  }
}

// End the session at the server, then locally. scope 'local' signs out THIS
// browser only: the admin account is shared, and the SDK default ('global')
// would sign out every other device using it too.
async function endAdminSession() {
  try { await supabase.rpc('admin_end_session'); } catch (_) { /* server still expires it on its own */ }
  try { await supabase.auth.signOut({ scope: 'local' }); } catch (_) { /* clear local state regardless */ }
  try { localStorage.removeItem(ACTIVITY_KEY); } catch (_) {}
}
import { toast, showLoadingOverlay } from '../utils/dom-helpers.js';
import { showPage } from '../ui/pages.js'; // see note above

export function requireAdmin() {
  if (adminLoggedIn) {
    showPage('admin');
  } else {
    document.getElementById('login-modal').style.display = 'flex';
    setTimeout(() => document.getElementById('login-pw').focus(), 50);
  }
}

// Restore an admin session on page load.
// supabase-js persists the session in localStorage, so a refresh does NOT
// sign you out at the Supabase level — but `adminLoggedIn` is an in-memory
// `let` in state.js and resets to false, so the app forgot it was logged in
// and demanded the password again. Ask Supabase what the real state is
// instead of assuming.
export async function restoreSession() {
  try {
    const { data, error } = await supabase.auth.getSession();
    const session = data?.session;
    if (error || !session) return false;
    // Only trust a session belonging to the admin account. Any other user
    // (or a stale session from a different project) is ignored.
    if ((session.user?.email || '').toLowerCase() !== ADMIN_EMAIL.toLowerCase()) return false;
    setAdminLoggedIn(true);
    const btn = document.getElementById('logout-btn');
    if (btn) btn.style.display = '';
    return true;
  } catch (e) {
    console.error('Session restore failed:', e);
    return false;
  }
}

// Called by the idle-timeout watchdog in app.js. MUST actually sign out at
// the Supabase level, not just clear the in-memory flags — otherwise the
// persisted session survives and restoreSession() would hand the panel
// straight back on the next refresh, defeating the timeout entirely.
export async function expireSession() {
  setAdminLoggedIn(false);
  await endAdminSession();
}

export async function doLogout() {
  setAdminLoggedIn(false);
  // Ends the session at the server first, then signs this browser out, and
  // clears the idle-timer stamp so a later page load doesn't evaluate a
  // stale timestamp against a fresh session.
  await endAdminSession();
  // Refetch as anon for the same reason as in doLogin: otherwise the browser
  // keeps showing admin-visible rows (rejected, cancelled) after sign-out
  // until the next page load.
  try { await loadData(); } catch (_) {}
  window.dispatchEvent(new CustomEvent('ldrooms:data-refreshed'));
  document.getElementById('logout-btn').style.display = 'none';
  showPage('status');
  toast('Logged out.');
}

export async function doLogin() {
  const pw = document.getElementById('login-pw').value;
  if (!pw) return;

  // Enforce the client-side lockout. setLoginLockedUntil() was being called
  // below and the "Locked for 5 minutes" message shown, but NOTHING ever read
  // the value — so the very next attempt went straight through. The message
  // was cosmetic. This is UX feedback only; the real limits are the
  // check_login_rate_limit RPC (10 / 5 min) and Supabase's own GoTrue limit
  // (30 / 5 min). A page refresh clears this, which is exactly why the
  // server-side limiter exists.
  if (loginLockedUntil && Date.now() < loginLockedUntil) {
    const secs = Math.ceil((loginLockedUntil - Date.now()) / 1000);
    document.getElementById('login-error').textContent =
      `Locked due to failed attempts. Try again in ${secs}s.`;
    document.getElementById('login-error').classList.add('visible');
    return;
  }
  // Real, server-enforced rate limiting — this RPC call must succeed
  // before we're even allowed to attempt the actual sign-in. Unlike a
  // client-side-only counter (trivially bypassed by refreshing the page),
  // this lives in Postgres and can't be reset by the browser. See
  // supabase/schema.sql's check_login_rate_limit() for the server side.
  try {
    const { data: rl, error: rlErr } = await supabase.rpc('check_login_rate_limit');
    if (!rlErr && rl && rl.ok === false) {
      document.getElementById('login-error').textContent = `Too many attempts. Try again in ${rl.retry_after_seconds}s.`;
      document.getElementById('login-error').classList.add('visible');
      return;
    }
  } catch (e) {
    // If the rate-limit check itself fails (network issue etc), fail safe
    // by still allowing the attempt — never let an outage lock out the
    // legitimate admin. The real sign-in call below still requires the
    // correct password regardless.
  }

  try {
    showLoadingOverlay(true);
    const { data, error } = await supabase.auth.signInWithPassword({ email: ADMIN_EMAIL, password: pw });
    if (!error && data.session) {
      // Start the server-side activity clock BEFORE treating the admin as
      // signed in. Without it the server refuses every admin action, so a
      // failure here must stop the login, not leave a panel that cannot save.
      const hb = await adminHeartbeat();
      if (hb !== 'ok') {
        try { await supabase.auth.signOut({ scope: 'local' }); } catch (_) {}
        document.getElementById('login-error').textContent = hb === 'error'
          ? 'Signed in, but the server could not start an admin session. Check your connection and try again.'
          : 'The server refused to start an admin session. Please try again.';
        document.getElementById('login-error').classList.add('visible');
        return;
      }
      setLoginAttempts(0);
      setLoginLockedUntil(0);
      // app.js keeps its idle clock in localStorage. Stamp it now so the
      // session isn't judged against a timestamp from a previous session.
      try { localStorage.setItem(ACTIVITY_KEY, String(Date.now())); } catch (_) {}
      setAdminLoggedIn(true);
      document.getElementById('logout-btn').style.display = '';
      document.getElementById('login-modal').style.display = 'none';
      document.getElementById('login-pw').value = '';
      document.getElementById('login-error').classList.remove('visible');
      // REFETCH AFTER LOGIN. What the client can see is now role-dependent:
      // the restrictive policy "Public sees only active bookings" hides
      // Rejected and Cancelled rows from anon. If the page was loaded while
      // logged out, the in-memory bookings array holds the ANON view, and
      // logging in does not change it — so the admin table was missing every
      // rejected booking and the "Show rejected" toggle had nothing to
      // reveal. Before that policy existed, anon and admin saw identical
      // data, which is why this gap never mattered until now.
      //
      // Fire the event AFTER loadData so listeners render fresh data. app.js
      // owns the render calls: doing them here would mean importing half the
      // ui layer into the api layer.
      try { await loadData(); } catch (_) {}
      window.dispatchEvent(new CustomEvent('ldrooms:data-refreshed'));
      showPage('admin');
      toast('Welcome, Admin.');
    } else {
      // Record the failure server-side. check_login_rate_limit() no longer
      // logs attempts itself (it used to log successes too, which counted
      // normal use toward the lockout), so failures must be reported here.
      // Fire-and-forget: a logging outage must never block a real login.
      supabase.rpc('log_failed_login').then(
        ({ error }) => { if (error) console.error('log_failed_login failed:', error); },
        err => console.error('log_failed_login threw:', err)
      );
      setLoginAttempts(loginAttempts + 1);
      if (loginAttempts + 1 >= MAX_LOGIN_ATTEMPTS) {
        setLoginLockedUntil(Date.now() + LOCKOUT_MS);
        // Do NOT reset the counter here. It used to call setLoginAttempts(0),
        // so the moment the lockout was announced the budget was handed back
        // and the next wrong password reported "4 attempts remaining". The
        // counter is cleared on a SUCCESSFUL login instead (see above).
        document.getElementById('login-error').textContent = 'Too many failed attempts. Locked for 5 minutes.';
      } else {
        document.getElementById('login-error').textContent = `Incorrect password. ${MAX_LOGIN_ATTEMPTS - (loginAttempts + 1)} attempt(s) remaining.`;
      }
      document.getElementById('login-error').classList.add('visible');
      document.getElementById('login-pw').value = '';
      document.getElementById('login-pw').focus();
    }
  } catch (e) {
    document.getElementById('login-error').textContent = 'Connection error. Try again.';
    document.getElementById('login-error').classList.add('visible');
  } finally {
    showLoadingOverlay(false);
  }
}

export function closeLogin() {
  document.getElementById('login-modal').style.display = 'none';
  document.getElementById('login-pw').value = '';
  document.getElementById('login-error').classList.remove('visible');
}
