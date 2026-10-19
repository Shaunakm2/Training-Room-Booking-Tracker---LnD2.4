#!/usr/bin/env node
// Static verification for LnDRooms. No network, no credentials, no deps.
//
// Every check here exists because the corresponding bug SHIPPED. This is not
// a general-purpose linter — it is a regression net for the specific class of
// failure this project produces: controls that exist, look correct on reading,
// and do nothing.
//
//   node scripts/verify.mjs
//
// Exit 0 = pass. Exit 1 = at least one FAIL.

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, dirname, resolve, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const results = [];
const ok   = (name, detail = '') => results.push({ status: 'PASS', name, detail });
const fail = (name, detail = '') => results.push({ status: 'FAIL', name, detail });
const warn = (name, detail = '') => results.push({ status: 'WARN', name, detail });

const read = p => readFileSync(join(ROOT, p), 'utf8');
function walk(dir, out = []) {
  for (const e of readdirSync(join(ROOT, dir))) {
    const rel = join(dir, e);
    if (statSync(join(ROOT, rel)).isDirectory()) walk(rel, out);
    else if (rel.endsWith('.js')) out.push(rel);
  }
  return out;
}
const jsFiles = walk('js');

// Strip ONLY comments, keeping string literals intact. Needed by checks that
// look for a specific string literal in the source — stripNoise() blanks those
// too, which silently made one such check unable to ever fail.
function stripComments(src) {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/(^|[^:])\/\/[^\n]*/g, '$1 ');
}

// Strip comments and string literals so pattern checks don't match prose or
// the very comments that warn about the pattern.
function stripNoise(src) {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/(^|[^:])\/\/[^\n]*/g, '$1 ')
    .replace(/`(?:\\.|[^`\\])*`/g, '``')
    .replace(/'(?:\\.|[^'\\\n])*'/g, "''")
    .replace(/"(?:\\.|[^"\\\n])*"/g, '""');
}

// ---------------------------------------------------------------
// 1. Every inline handler name in index.html is exposed on window.
//    Bug history: onchange="_sortField=..." created an unread global and the
//    sort dropdown was silently dead; !reqSubmitting threw ReferenceError.
// ---------------------------------------------------------------
{
  const html = read('index.html');
  const app  = read('js/app.js');

  const assignBlocks = [...app.matchAll(/Object\.assign\s*\(\s*window\s*,\s*\{/g)];
  if (!assignBlocks.length) {
    fail('window exposure block found', 'no Object.assign(window, {...}) in app.js');
  }
  // Collect identifiers assigned to window, via Object.assign or window.x =
  const exposed = new Set();
  for (const m of assignBlocks) {
    let i = m.index + m[0].length, depth = 1, buf = '';
    while (i < app.length && depth > 0) {
      const c = app[i];
      if (c === '{') depth++;
      else if (c === '}') { depth--; if (!depth) break; }
      buf += c; i++;
    }
    for (const k of buf.matchAll(/(^|[,\s])([A-Za-z_$][\w$]*)\s*(?=[,:}\n])/g)) exposed.add(k[2]);
  }
  for (const m of app.matchAll(/window\.([A-Za-z_$][\w$]*)\s*=/g)) exposed.add(m[1]);

  // Names referenced by inline handlers
  const GLOBALS = new Set([
    'this','event','window','document','true','false','null','undefined','return',
    'if','else','typeof','new','function','void','const','let','var','in','of',
    'Math','Date','JSON','String','Number','Boolean','Array','Object','console',
    'alert','confirm','parseInt','parseFloat','setTimeout','navigator','location',
  ]);
  const missing = new Map();
  const attrRe = /\bon[a-z]+\s*=\s*(["'])([\s\S]*?)\1/g;
  let handlers = 0;
  for (const m of html.matchAll(attrRe)) {
    handlers++;
    const code = m[2];
    for (const id of code.matchAll(/(?:^|[^.\w$'"`])([A-Za-z_$][\w$]*)\s*(?=\()/g)) {
      const name = id[1];
      if (GLOBALS.has(name) || exposed.has(name)) continue;
      missing.set(name, (missing.get(name) || 0) + 1);
    }
  }
  if (missing.size) {
    fail('inline handlers resolve on window',
      `${handlers} handlers scanned; unresolved: ${[...missing.keys()].join(', ')}`);
  } else {
    ok('inline handlers resolve on window', `${handlers} handlers, ${exposed.size} names exposed`);
  }
}

// ---------------------------------------------------------------
// 2. No bare assignment to a state.js live binding.
//    Bug history: reassigning instead of calling the setter silently desyncs
//    every other module.
// ---------------------------------------------------------------
{
  const stateSrc = read('js/state.js');
  const mutable = [...stateSrc.matchAll(/export\s+let\s+([A-Za-z_$][\w$]*)/g)].map(m => m[1]);
  const offenders = [];
  for (const f of jsFiles) {
    if (f.endsWith('state.js')) continue;
    const src = stripNoise(read(f));
    for (const name of mutable) {
      const re = new RegExp(`(?:^|[^.\\w$])${name}\\s*(?:=[^=]|\\+\\+|--|\\+=|-=)`, 'gm');
      if (re.test(src)) offenders.push(`${f}: ${name}`);
    }
  }
  offenders.length
    ? fail('no direct writes to state.js bindings', offenders.join('; '))
    : ok('no direct writes to state.js bindings', `${mutable.length} bindings checked`);
}

// ---------------------------------------------------------------
// 3. supabase.rpc(...) / .from(...) never uses .catch().
//    Bug history: PostgrestBuilder is a lazy thenable with no catch() method.
//    The line threw TypeError AND never sent the request, silently disabling
//    server-side failed-login logging, the attempt counter and its message.
// ---------------------------------------------------------------
{
  const offenders = [];
  for (const f of jsFiles) {
    const src = stripNoise(read(f));
    for (const m of src.matchAll(/\.(?:rpc|from)\s*\([\s\S]{0,400}?\.catch\s*\(/g)) {
      offenders.push(`${f}: ${src.slice(m.index, m.index + 60).replace(/\s+/g, ' ')}`);
    }
  }
  offenders.length
    ? fail('no .catch() on PostgrestBuilder', offenders.join('; '))
    : ok('no .catch() on PostgrestBuilder');
}

// ---------------------------------------------------------------
// 4. schema.sql invariants.
// ---------------------------------------------------------------
{
  const sqlRaw = read('supabase/schema.sql');
  // Strip SQL comments first: this file documents the rules it follows, so an
  // unstripped scan matches the comment that says "no DROP TABLE anywhere".
  const sql = sqlRaw.replace(/--[^\n]*/g, ' ').replace(/\/\*[\s\S]*?\*\//g, ' ');

  /(drop\s+table)/i.test(sql)
    ? fail('schema has no DROP TABLE')
    : ok('schema has no DROP TABLE');

  // Every SECURITY DEFINER function must name pg_temp in its search_path.
  const defs = [...sql.matchAll(/create\s+or\s+replace\s+function\s+([\w.]+)\s*\(([\s\S]*?)\)\s*returns[\s\S]*?(?=\$\$)/gi)];
  const badPath = [];
  for (const d of defs) {
    const head = d[0];
    if (!/security\s+definer/i.test(head)) continue;
    if (!/search_path\s*=\s*[^;\n]*pg_temp/i.test(head)) badPath.push(d[1]);
  }
  badPath.length
    ? fail('definer functions name pg_temp', badPath.join(', '))
    : ok('definer functions name pg_temp', `${defs.length} functions scanned`);

  // No admin policy may be unconditional.
  const loose = [];
  for (const p of sql.matchAll(/create\s+policy\s+"([^"]+)"[\s\S]*?;/gi)) {
    const body = p[0];
    if (!/admin/i.test(p[1])) continue;
    if (/using\s*\(\s*true\s*\)/i.test(body) || /with\s+check\s*\(\s*true\s*\)/i.test(body)) loose.push(p[1]);
  }
  loose.length
    ? fail('no unconditional admin policy', loose.join(', '))
    : ok('no unconditional admin policy');

  // IPv6 grouping needs network(), not set_masklen() alone.
  if (/set_masklen/i.test(sql) && !/network\s*\(\s*set_masklen/i.test(sql)) {
    fail('IPv6 masking uses network(set_masklen(...))',
         'set_masklen alone leaves host bits intact and groups nothing');
  } else {
    ok('IPv6 masking uses network(set_masklen(...))');
  }

  // The limiter must not key on inet_client_addr() directly: under PostgREST
  // that is loopback for every user.
  const logFn = sql.match(/create\s+or\s+replace\s+function\s+public\.log_failed_login[\s\S]*?\$\$[\s\S]*?\$\$/i);
  if (logFn && /values\s*\(\s*inet_client_addr\(\)\s*\)/i.test(logFn[0])) {
    fail('log_failed_login uses client_ip()', 'still inserting inet_client_addr()');
  } else {
    ok('log_failed_login uses client_ip()');
  }

  // config.js ADMIN_EMAIL must match is_admin() in the schema.
  const cfg = read('js/config.js').match(/ADMIN_EMAIL\s*=\s*['"]([^'"]+)['"]/i);
  const schemaEmail = sql.match(/auth\.jwt\(\)\s*->>\s*'email'\)\s*=\s*'([^']+)'/i);
  if (!cfg || !schemaEmail) {
    warn('ADMIN_EMAIL matches is_admin()', 'could not locate one of the two values');
  } else if (cfg[1].trim().toLowerCase() !== schemaEmail[1].trim().toLowerCase()) {
    fail('ADMIN_EMAIL matches is_admin()', `config.js=${cfg[1]} schema=${schemaEmail[1]}`);
  } else {
    ok('ADMIN_EMAIL matches is_admin()', cfg[1]);
  }
}

// ---------------------------------------------------------------
// 4b. Regression guards for the three findings fixed in this pass.
// ---------------------------------------------------------------
{
  const sql = read('supabase/schema.sql');
  const client = read('js/api/supabase-client.js');
  const auth = read('js/api/auth.js');

  // CRITICAL: booking_id must be format-constrained in the DB and validated
  // in the client. It is interpolated into onclick attributes unescaped.
  /booking_id_format/.test(sql)
    ? ok('booking_id CHECK constraint in schema')
    : fail('booking_id CHECK constraint in schema', 'stored XSS vector is open');

  /ID_OK|\^\[A-Za-z0-9_-\]\{1,40\}\$/.test(client)
    ? ok('booking_id validated in loadData')
    : fail('booking_id validated in loadData', 'unsafe ids reach the DOM');

  // HIGH: the insert rate limiter must count transactions, not rows, or a
  // batched recurring booking trips its own limit and rolls back.
  /count\(distinct txid\)/i.test(sql)
    ? ok('insert limiter counts transactions')
    : fail('insert limiter counts transactions', 'recurring bookings will fail');

  // MEDIUM: the archive insert must name its columns. A positional
  // `insert into bookings_archive select * from moved` breaks the moment the
  // two tables drift, and can write values into the wrong same-typed column.
  /insert into public\.bookings_archive\s*\(/i.test(sql)
    ? ok('archive insert names its columns')
    : fail('archive insert names its columns', 'positional select * will break on drift');

  // The archive must be told about created_at explicitly; LIKE INCLUDING ALL
  // only copies the shape that existed when the archive was created.
  /alter table public\.bookings_archive[\s\S]{0,120}created_at/i.test(sql)
    ? ok('archive has created_at in schema')
    : fail('archive has created_at in schema', 'archive_old_bookings will fail');

  // HIGH: the recurring EDIT must never be able to lose the original or leave
  // duplicates. History: delete-first destroyed the booking on a mid-way
  // failure; the fix (create first, delete last, best-effort clean-up) could
  // still leave duplicates, and a dropped response could make the clean-up
  // delete rows that had been saved. It is now ONE server transaction
  // (replace_booking_atomic): the client must call that and nothing else.
  {
    const at = stripNoise(read('js/ui/admin-table.js'));
    const m = at.match(/if \(id && isRecurring\)[\s\S]*?\n  \}/);
    const sqlNoComments = sql.replace(/--[^\n]*/g, ' ');
    const fn = sqlNoComments.match(/function public\.replace_booking_atomic[\s\S]*?\$\$[\s\S]*?\$\$/i);
    if (!m) {
      warn('recurring edit is one transaction', 'could not locate the block');
    } else {
      const problems = [];
      if (!/apiReplaceRecurring\(/.test(m[0])) problems.push('admin-table does not call apiReplaceRecurring');
      if (/apiDelete\(|apiCreate\(|apiCreateBatch\(/.test(m[0])) problems.push('client still issues separate create/delete calls');
      if (!fn) problems.push('replace_booking_atomic missing from schema');
      else if (!/delete from public\.bookings[\s\S]*create_bookings_atomic\(/i.test(fn[0]))
        problems.push('replace_booking_atomic must delete then create inside the same function');
      problems.length
        ? fail('recurring edit is one transaction', problems.join('; '))
        : ok('recurring edit is one transaction');
    }
  }

  // The default sort in state.js must match the <option selected> in
  // index.html. They are set independently, so a mismatch shows one label
  // while the table is ordered by something else — and this dropdown has a
  // history of being silently wrong.
  {
    const html = read('index.html');
    const st = read('js/state.js');
    const sel = html.match(/<option value="([^"]+)"\s+selected>/);
    const f = st.match(/export let sortField\s*=\s*'([^']+)'/);
    const d = st.match(/export let sortDir\s*=\s*'([^']+)'/);
    if (!sel || !f || !d) {
      warn('default sort matches selected option', 'could not read one of the three values');
    } else {
      const want = `${f[1]}-${d[1]}`;
      sel[1] === want
        ? ok('default sort matches selected option', want)
        : fail('default sort matches selected option',
               `index.html selects "${sel[1]}" but state.js defaults to "${want}"`);
    }
  }

  // Both release paths must refuse a release at or before the start minute:
  // end <= start reads as OVERNIGHT and turns a freed room into a 24h block.
  {
    const problems = [];
    for (const f of ['js/ui/admin-table.js', 'js/ui/cancel-release.js']) {
      if (!/releaseWouldBeEmpty\(/.test(stripComments(read(f)))) problems.push(f);
    }
    if (!/v_new_end <= v_start/.test(sql)) problems.push('schema.sql (server guard still `<`)');
    problems.length
      ? fail('release refuses zero-length results', problems.join(', '))
      : ok('release refuses zero-length results');
  }

  // The Today filter must reason in spans like everything else, or an
  // overnight booking running right now vanishes from it.
  {
    const fs = stripComments(read('js/domain/filters-sort.js'));
    /filterDate === 'today'[\s\S]{0,160}bookingSpans/.test(fs)
      ? ok('Today filter uses spans')
      : fail('Today filter uses spans', 'currently-running overnight bookings will be hidden');
  }

  // Alternate-room suggestions must respect capacity, and there must be only
  // ONE definition of getFreeRoomsForDate.
  {
    const defs = ['js/domain/conflicts.js', 'js/ui/conflict-picker.js']
      .filter(f => /function getFreeRoomsForDate/.test(stripComments(read(f))));
    const c = stripComments(read('js/domain/conflicts.js'));
    const problems = [];
    if (defs.length !== 1) problems.push(`${defs.length} definitions: ${defs.join(', ')}`);
    if (!/r\.capacity/.test(c)) problems.push('capacity not considered');
    problems.length
      ? fail('free-room suggestions respect capacity', problems.join('; '))
      : ok('free-room suggestions respect capacity');
  }

  // Recurring ranges must be capped in BOTH forms.
  {
    const missing = ['js/ui/admin-table.js', 'js/ui/request-form.js']
      .filter(f => !/MAX_RECURRING_DATES/.test(stripComments(read(f))));
    missing.length
      ? fail('recurring range is capped', missing.join(', '))
      : ok('recurring range is capped');
  }

  // Backdating: public refused client-side AND in the policy; admin prompted.
  {
    const problems = [];
    if (!/date < todayStr\(\)/.test(stripComments(read('js/ui/request-form.js'))))
      problems.push('public form allows past dates');
    if (!/booking_date >= current_date/.test(sql))
      problems.push('public INSERT policy allows past dates');
    if (!/Book in the Past/.test(read('js/ui/admin-table.js')))
      problems.push('admin form does not warn');
    problems.length
      ? fail('backdating is public-blocked, admin-warned', problems.join('; '))
      : ok('backdating is public-blocked, admin-warned');
  }

  // The idle watchdog must check staleness BEFORE resetting the clock.
  // The interval samples every 15s but activity events arrive instantly, so
  // the first mousemove after a laptop wakes used to erase the idle gap
  // before the interval could observe it — an overnight session survived.
  {
    const app = stripComments(read('js/app.js'));
    const m = app.match(/function _touchActivity\(\)[\s\S]*?\n\}/);
    if (!m) {
      warn('idle check runs before the clock resets', 'could not locate _touchActivity');
    } else {
      const iCheck = m[0].search(/SESSION_TIMEOUT_MS/);
      const iReset = m[0].search(/_lastActivityAt = now/);
      (iCheck !== -1 && iReset !== -1 && iCheck < iReset)
        ? ok('idle check runs before the clock resets')
        : fail('idle check runs before the clock resets',
               'returning to the machine will erase the idle period');
    }
  }

  // Idle time must be read across tabs, or a second idle tab expires a
  // session the user is actively using elsewhere.
  {
    const app = stripComments(read('js/app.js'));
    /_lastActivitySeen\(\)/.test(app) && /Math\.max/.test(app)
      ? ok('idle time is cross-tab aware')
      : fail('idle time is cross-tab aware', 'a background tab can expire an active session');
  }

  // Room capacities are declared twice: ROOMS in js/config.js (used by the UI)
  // and a CASE in enforce_room_capacity (enforced by the database). They must
  // agree, or the form and the trigger disagree about whether a booking fits.
  {
    const cfg = read('js/config.js');
    const caps = new Map();
    for (const m of cfg.matchAll(/id:\s*'([^']+)'[^}]*?capacity:\s*(\d+)/g)) {
      caps.set(m[1], Number(m[2]));
    }
    const fn = sql.match(/v_cap := case new\.room([\s\S]*?)end;/);
    if (!caps.size || !fn) {
      warn('room capacities agree', 'could not parse config.js ROOMS or the SQL CASE');
    } else {
      const sqlCaps = new Map();
      for (const m of fn[1].matchAll(/when\s*'([^']+)'\s*then\s*(\d+)/g)) {
        sqlCaps.set(m[1], Number(m[2]));
      }
      const elseM = fn[1].match(/else\s*(\d+)/);
      const dflt = elseM ? Number(elseM[1]) : null;
      const bad = [];
      for (const [id, cap] of caps) {
        const expected = sqlCaps.has(id) ? sqlCaps.get(id) : dflt;
        if (expected !== cap) bad.push(`${id}: config=${cap} sql=${expected}`);
      }
      // A room named in the SQL that no longer exists in config is also drift.
      for (const id of sqlCaps.keys()) {
        if (!caps.has(id)) bad.push(`${id}: in SQL but not in config.js ROOMS`);
      }
      bad.length
        ? fail('room capacities agree', bad.join('; '))
        : ok('room capacities agree', `${caps.size} rooms, default ${dflt}`);
    }
  }

  // createdSortKey must live in utils/ids.js, not api/. Putting it in api/
  // made domain/filters-sort.js import from the api layer.
  {
    const ids = stripComments(read('js/utils/ids.js'));
    const domainImportsApi = /from '\.\.\/api\//.test(read('js/domain/filters-sort.js'));
    (/function createdSortKey/.test(ids) && !domainImportsApi)
      ? ok('createdSortKey is in utils, domain stays pure')
      : fail('createdSortKey is in utils, domain stays pure',
             domainImportsApi ? 'domain/ imports from api/' : 'helper not in utils/ids.js');
  }

  // Creation-time sorting must prefer the created_at column, with a fallback
  // for the nulls that genuinely exist in production.
  {
    const ids = stripComments(read('js/utils/ids.js'));
    (/createdAtMs/.test(ids) && /creationMs\(b\.id\)/.test(ids))
      ? ok('creation sort prefers created_at with fallback')
      : fail('creation sort prefers created_at with fallback',
             'either the column is ignored or the id fallback is gone');
  }

  // showConfirmModal must settle a pending promise before taking the slot,
  // or opening a second confirm orphans the first `await` forever.
  {
    const d = stripComments(read('js/utils/dom-helpers.js'));
    /if \(_confirmModalResolve\) _confirmModalResolve\(false\)/.test(d)
      ? ok('showConfirmModal settles pending promises')
      : fail('showConfirmModal settles pending promises', 'a second confirm will orphan the first');
  }

  // ids.js: DAY_MS / EARLIEST_PLAUSIBLE_MS are const, so they must appear
  // BEFORE creationMs(). Declared after, any top-level call throws a TDZ
  // ReferenceError.
  {
    const i = stripComments(read('js/utils/ids.js'));
    const c = i.indexOf('const EARLIEST_PLAUSIBLE_MS');
    const f = i.indexOf('function creationMs');
    (c !== -1 && f !== -1 && c < f)
      ? ok('ids.js constants precede creationMs')
      : fail('ids.js constants precede creationMs', 'temporal dead zone hazard');
  }

  // Pre-flight refreshes must bypass the write debounce, or a save within 3s
  // of the previous one checks conflicts against stale data.
  {
    const problems = [];
    for (const f of ['js/ui/admin-table.js', 'js/ui/request-form.js']) {
      const src = stripComments(read(f));
      if (/loadData\(true\)\s*[;,)]/.test(src)) problems.push(f);
    }
    problems.length
      ? fail('pre-flight refreshes are forced', `${problems.join(', ')} still call loadData(true)`)
      : ok('pre-flight refreshes are forced');
  }

  // Dead state must not come back: sessionToken was written five times and
  // read never, with a comment claiming it was required for admin writes.
  {
    const any = ['js/state.js', 'js/api/auth.js']
      .filter(f => /setSessionToken\s*\(/.test(stripComments(read(f))));
    any.length
      ? fail('sessionToken stays removed', any.join(', '))
      : ok('sessionToken stays removed');
  }

  // Active Now must filter on STATUS as well as time. bookingTimeStatus()
  // answers only "is now inside this window" and knows nothing about status,
  // so using it alone put Rejected and Cancelled bookings under ACTIVE NOW
  // with a Release button, while the timeline showed the room as free.
  {
    // stripComments, NOT stripNoise: this looks for the string literal
    // 'Confirmed', and stripNoise blanks string literals — which would make
    // the check fail permanently regardless of the code. Second time this
    // exact trap has come up; see the note on stripComments above.
    const at = stripComments(read('js/ui/admin-table.js'));
    const m = at.match(/export function renderActiveNow\(\)[\s\S]{0,700}/);
    (m && /status === 'Confirmed'/.test(m[0]))
      ? ok('Active Now filters by status')
      : fail('Active Now filters by status', 'rejected/cancelled bookings will show as active');
  }

  // The table must not reset its page on every render: the 60s poll and every
  // tab-focus call renderTable(), which ejected the admin from page 3.
  {
    const at = stripNoise(read('js/ui/admin-table.js'));
    const m = at.match(/export function renderTable\(\)[\s\S]{0,400}/);
    (m && /setTablePage\(0\)/.test(m[0]))
      ? fail('renderTable does not reset the page', 'poll will eject the admin from page N')
      : ok('renderTable does not reset the page');
  }

  // The service worker must not cache failed responses. Without a status
  // check, a 404/500/proxy block page was cached and served as the app.
  {
    const sw = stripNoise(read('sw.js'));
    /response\.ok/.test(sw)
      ? ok('service worker caches only successes')
      : fail('service worker caches only successes', 'error responses will poison the cache');
  }

  // A failed refresh must not blank the list. loadData(true) runs every 60s,
  // so setBookings([]) on error emptied the whole UI on one dropped packet.
  {
    const c = stripNoise(read('js/api/supabase-client.js'));
    const m = c.match(/catch \(e\)[\s\S]{0,600}?\n  \}/);
    (m && /bookings\.length === 0/.test(m[0]))
      ? ok('failed refresh keeps stale data')
      : fail('failed refresh keeps stale data', 'a network blip will blank the UI');
  }

  // escHtml must escape single quotes and must not swallow falsy values.
  {
    const d = stripComments(read('js/utils/dom-helpers.js'));
    const problems = [];
    if (!/&#39;/.test(d)) problems.push("no single-quote escaping");
    if (/if \(!s\) return ''/.test(d)) problems.push("`if (!s)` swallows 0 and false");
    problems.length
      ? fail('escHtml is complete', problems.join('; '))
      : ok('escHtml is complete');
  }

  // A failed edit must not clear the form — the error says "try again" and
  // there would be nothing left to retry from.
  {
    const at = stripNoise(read('js/ui/admin-table.js'));
    /if \(!editFailed\) resetForm\(\)/.test(at)
      ? ok('failed edit preserves the form')
      : fail('failed edit preserves the form', 'resetForm() runs unconditionally');
  }

  // Sign-in and sign-out must refetch. The restrictive SELECT policy makes the
  // visible row set role-dependent, so a page loaded while logged out holds
  // the ANON view — and logging in does not change it. That is how the
  // "Show rejected" toggle ended up with nothing to reveal.
  {
    const a = stripNoise(read('js/api/auth.js'));
    const login  = a.match(/export async function doLogin[\s\S]*?\n\}/);
    const logout = a.match(/export async function doLogout[\s\S]*?\n\}/);
    const missing = [];
    if (!login  || !/loadData\(/.test(login[0]))  missing.push('doLogin');
    if (!logout || !/loadData\(/.test(logout[0])) missing.push('doLogout');
    missing.length
      ? fail('login/logout refetch data', `${missing.join(' and ')} do not call loadData()`)
      : ok('login/logout refetch data');
  }

  // The restrictive SELECT policy must exempt authenticated, or it applies to
  // the admin too (PUBLIC includes every role) and the "Show rejected" toggle
  // shows nothing. It must also NOT call is_admin(), which is revoked from
  // anon and would error on every public SELECT.
  {
    const m = sql.match(/create policy "Public sees only active bookings"[\s\S]*?;/);
    if (!m) {
      warn('restrictive SELECT policy exempts admin', 'policy not present in schema');
    } else if (/is_admin\(\)/.test(m[0])) {
      fail('restrictive SELECT policy exempts admin',
           'uses is_admin(), which anon cannot execute — every public SELECT would error');
    } else if (!/auth\.role\(\)\s*=\s*'authenticated'/.test(m[0])) {
      fail('restrictive SELECT policy exempts admin',
           'no authenticated clause — admin cannot see rejected bookings');
    } else {
      ok('restrictive SELECT policy exempts admin');
    }
  }

  // The "Show rejected" toggle must exist in the markup AND be read by the
  // filter. Either half alone is a silent no-op: a checkbox nothing reads, or
  // a filter with no way to switch it off.
  {
    const html = read('index.html');
    const fs = stripComments(read('js/domain/filters-sort.js'));
    const inHtml = /id="filter-show-rejected"/.test(html);
    const inFilter = /filter-show-rejected/.test(fs) && /status !== 'Rejected'/.test(fs);
    (inHtml && inFilter)
      ? ok('show-rejected toggle is wired end to end')
      : fail('show-rejected toggle is wired end to end',
             `markup: ${inHtml ? 'yes' : 'MISSING'}, filter: ${inFilter ? 'yes' : 'MISSING'}`);
  }

  // Bulk approve must run a conflict check. approvePending() always did;
  // admin-table's bulkApprove() did not, so bulk-approving a Rejected booking
  // silently reinstated it into an occupied slot, bypassing the guard.
  {
    const at = stripNoise(read('js/ui/admin-table.js'));
    const m = at.match(/export async function bulkApprove\(\)[\s\S]*?\n\}/);
    if (!m) {
      warn('bulkApprove checks conflicts', 'could not locate the function');
    } else {
      /findConflict\(/.test(m[0])
        ? ok('bulkApprove checks conflicts')
        : fail('bulkApprove checks conflicts', 'can confirm a booking into an occupied slot');
    }
  }

  // MEDIUM: bulk selection must come from state, not the DOM. Only the current
  // page's rows exist in the DOM, so a DOM-derived selection was truncated by
  // pagination and by the 60s poll while the count kept showing the old value.
  {
    // stripComments, NOT stripNoise: this looks for a string literal, and
    // stripNoise blanks string literals — which made this check unable to
    // fail at all. Caught by mutation-testing it.
    const at = stripComments(read('js/ui/admin-table.js'));
    /querySelectorAll\('\.row-cb:checked'\)/.test(at)
      ? fail('bulk selection is state-backed', 'still reading :checked from the DOM')
      : ok('bulk selection is state-backed');
  }

  // The admin capacity override must exist in the schema, or the UI's
  // "Book anyway?" prompt is a button that cannot work.
  /auth\.role\(\)\s*=\s*'authenticated'[\s\S]{0,200}return new;/.test(sql)
    ? ok('admin capacity override in schema')
    : fail('admin capacity override in schema', 'Book Anyway will always fail');

  // HIGH: the lockout must actually be read, not just written.
  /Date\.now\(\)\s*<\s*loginLockedUntil/.test(auth)
    ? ok('login lockout is enforced')
    : fail('login lockout is enforced', 'loginLockedUntil is set but never read');
}

// ---------------------------------------------------------------
// 4c. Utility classes applied to form controls must be element-qualified.
//     `.form-group input` is (0,1,1) and sets width:100% plus
//     appearance:none. A bare `.cb-lg` (0,1,0) loses to it, and the recurring
//     checkbox rendered as a full-width empty box with its label pushed off
//     screen. These properties used to live in inline style attributes, which
//     always beat class selectors — the specificity was doing real work and
//     was lost silently in the conversion.
// ---------------------------------------------------------------
{
  const css = read('style.css');
  const bad = [];
  for (const cls of ['cb-lg', 'cb-danger', 'cb-label']) {
    // Every selector mentioning the class must name an element or an
    // attribute, i.e. never appear as a lone `.cls {`.
    const lone = new RegExp(`(^|[,\\s])\\.${cls}\\s*[,{]`, 'm');
    if (lone.test(css)) bad.push(cls);
  }
  bad.length
    ? fail('form-control classes are element-qualified',
           `${bad.join(', ')} will lose to .form-group input/label`)
    : ok('form-control classes are element-qualified');
}

// ---------------------------------------------------------------
// 4d. Audit trail, atomic writes, server-side conflicts (schema section 14).
//     Each guard here protects a property that, if lost, fails silently:
//     the app keeps working while partial saves, double bookings or missing
//     audit rows creep back in.
// ---------------------------------------------------------------
{
  const sqlRaw = read('supabase/schema.sql');
  const sql = sqlRaw.replace(/--[^\n]*/g, ' ');
  const api = stripComments(read('js/api/bookings.js'));
  const fnBody = name => {
    const m = sql.match(new RegExp(`function public\\.${name}\\s*\\([\\s\\S]*?\\$\\$([\\s\\S]*?)\\$\\$`, 'i'));
    return m ? m[1] : null;
  };

  // Every RPC the client calls must exist in the schema.
  {
    const called = [...new Set([...api.matchAll(/(?:rpc|callRpc)\(\s*'([a-z_]+)'/g)].map(m => m[1]))];
    const missing = called.filter(n => !new RegExp(`create\\s+or\\s+replace\\s+function\\s+public\\.${n}\\s*\\(`, 'i').test(sql));
    missing.length
      ? fail('every client RPC exists in schema', missing.join(', '))
      : ok('every client RPC exists in schema', `${called.length} RPCs`);
  }

  // Booking writes from the browser go through atomic RPCs, never direct
  // insert/update/delete on the table (apiSetConflictResolved is the single,
  // single-row exception and is still audited by the trigger).
  {
    const direct = [...api.matchAll(/\.from\('bookings'\)\s*\.(insert|delete|update)\(/g)].map(m => m[1]);
    const okDirect = direct.length === 1 && direct[0] === 'update'
      && /apiSetConflictResolved[\s\S]{0,200}\.from\('bookings'\)\s*\.update\(\{\s*conflict_resolved/.test(api);
    (direct.length === 0 || okDirect)
      ? ok('booking writes use atomic RPCs')
      : fail('booking writes use atomic RPCs', `direct table writes: ${direct.join(', ')}`);
  }

  // Audit trail: trigger on bookings, append-only, admin-read-only.
  {
    const problems = [];
    if (!/create trigger trg_audit_booking_change\s+after insert or update or delete on public\.bookings/i.test(sql))
      problems.push('audit trigger missing');
    if (!/create trigger trg_audit_log_append_only\s+before update or delete on public\.booking_audit_log/i.test(sql))
      problems.push('append-only trigger missing');
    if (!/revoke all on public\.booking_audit_log from public, anon, authenticated/i.test(sql))
      problems.push('audit table grants not revoked');
    problems.length
      ? fail('audit trail is complete and append-only', problems.join('; '))
      : ok('audit trail is complete and append-only');
  }

  // Server-side overlap rule, with the admin override reset after use.
  {
    const problems = [];
    if (!/create trigger trg_no_confirmed_overlap/i.test(sql)) problems.push('overlap trigger missing');
    const t = fnBody('enforce_no_confirmed_overlap');
    if (!t || !/pg_advisory_xact_lock/.test(t)) problems.push('overlap check is not serialised per room');
    if (!t || !/v_new <@ v_old/.test(t)) problems.push('release-early of a shared room would be refused');
    for (const n of ['create_bookings_atomic', 'update_booking_atomic',
                     'update_booking_statuses_atomic', 'approve_bookings_atomic']) {
      const b = fnBody(n);
      if (!b) { problems.push(`${n} missing`); continue; }
      if (/allow_booking_conflict',\s*'on'/.test(b) && !/allow_booking_conflict',\s*'off'/.test(b))
        problems.push(`${n} turns the override on but never off`);
    }
    problems.length
      ? fail('confirmed overlaps refused server-side', problems.join('; '))
      : ok('confirmed overlaps refused server-side');
  }

  // Public create RPC must re-apply the public INSERT policy rules, because a
  // SECURITY DEFINER function bypasses RLS.
  {
    const b = fnBody('create_bookings_atomic') || '';
    const problems = [];
    if (!/<>\s*'Pending'/.test(b)) problems.push('public can create non-Pending rows');
    if (!/<\s*current_date/.test(b)) problems.push('public can backdate');
    if (!/conflict_resolved/.test(b) || !/Conflict fields are admin-only/.test(b)) problems.push('public can set conflict fields');
    if (!/booking_idempotency/.test(b)) problems.push('no idempotency');
    problems.length
      ? fail('public create RPC enforces public rules', problems.join('; '))
      : ok('public create RPC enforces public rules');
  }

  // The batch limit in the RPC must allow the longest recurring range the UI
  // permits, or every maximum-length recurring booking fails.
  {
    const cfg = read('js/config.js').match(/MAX_RECURRING_DATES\s*=\s*(\d+)/);
    const lim = (fnBody('create_bookings_atomic') || '').match(/not between 1 and (\d+)/);
    if (!cfg || !lim) {
      warn('RPC batch limit covers MAX_RECURRING_DATES', 'could not read one of the two values');
    } else {
      Number(lim[1]) >= Number(cfg[1])
        ? ok('RPC batch limit covers MAX_RECURRING_DATES', `${lim[1]} >= ${cfg[1]}`)
        : fail('RPC batch limit covers MAX_RECURRING_DATES', `RPC allows ${lim[1]}, UI allows ${cfg[1]}`);
    }
  }

  // Admin-only RPCs must be revoked from anon BY NAME. Supabase grants
  // EXECUTE on new functions to anon directly, so revoking PUBLIC is not enough.
  {
    const missing = ['update_booking_atomic', 'update_booking_statuses_atomic',
                     'approve_bookings_atomic', 'delete_bookings_atomic', 'replace_booking_atomic']
      .filter(n => !new RegExp(`revoke all on function public\\.${n}\\([^)]*\\)\\s+from public, anon, authenticated`, 'i').test(sql)
               || new RegExp(`grant execute on function public\\.${n}\\([^)]*\\)\\s+to[^;]*anon`, 'i').test(sql));
    missing.length
      ? fail('admin RPCs not executable by anon', missing.join(', '))
      : ok('admin RPCs not executable by anon');
  }

  // Pre-flight refresh must FAIL CLOSED: deciding on stale data is the bug.
  {
    const bad = ['js/ui/request-form.js', 'js/ui/admin-table.js']
      .filter(f => !/\(await loadData\(true, true\)\)\s*!==\s*true|refreshed\s*!==\s*true/.test(stripComments(read(f))));
    const client = stripNoise(read('js/api/supabase-client.js'));
    if (!/return true;/.test(client) || !/return false;/.test(client)) bad.push('supabase-client.js loadData does not report success');
    bad.length
      ? fail('pre-flight refresh fails closed', bad.join(', '))
      : ok('pre-flight refresh fails closed');
  }
}

// ---------------------------------------------------------------
// 5. Service worker cache version bumped when shipped assets change.
//    Bug history: stale modules served after deploy, making observed
//    behaviour contradict the source being read.
// ---------------------------------------------------------------
{
  const sw = read('sw.js');
  const m = sw.match(/['"]([\w-]*shell-v(\d+))['"]/);
  m ? ok('service worker cache versioned', m[1])
    : warn('service worker cache versioned', 'no ...-vN cache name found in sw.js');
}

// ---------------------------------------------------------------
// 6. No secret key committed.
// ---------------------------------------------------------------
{
  const hits = [];
  for (const f of [...jsFiles, 'index.html', 'sw.js']) {
    if (/sb_secret_/.test(read(f))) hits.push(f);
  }
  hits.length
    ? fail('no sb_secret_ key in source', hits.join(', '))
    : ok('no sb_secret_ key in source');
}

// ---------------------------------------------------------------
// 7. Module graph links. Catches typo'd import paths and missing exports,
//    which no amount of reading reliably catches.
// ---------------------------------------------------------------
{
  const problems = [];
  const exportsOf = new Map();
  for (const f of jsFiles) {
    const src = read(f);
    const names = new Set();
    for (const m of src.matchAll(/export\s+(?:async\s+)?(?:function|const|let|var|class)\s+([A-Za-z_$][\w$]*)/g)) names.add(m[1]);
    for (const m of src.matchAll(/export\s*\{([^}]*)\}/g))
      for (const part of m[1].split(',')) {
        const n = part.trim().split(/\s+as\s+/).pop().trim();
        if (n) names.add(n);
      }
    if (/export\s+default/.test(src)) names.add('default');
    exportsOf.set(f, names);
  }
  for (const f of jsFiles) {
    const src = read(f);
    for (const m of src.matchAll(/import\s+([\s\S]*?)\s+from\s+['"]([^'"]+)['"]/g)) {
      const spec = m[2];
      if (!spec.startsWith('.')) continue;
      const target = relative(ROOT, resolve(dirname(join(ROOT, f)), spec));
      if (!exportsOf.has(target)) { problems.push(`${f} -> ${spec} (file not found)`); continue; }
      const clause = m[1];
      const named = clause.match(/\{([^}]*)\}/);
      if (!named) continue;
      for (const part of named[1].split(',')) {
        const n = part.trim().split(/\s+as\s+/)[0].trim();
        if (n && !exportsOf.get(target).has(n)) problems.push(`${f}: '${n}' not exported by ${target}`);
      }
    }
  }
  problems.length
    ? fail('module graph links', problems.join('; '))
    : ok('module graph links', `${jsFiles.length} modules`);
}

// ---------------------------------------------------------------
// Report
// ---------------------------------------------------------------
const pad = Math.max(...results.map(r => r.name.length));
let failed = 0;
for (const r of results) {
  if (r.status === 'FAIL') failed++;
  const tag = r.status === 'PASS' ? '  ok  ' : r.status === 'WARN' ? ' warn ' : ' FAIL ';
  console.log(`[${tag}] ${r.name.padEnd(pad)}  ${r.detail}`);
}
const warns = results.filter(r => r.status === 'WARN').length;
console.log(`\n${results.length - failed - warns} passed, ${warns} warned, ${failed} failed`);
process.exit(failed ? 1 : 0);
