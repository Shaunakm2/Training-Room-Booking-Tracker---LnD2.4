-- ============================================================================
--  ROOM BOOKING TRACKER  —  DATABASE SCHEMA  (Supabase / PostgreSQL)
--  IMS L&D Training Rooms (AHD)
-- ============================================================================
--
--  THE ONE AND ONLY DATABASE FILE.  Everything the database needs is here:
--  tables, rules, security, functions, views and privileges. If you change
--  anything in the Supabase SQL editor, change it here too — three security
--  problems once went unnoticed for months because the live database and this
--  file had drifted apart.
--
--  HOW TO RUN
--    Supabase -> SQL Editor -> New query -> paste this WHOLE file -> Run.
--    Expected: "Success. No rows returned".
--    Then run the self-test in APPENDIX E (copy the marked block).
--
--  SAFE TO RE-RUN.  Idempotent: tables use IF NOT EXISTS, functions use
--  CREATE OR REPLACE, policies/triggers/constraints are dropped and re-made.
--  NO DATA IS EVER DELETED: there is no DROP TABLE anywhere in this file.
--
--  CONTENTS
--    1. Helper functions        7. Booking write functions (atomic RPCs)
--    2. Tables                  8. Public self-service: cancel / release
--    3. Data rules              9. Change marker (cheap refresh check)
--    4. Row level security     10. Login rate limit
--    5. Audit trail            11. Archive + reporting views
--    6. Booking triggers       12. Privileges (every grant, in one place)
--   10b. Admin idle timeout    13. Realtime + API reload
--    Appendix A  Health checks          Appendix D  Accepted trade-offs
--    Appendix B  Scheduled job          Appendix E  Self-test
--    Appendix C  Maintenance
--
--  ADMIN IDENTITY.  The admin is the account whose email appears in
--  public.is_admin_account() (section 1). Keep it identical to ADMIN_EMAIL in
--  js/config.js — scripts/verify.mjs fails the build if they differ.
--
--  ADMIN IDLE TIMEOUT (section 10b).  is_admin() is true only for the admin
--  account AND a session that has sent an activity heartbeat within
--  admin_idle_limit() (12 min = the 10-min browser timeout + 2 min grace for
--  heartbeat throttling). Enforced here, not just in the browser: an idle
--  session cannot approve, edit or delete anything, whatever the client does.
--
--  CONFLICT OVERRIDE (used by sections 6 and 7).  A Confirmed booking may not
--  overlap another Confirmed booking in the same room. The admin can still
--  choose "Approve anyway": the write function then sets the transaction-local
--  flag app.allow_booking_conflict = 'on', and switches it 'off' again before
--  returning. Only admin-checked functions can set it, and every override is
--  recorded in the audit trail.
-- ============================================================================


-- ============================================================================
-- 1. HELPER FUNCTIONS
-- ============================================================================

-- Real client address of the caller, for rate limiting and the audit trail.
-- Browser calls arrive through PostgREST, so inet_client_addr() alone would
-- return PostgREST's own address for every user. Headers, in order of trust:
--   cf-connecting-ip (set by Cloudflare, not forgeable past the edge),
--   sb-forwarded-for, x-real-ip, first entry of x-forwarded-for,
--   then inet_client_addr() for direct connections (SQL editor, cron).
-- IPv6 is grouped to its /64: privacy extensions rotate addresses inside it.
-- network() is required — set_masklen() alone keeps the host bits.
-- Limitation: headers are ultimately client-influenced; this raises the bar,
-- it is not a WAF.
create or replace function public.client_ip()
returns inet
language plpgsql
stable
set search_path = public, pg_temp
as $$
declare
  v_hdrs jsonb;
  v_raw  text;
  v_ip   inet;
begin
  begin
    v_hdrs := current_setting('request.headers', true)::jsonb;
  exception when others then
    v_hdrs := null;
  end;

  if v_hdrs is not null then
    v_raw := coalesce(
      nullif(btrim(v_hdrs ->> 'cf-connecting-ip'), ''),
      nullif(btrim(v_hdrs ->> 'sb-forwarded-for'), ''),
      nullif(btrim(v_hdrs ->> 'x-real-ip'), ''),
      nullif(btrim(split_part(coalesce(v_hdrs ->> 'x-forwarded-for', ''), ',', 1)), '')
    );
  end if;

  if v_raw is not null then
    begin
      v_ip := v_raw::inet;
    exception when others then
      v_ip := null;   -- malformed or spoofed garbage: fall through
    end;
  end if;

  v_ip := coalesce(v_ip, inet_client_addr());

  if v_ip is null then
    return null;
  end if;

  if family(v_ip) = 6 then
    return network(set_masklen(v_ip, 64));
  end if;

  return v_ip;
end;
$$;

-- Is the caller signed in as the admin ACCOUNT? Identity only — says nothing
-- about whether the session is still active. Keep the email in step with
-- js/config.js. Used by the session functions in section 10b; everything
-- else uses is_admin() below.
create or replace function public.is_admin_account()
returns boolean
language sql
stable
set search_path = public, pg_temp
as $$
  select coalesce((auth.jwt() ->> 'email') = 'shaunakmistry4@gmail.com', false)
$$;

-- Server-side idle limit for admin sessions. ONE place. Must equal
-- ADMIN_IDLE_TIMEOUT_MIN + 2 in js/config.js (verify.mjs checks): the extra
-- 2 minutes cover the heartbeat throttle, so the server never expires a
-- session the browser still considers active.
create or replace function public.admin_idle_limit()
returns interval
language sql
immutable
set search_path = public, pg_temp
as $$
  select interval '12 minutes'
$$;

-- Supabase session id from the access token. Every sign-in creates a new
-- session; token refreshes keep the same id. Null if absent or malformed.
create or replace function public.jwt_session_id()
returns uuid
language plpgsql
stable
set search_path = public, pg_temp
as $$
begin
  return nullif(auth.jwt() ->> 'session_id', '')::uuid;
exception when others then
  return null;
end;
$$;

-- Is the caller the admin, in a session that is still ACTIVE? Checked inside
-- every admin-only function and in the admin RLS policies.
--   - admin account (is_admin_account), and
--   - this session has an activity record (section 10b) that is not revoked
--     and was touched within admin_idle_limit().
-- A valid JWT is NOT enough: access tokens live for an hour and refresh
-- tokens until revoked, so the token alone cannot express "idle for 12
-- minutes". SECURITY DEFINER to read admin_session_activity, which no app
-- role can read directly. plpgsql (not sql) so the body is not checked
-- against tables that section 2 creates later in this file.
create or replace function public.is_admin()
returns boolean
language plpgsql
stable
security definer
set search_path = public, pg_temp
as $$
begin
  if not public.is_admin_account() then
    return false;
  end if;
  return exists (
    select 1
      from public.admin_session_activity a
     where a.session_id = public.jwt_session_id()
       and a.revoked_at is null
       and a.last_seen > now() - public.admin_idle_limit()
  );
end;
$$;

-- Base-36 text -> bigint. Used only by the optional created_at backfill in
-- Appendix C. Returns null for bad characters or input longer than 12
-- characters (36^12 still fits in a bigint; longer would overflow).
create or replace function public.base36_to_bigint(p_text text)
returns bigint
language plpgsql
immutable
as $$
declare
  v_result bigint := 0;
  v_char   text;
  v_digit  int;
begin
  if p_text is null or length(p_text) = 0 or length(p_text) > 12 then
    return null;
  end if;
  for i in 1..length(p_text) loop
    v_char  := lower(substring(p_text from i for 1));
    v_digit := position(v_char in '0123456789abcdefghijklmnopqrstuvwxyz') - 1;
    if v_digit < 0 then
      return null;
    end if;
    v_result := v_result * 36 + v_digit;
  end loop;
  return v_result;
end;
$$;

-- Real end timestamp of a booking. Mirrors bookingSpans() in
-- js/domain/time.js: an end time at or before the start time means the
-- booking runs into the next day.
create or replace function public.booking_end_ts(
  p_date date, p_start time, p_end time, p_end_date date
)
returns timestamp
language sql
immutable
set search_path = public, pg_temp
as $$
  select case
           when coalesce(p_end_date, p_date) + p_end > p_date + p_start
             then coalesce(p_end_date, p_date) + p_end
           else (p_date + 1) + p_end
         end
$$;


-- ============================================================================
-- 2. TABLES
-- ============================================================================

-- 2.1 bookings — the only table the app reads and writes.
create table if not exists public.bookings (
  booking_id        text primary key,
  room              text not null check (room in (
                      'brihaspati','vedvyas','conf2f','parashurama','pingala',
                      'chanakya','bhardwaja','vishwamitra','vasistha','sharada'
                    )),
  booked_by         text not null check (char_length(booked_by) <= 80),
  purpose           text check (char_length(purpose) <= 100),
  booking_date      date not null,
  start_time        time not null,
  end_time          time not null,
  attendees         integer check (attendees between 1 and 500),
  status            text not null default 'Confirmed'
                      check (status in ('Confirmed','Pending','Cancelled','Rejected')),
  end_date          date,
  conflict_resolved boolean not null default false,
  conflict_note     text
);

-- Creation time. NULLABLE on purpose: rows older than this column have no
-- recoverable creation time, and stamping them with now() would make the
-- oldest rows look newest. The app treats null as "unknown, sort oldest".
alter table public.bookings
  add column if not exists created_at timestamptz default now();

create index if not exists idx_bookings_date       on public.bookings (booking_date);
create index if not exists idx_bookings_room_date  on public.bookings (room, booking_date);
create index if not exists idx_bookings_status     on public.bookings (status);
create index if not exists idx_bookings_created_at on public.bookings (created_at desc nulls last);

-- 2.2 booking_audit_log — append-only history of every booking change.
--     Written only by the trigger in section 5; nobody can edit or delete it.
create table if not exists public.booking_audit_log (
  audit_id       bigint generated always as identity primary key,
  booking_id     text not null,
  action         text not null check (action in ('INSERT','UPDATE','DELETE')),
  actor_role     text not null,
  actor_id       uuid,
  actor_email    text,
  client_ip      inet,
  occurred_at    timestamptz not null default now(),
  transaction_id bigint not null,
  old_row        jsonb,
  new_row        jsonb
);
create index if not exists booking_audit_booking_time_idx
  on public.booking_audit_log (booking_id, occurred_at desc);
create index if not exists booking_audit_time_idx
  on public.booking_audit_log (occurred_at desc);

-- 2.3 booking_idempotency — one row per submission key for 24 hours, so a
--     double click or a retried request creates its bookings only once.
create table if not exists public.booking_idempotency (
  actor_key   text not null,
  request_key text not null,
  response    jsonb,
  created_at  timestamptz not null default now(),
  primary key (actor_key, request_key)
);
create index if not exists booking_idempotency_created_idx
  on public.booking_idempotency (created_at);

-- 2.4 booking_rate_log — recent booking actions, for the insert rate limit.
--     txid makes a multi-row batch count as ONE action (see section 6).
create table if not exists public.booking_rate_log (
  id         bigint generated always as identity primary key,
  actor      text not null,
  created_at timestamptz not null default now()
);
alter table public.booking_rate_log add column if not exists txid bigint;
create index if not exists idx_rate_log_actor_time
  on public.booking_rate_log (actor, created_at);
create unique index if not exists booking_rate_log_actor_txid_idx
  on public.booking_rate_log (actor, txid);

-- 2.5 login_attempt_log — failed admin logins per client IP (section 10).
create table if not exists public.login_attempt_log (
  id         bigint generated always as identity primary key,
  created_at timestamptz not null default now()
);
alter table public.login_attempt_log
  add column if not exists ip inet;
create index if not exists login_attempt_log_ip_time_idx
  on public.login_attempt_log (ip, created_at desc);

-- 2.6 bookings_archive — bookings older than 90 days, moved by the daily job.
--     LIKE ... INCLUDING ALL copies the shape of bookings only at the moment
--     the archive is first created, so later columns and constraints are
--     repeated here explicitly. MAINTENANCE RULE: a column added to bookings
--     must be added here AND to both column lists in archive_old_bookings().
create table if not exists public.bookings_archive (like public.bookings including all);
-- Nullable, matching bookings.created_at — legacy rows have no value.
alter table public.bookings_archive
  add column if not exists created_at timestamptz;
alter table public.bookings_archive
  alter column created_at drop not null;

-- 2.7 admin_session_activity — last real activity per admin sign-in session,
--     for the server-side idle timeout (section 10b). One row per Supabase
--     session. A revoked or stale row is kept as a tombstone, so that session
--     can never be revived; tombstones are purged after 90 days.
create table if not exists public.admin_session_activity (
  session_id  uuid primary key,
  user_id     uuid,
  last_seen   timestamptz not null default now(),
  created_at  timestamptz not null default now(),
  revoked_at  timestamptz
);
create index if not exists admin_session_activity_last_seen_idx
  on public.admin_session_activity (last_seen);


-- ============================================================================
-- 3. DATA RULES
-- ============================================================================
-- Column-level rules (room list, status list, name <= 80, purpose <= 100,
-- attendees 1..500) are in the table definition above.

-- booking_id format. NOT cosmetic: the id is placed inside onclick="..."
-- attributes in the admin screens, so a quote mark in an id would be stored
-- script injection. App-generated ids are [a-z0-9] only.
alter table public.bookings
  drop constraint if exists bookings_booking_id_format;
alter table public.bookings
  add constraint bookings_booking_id_format
  check (booking_id ~ '^[A-Za-z0-9_-]{1,40}$');

alter table public.bookings_archive
  drop constraint if exists bookings_archive_booking_id_format;
alter table public.bookings_archive
  add constraint bookings_archive_booking_id_format
  check (booking_id ~ '^[A-Za-z0-9_-]{1,40}$');

-- Fill end_date on very old rows that have none, so they can satisfy the
-- rules below. Only touches rows where it is null; does nothing on re-runs.
-- One bad legacy row is reported as a notice, not allowed to stop the file.
do $$
declare
  r record;
begin
  perform set_config('app.allow_booking_conflict', 'on', true);
  for r in select booking_id from public.bookings where end_date is null loop
    begin
      update public.bookings
         set end_date = case when end_time > start_time
                             then booking_date else booking_date + 1 end
       where booking_id = r.booking_id;
    exception when others then
      raise notice 'end_date backfill skipped for %: %', r.booking_id, sqlerrm;
    end;
  end loop;
  perform set_config('app.allow_booking_conflict', 'off', true);
end $$;

-- Booking rules. NOT VALID = enforced on every new or changed row from now on,
-- without re-checking existing rows while this file runs. To check old rows
-- too, see Appendix C.
alter table public.bookings drop constraint if exists bookings_booked_by_nonblank;
alter table public.bookings add constraint bookings_booked_by_nonblank
  check (length(btrim(booked_by)) >= 1) not valid;

alter table public.bookings drop constraint if exists bookings_conflict_note_length;
alter table public.bookings add constraint bookings_conflict_note_length
  check (conflict_note is null or char_length(conflict_note) <= 500) not valid;

-- An overnight booking ends the next day; nothing may end earlier than it
-- starts or span more than one following day.
alter table public.bookings drop constraint if exists bookings_end_date_valid;
alter table public.bookings add constraint bookings_end_date_valid
  check (end_date is not null
         and end_date between booking_date and booking_date + 1) not valid;

alter table public.bookings drop constraint if exists bookings_positive_duration;
alter table public.bookings add constraint bookings_positive_duration
  check ((end_date + end_time) > (booking_date + start_time)) not valid;

alter table public.bookings drop constraint if exists bookings_max_duration;
alter table public.bookings add constraint bookings_max_duration
  check ((end_date + end_time) <= (booking_date + start_time + interval '24 hours')) not valid;

-- Clean-up of objects from earlier drafts (no-ops if already gone):
-- a purpose-length constraint that duplicated the column rule, and a
-- 2-argument version of update_booking_statuses_atomic that was replaced by
-- the 3-argument one in section 7.
alter table public.bookings drop constraint if exists bookings_purpose_length;
drop function if exists public.update_booking_statuses_atomic(text[], text);


-- ============================================================================
-- 4. ROW LEVEL SECURITY
-- ============================================================================
-- RLS is the real security boundary: the publishable key in the page source
-- lets anyone call the API, and these policies decide what they get.
--
-- Supporting tables (audit, idempotency, rate logs, archive) have RLS ON and
-- NO policies except the admin's read access to the audit log. That is
-- intentional: only the SECURITY DEFINER functions in this file, which run as
-- the table owner, may touch them. Do not add policies to "fix" empty
-- results, and do not set FORCE ROW LEVEL SECURITY — either breaks the
-- triggers silently.
alter table public.bookings            enable row level security;
alter table public.booking_audit_log   enable row level security;
alter table public.booking_idempotency enable row level security;
alter table public.booking_rate_log    enable row level security;
alter table public.login_attempt_log   enable row level security;
alter table public.bookings_archive    enable row level security;
alter table public.admin_session_activity enable row level security;

drop policy if exists "Public can view bookings"           on public.bookings;
drop policy if exists "Public sees only active bookings"   on public.bookings;
drop policy if exists "Public can create pending requests" on public.bookings;
drop policy if exists "Admins can insert any booking"      on public.bookings;
drop policy if exists "Admins can update bookings"         on public.bookings;
drop policy if exists "Admins can delete bookings"         on public.bookings;
drop policy if exists "Admin can view booking audit"       on public.booking_audit_log;

-- Anyone can read bookings: this powers the public room-status board.
-- Accepted for an intranet tool — see Appendix D.
create policy "Public can view bookings"
  on public.bookings for select
  using (true);

-- ...but not Rejected or Cancelled history ("X asked and was refused" is
-- nobody's business). RESTRICTIVE, so it narrows the policy above instead of
-- widening it. Uses auth.role(), NOT is_admin(): is_admin() is not executable
-- by anon, and calling it here would make every public read fail. The
-- authenticated clause keeps the admin's "Show rejected" toggle working.
create policy "Public sees only active bookings"
  on public.bookings as restrictive for select
  to public
  using (
    status in ('Pending','Confirmed')
    or auth.role() = 'authenticated'
  );

-- Anyone can submit a request, but only as Pending, with no conflict fields
-- and not for a past date. The app submits through create_bookings_atomic()
-- (section 7), which applies the same rules; this policy covers anyone
-- posting to the table directly. current_date is UTC, which is behind IST,
-- so "today" in Mumbai always passes.
create policy "Public can create pending requests"
  on public.bookings for insert
  with check (
    status = 'Pending'
    and conflict_resolved = false
    and (conflict_note is null or conflict_note = '')
    and booking_date >= current_date
  );

-- Admin writes. Gated on is_admin(), not just "logged in": policy names mean
-- nothing to Postgres, and these once read `using (true)`, which gave ANY
-- signed-in account full control. Sign-ups are also disabled in the Supabase
-- dashboard — two independent locks.
-- `(select public.is_admin())` rather than a bare call: Postgres then runs it
-- once per statement instead of once per row (is_admin() now reads a table).
create policy "Admins can insert any booking"
  on public.bookings for insert
  to authenticated
  with check ((select public.is_admin()));

create policy "Admins can update bookings"
  on public.bookings for update
  to authenticated
  using ((select public.is_admin()))
  with check ((select public.is_admin()));

create policy "Admins can delete bookings"
  on public.bookings for delete
  to authenticated
  using ((select public.is_admin()));

-- Only the admin can read the audit trail. Nobody can write to it directly.
create policy "Admin can view booking audit"
  on public.booking_audit_log for select
  to authenticated
  using ((select public.is_admin()));


-- ============================================================================
-- 5. AUDIT TRAIL
-- ============================================================================
-- Every INSERT, UPDATE and DELETE on bookings — from the app, the public
-- self-service flow, the archive job or the SQL editor — writes one row with
-- who (role, user id, email, IP), when, and the row before and after.
-- auth.role() / auth.jwt() read the request's JWT, so they still identify the
-- real caller inside SECURITY DEFINER functions. actor_role 'database' means
-- no JWT (SQL editor or scheduled job).
create or replace function public.audit_booking_change()
returns trigger
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
  insert into public.booking_audit_log
    (booking_id, action, actor_role, actor_id, actor_email, client_ip,
     transaction_id, old_row, new_row)
  values
    (coalesce(new.booking_id, old.booking_id),
     tg_op,
     coalesce(auth.role(), 'database'),
     auth.uid(),
     auth.jwt() ->> 'email',
     public.client_ip(),
     txid_current(),
     case when tg_op in ('UPDATE','DELETE') then to_jsonb(old) end,
     case when tg_op in ('INSERT','UPDATE') then to_jsonb(new) end);
  return coalesce(new, old);
end;
$$;

-- Append-only: blocks UPDATE and DELETE on the audit log for everyone,
-- including service_role (which bypasses RLS but not triggers).
create or replace function public.audit_log_is_append_only()
returns trigger
language plpgsql
set search_path = public, pg_temp
as $$
begin
  raise exception 'booking_audit_log is append-only.' using errcode = '42501';
end;
$$;

drop trigger if exists trg_audit_booking_change on public.bookings;
create trigger trg_audit_booking_change
  after insert or update or delete on public.bookings
  for each row execute function public.audit_booking_change();

drop trigger if exists trg_audit_log_append_only on public.booking_audit_log;
create trigger trg_audit_log_append_only
  before update or delete on public.booking_audit_log
  for each row execute function public.audit_log_is_append_only();


-- ============================================================================
-- 6. BOOKING TRIGGERS
-- ============================================================================
-- These run on every write to bookings, whatever path it came from, so the
-- rules hold even if the browser code is wrong or bypassed.

-- 6.1 Room capacity. Seat counts DUPLICATE js/config.js ROOMS;
--     scripts/verify.mjs fails the build if the two disagree. A room added to
--     config.js with a capacity other than 30 must be added to the CASE.
--   - The admin may overbook ("Book anyway"): attendee counts are estimates.
--   - Public requests are hard-capped.
--   - An UPDATE that changes neither room nor attendees is skipped, so an
--     admin-overbooked booking can still be cancelled or released by its
--     booker through the public functions.
--   - SECURITY INVOKER on purpose: it reads no tables, and as DEFINER
--     auth.role() would report the owner and hand everyone the override.
create or replace function public.enforce_room_capacity()
returns trigger
language plpgsql
set search_path = public, pg_temp
as $$
declare
  v_cap integer;
begin
  if auth.role() = 'authenticated' then
    return new;
  end if;
  if tg_op = 'UPDATE' and new.room = old.room
     and new.attendees is not distinct from old.attendees then
    return new;
  end if;

  v_cap := case new.room
    when 'chanakya' then 45
    when 'conf2f'   then 5
    else 30
  end;
  if new.attendees is not null and new.attendees > v_cap then
    raise exception 'Room % holds up to % people (got %).', new.room, v_cap, new.attendees;
  end if;
  return new;
end;
$$;

-- 6.2 No overlapping Confirmed bookings in the same room.
--   - Only Confirmed bookings occupy a room; Pending ones never block.
--   - pg_advisory_xact_lock serialises writes per room until COMMIT, so two
--     people confirming the same slot at the same instant cannot both win.
--   - Shortening a Confirmed booking within its own time (Release Early) is
--     always allowed, even in a room shared through "Approve anyway".
--   - Skipped when the admin override flag is on (see header).
create or replace function public.enforce_no_confirmed_overlap()
returns trigger
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_new      tsrange;
  v_old      tsrange;
  v_conflict text;
begin
  if new.status <> 'Confirmed' then
    return new;
  end if;
  if coalesce(current_setting('app.allow_booking_conflict', true), 'off') = 'on' then
    return new;
  end if;

  v_new := tsrange(new.booking_date + new.start_time,
                   public.booking_end_ts(new.booking_date, new.start_time,
                                         new.end_time, new.end_date), '[)');

  if tg_op = 'UPDATE' and old.status = 'Confirmed' and old.room = new.room then
    v_old := tsrange(old.booking_date + old.start_time,
                     public.booking_end_ts(old.booking_date, old.start_time,
                                           old.end_time, old.end_date), '[)');
    if v_new <@ v_old then
      return new;
    end if;
  end if;

  perform pg_advisory_xact_lock(hashtextextended('ldrooms:' || new.room, 0));

  select b.booking_id into v_conflict
    from public.bookings b
   where b.room = new.room
     and b.status = 'Confirmed'
     and b.booking_id <> new.booking_id
     and b.booking_date between new.booking_date - 1 and new.booking_date + 1
     and tsrange(b.booking_date + b.start_time,
                 public.booking_end_ts(b.booking_date, b.start_time,
                                       b.end_time, b.end_date), '[)') && v_new
   limit 1;

  if v_conflict is not null then
    raise exception 'ROOM_CONFLICT: room % is already booked at this time (booking %).',
      new.room, v_conflict
      using errcode = '23P01';
  end if;
  return new;
end;
$$;

-- 6.3 Insert rate limit.
--   - Admin: 5 actions/minute. Public: 20 actions/minute per client IP —
--     a whole office shares one IP behind NAT, so the number is generous.
--   - Counts distinct transactions, not rows: a 65-day recurring request is
--     one action. (Counting rows made every recurring request fail.)
--   - Keyed by IP, not by the typed name, which anyone can change per request.
create or replace function public.enforce_booking_rate_limit()
returns trigger
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_actor      text;
  v_limit      integer;
  v_recent_cnt integer;
begin
  if auth.role() = 'authenticated' then
    v_actor := 'auth:' || auth.uid()::text;
    v_limit := 5;
  else
    v_actor := 'ip:' || coalesce(public.client_ip()::text, 'unknown');
    v_limit := 20;
  end if;

  delete from public.booking_rate_log where created_at < now() - interval '2 minutes';

  select count(distinct txid) into v_recent_cnt
  from public.booking_rate_log
  where actor = v_actor and created_at > now() - interval '60 seconds';

  if v_recent_cnt >= v_limit then
    raise exception 'Rate limit exceeded: max % booking action(s) per minute. Please wait a moment and try again.', v_limit
      using errcode = 'P0001';
  end if;

  insert into public.booking_rate_log (actor, txid)
  values (v_actor, txid_current())
  on conflict do nothing;
  return new;
end;
$$;

-- BEFORE triggers fire in name order: rate limit, capacity, overlap.
drop trigger if exists trg_enforce_booking_rate_limit on public.bookings;
create trigger trg_enforce_booking_rate_limit
  before insert on public.bookings
  for each row
  execute function public.enforce_booking_rate_limit();

drop trigger if exists trg_enforce_room_capacity on public.bookings;
create trigger trg_enforce_room_capacity
  before insert or update on public.bookings
  for each row
  execute function public.enforce_room_capacity();

drop trigger if exists trg_no_confirmed_overlap on public.bookings;
create trigger trg_no_confirmed_overlap
  before insert or update of room, booking_date, start_time, end_time, end_date, status
  on public.bookings
  for each row execute function public.enforce_no_confirmed_overlap();


-- ============================================================================
-- 7. BOOKING WRITE FUNCTIONS (atomic RPCs)
-- ============================================================================
-- Every booking change the app makes goes through one of these. Each call is
-- ONE transaction: it fully succeeds or changes nothing — there is never a
-- half-saved recurring booking or a half-applied bulk action.
--
-- They are SECURITY DEFINER (so they bypass RLS), which is why each one
-- re-checks who is calling: admin-only functions call is_admin(), and the one
-- public function re-applies the public INSERT policy's rules itself.
--
-- Error codes the app translates into messages (js/api/bookings.js):
--   23P01 room conflict   23514 invalid data   42501 not allowed
--   P0002 booking no longer exists   22023 bad request   P0001 rate limit

-- Identity used for idempotency keys: user id for the admin, IP for public.
create or replace function public.booking_actor_key()
returns text
language sql
stable
set search_path = public, pg_temp
as $$
  select case when auth.role() = 'authenticated'
              then 'auth:' || coalesce(auth.uid()::text, 'unknown')
              else 'ip:'   || coalesce(public.client_ip()::text, 'unknown')
         end
$$;

-- Create 1..100 bookings (the UI allows at most 65 recurring dates).
--   Public callers: Pending only, no past dates, no conflict fields.
--   Admin: any status; p_allow_conflicts = "Approve anyway".
--   p_request_key: the same key twice returns the first result instead of
--   creating the bookings again. A failed attempt rolls back its key too, so
--   a retry after a failure is processed normally.
create or replace function public.create_bookings_atomic(
  p_rows            jsonb,
  p_request_key     text,
  p_allow_conflicts boolean default false
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_is_admin boolean := coalesce(auth.role() = 'authenticated' and public.is_admin(), false);
  v_actor    text;
  v_response jsonb;
  v_count    integer := 0;
  v_status   text;
  r          jsonb;
begin
  if auth.role() = 'authenticated' and not v_is_admin then
    raise exception 'Admin access required.' using errcode = '42501';
  end if;
  if p_request_key is null or p_request_key !~ '^[A-Za-z0-9_-]{16,100}$' then
    raise exception 'Invalid request key.' using errcode = '22023';
  end if;
  if p_rows is null or jsonb_typeof(p_rows) <> 'array'
     or jsonb_array_length(p_rows) not between 1 and 100 then
    raise exception 'A request must contain between 1 and 100 bookings.' using errcode = '22023';
  end if;
  if coalesce(p_allow_conflicts, false) and not v_is_admin then
    raise exception 'Only the admin can override a conflict.' using errcode = '42501';
  end if;

  v_actor := public.booking_actor_key();
  delete from public.booking_idempotency where created_at < now() - interval '24 hours';
  insert into public.booking_idempotency (actor_key, request_key)
  values (v_actor, p_request_key)
  on conflict do nothing;
  if not found then
    select response into v_response
      from public.booking_idempotency
     where actor_key = v_actor and request_key = p_request_key;
    return coalesce(v_response, jsonb_build_object('ok', true, 'created', 0))
           || jsonb_build_object('duplicate', true);
  end if;

  if coalesce(p_allow_conflicts, false) then
    perform set_config('app.allow_booking_conflict', 'on', true);
  end if;

  for r in select value from jsonb_array_elements(p_rows) loop
    v_status := coalesce(nullif(r ->> 'status', ''), 'Pending');
    if not v_is_admin then
      if v_status <> 'Pending' then
        raise exception 'Requests are created as Pending.' using errcode = '42501';
      end if;
      if (r ->> 'booking_date')::date < current_date then
        raise exception 'Bookings cannot be made for a past date.' using errcode = '22023';
      end if;
      if coalesce((r ->> 'conflict_resolved')::boolean, false)
         or coalesce(r ->> 'conflict_note', '') <> '' then
        raise exception 'Conflict fields are admin-only.' using errcode = '42501';
      end if;
    end if;

    insert into public.bookings
      (booking_id, room, booked_by, purpose, booking_date, start_time, end_time,
       attendees, status, end_date, conflict_resolved, conflict_note)
    values
      (r ->> 'booking_id',
       r ->> 'room',
       btrim(r ->> 'booked_by'),
       coalesce(btrim(r ->> 'purpose'), ''),
       (r ->> 'booking_date')::date,
       (r ->> 'start_time')::time,
       (r ->> 'end_time')::time,
       nullif(r ->> 'attendees', '')::integer,
       v_status,
       (r ->> 'end_date')::date,
       coalesce((r ->> 'conflict_resolved')::boolean, false),
       coalesce(r ->> 'conflict_note', ''));
    v_count := v_count + 1;
  end loop;

  perform set_config('app.allow_booking_conflict', 'off', true);

  v_response := jsonb_build_object('ok', true, 'created', v_count, 'duplicate', false);
  update public.booking_idempotency
     set response = v_response
   where actor_key = v_actor and request_key = p_request_key;
  return v_response;
end;
$$;

-- Update one booking: admin edit, early release, move to another room.
create or replace function public.update_booking_atomic(
  p_row             jsonb,
  p_allow_conflicts boolean default false
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_count integer;
begin
  if not coalesce(auth.role() = 'authenticated' and public.is_admin(), false) then
    raise exception 'Admin access required.' using errcode = '42501';
  end if;
  if p_row is null or jsonb_typeof(p_row) <> 'object' or coalesce(p_row ->> 'booking_id', '') = '' then
    raise exception 'Booking data is required.' using errcode = '22023';
  end if;
  if coalesce(p_allow_conflicts, false) then
    perform set_config('app.allow_booking_conflict', 'on', true);
  end if;

  update public.bookings
     set room              = p_row ->> 'room',
         booked_by         = btrim(p_row ->> 'booked_by'),
         purpose           = coalesce(btrim(p_row ->> 'purpose'), ''),
         booking_date      = (p_row ->> 'booking_date')::date,
         start_time        = (p_row ->> 'start_time')::time,
         end_time          = (p_row ->> 'end_time')::time,
         attendees         = nullif(p_row ->> 'attendees', '')::integer,
         status            = coalesce(nullif(p_row ->> 'status', ''), 'Confirmed'),
         end_date          = (p_row ->> 'end_date')::date,
         conflict_resolved = coalesce((p_row ->> 'conflict_resolved')::boolean, false),
         conflict_note     = coalesce(p_row ->> 'conflict_note', '')
   where booking_id = p_row ->> 'booking_id';
  get diagnostics v_count = row_count;

  perform set_config('app.allow_booking_conflict', 'off', true);

  if v_count <> 1 then
    raise exception 'Booking % no longer exists.', p_row ->> 'booking_id' using errcode = 'P0002';
  end if;
  return jsonb_build_object('ok', true, 'updated', v_count);
end;
$$;

-- One status for many bookings: approve, reject or cancel, single or bulk.
-- If any selected booking no longer exists, nothing is changed.
create or replace function public.update_booking_statuses_atomic(
  p_ids             text[],
  p_status          text,
  p_allow_conflicts boolean default false
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_ids   text[];
  v_count integer;
begin
  if not coalesce(auth.role() = 'authenticated' and public.is_admin(), false) then
    raise exception 'Admin access required.' using errcode = '42501';
  end if;
  if p_status is null or p_status not in ('Confirmed','Pending','Cancelled','Rejected') then
    raise exception 'Invalid status.' using errcode = '22023';
  end if;
  select array_agg(distinct x) into v_ids from unnest(p_ids) as x where x is not null;
  if v_ids is null or cardinality(v_ids) not between 1 and 500 then
    raise exception 'Between 1 and 500 bookings must be selected.' using errcode = '22023';
  end if;
  if coalesce(p_allow_conflicts, false) then
    perform set_config('app.allow_booking_conflict', 'on', true);
  end if;

  update public.bookings set status = p_status where booking_id = any(v_ids);
  get diagnostics v_count = row_count;

  perform set_config('app.allow_booking_conflict', 'off', true);

  if v_count <> cardinality(v_ids) then
    raise exception 'One or more selected bookings no longer exist. Nothing was changed.' using errcode = 'P0002';
  end if;
  return jsonb_build_object('ok', true, 'updated', v_count);
end;
$$;

-- Approve several conflicting requests, each with its own resolution:
-- move to another room, or approve anyway (override).
--   p_items: [{"booking_id": "...", "room": "<room id or null>", "override": true|false}]
create or replace function public.approve_bookings_atomic(p_items jsonb)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  it      jsonb;
  v_count integer;
  v_total integer := 0;
begin
  if not coalesce(auth.role() = 'authenticated' and public.is_admin(), false) then
    raise exception 'Admin access required.' using errcode = '42501';
  end if;
  if p_items is null or jsonb_typeof(p_items) <> 'array'
     or jsonb_array_length(p_items) not between 1 and 500 then
    raise exception 'Between 1 and 500 bookings must be supplied.' using errcode = '22023';
  end if;

  for it in select value from jsonb_array_elements(p_items) loop
    perform set_config('app.allow_booking_conflict',
                       case when coalesce((it ->> 'override')::boolean, false) then 'on' else 'off' end,
                       true);
    update public.bookings
       set status = 'Confirmed',
           room   = coalesce(nullif(it ->> 'room', ''), room)
     where booking_id = it ->> 'booking_id';
    get diagnostics v_count = row_count;
    if v_count <> 1 then
      perform set_config('app.allow_booking_conflict', 'off', true);
      raise exception 'Booking % no longer exists. Nothing was changed.', it ->> 'booking_id'
        using errcode = 'P0002';
    end if;
    v_total := v_total + 1;
  end loop;

  perform set_config('app.allow_booking_conflict', 'off', true);
  return jsonb_build_object('ok', true, 'approved', v_total);
end;
$$;

-- Permanently delete bookings. The audit trail keeps a full copy of each.
create or replace function public.delete_bookings_atomic(p_ids text[])
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_ids   text[];
  v_count integer;
begin
  if not coalesce(auth.role() = 'authenticated' and public.is_admin(), false) then
    raise exception 'Admin access required.' using errcode = '42501';
  end if;
  select array_agg(distinct x) into v_ids from unnest(p_ids) as x where x is not null;
  if v_ids is null or cardinality(v_ids) not between 1 and 500 then
    raise exception 'Between 1 and 500 bookings must be selected.' using errcode = '22023';
  end if;
  delete from public.bookings where booking_id = any(v_ids);
  get diagnostics v_count = row_count;
  if v_count <> cardinality(v_ids) then
    raise exception 'One or more selected bookings no longer exist. Nothing was deleted.' using errcode = 'P0002';
  end if;
  return jsonb_build_object('ok', true, 'deleted', v_count);
end;
$$;

-- Recurring edit: replace one booking with a set of dated bookings.
-- The original is deleted first INSIDE the transaction, so a replacement for
-- the same slot does not clash with it; if any date fails, the delete rolls
-- back too and the original is untouched.
create or replace function public.replace_booking_atomic(
  p_original_id text,
  p_rows        jsonb,
  p_request_key text
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_result jsonb;
begin
  if not coalesce(auth.role() = 'authenticated' and public.is_admin(), false) then
    raise exception 'Admin access required.' using errcode = '42501';
  end if;

  select response into v_result
    from public.booking_idempotency
   where actor_key = public.booking_actor_key()
     and request_key = p_request_key
     and response is not null;
  if found then
    return v_result || jsonb_build_object('duplicate', true, 'replaced', p_original_id);
  end if;

  perform 1 from public.bookings where booking_id = p_original_id for update;
  if not found then
    raise exception 'The original booking no longer exists.' using errcode = 'P0002';
  end if;

  delete from public.bookings where booking_id = p_original_id;
  v_result := public.create_bookings_atomic(p_rows, p_request_key, false);
  return v_result || jsonb_build_object('replaced', p_original_id);
end;
$$;


-- ============================================================================
-- 8. PUBLIC SELF-SERVICE: CANCEL / RELEASE
-- ============================================================================
-- The only way an anonymous caller can change an existing booking. The typed
-- name must match booked_by (case and surrounding spaces ignored). Names are
-- visible on the public board, so this prevents accidents rather than
-- deliberate misuse — accepted for an intranet tool, and every use is in the
-- audit trail with the caller's IP. See Appendix D.

create or replace function public.cancel_own_booking(
  p_booking_id  text,
  p_booker_name text
)
returns json
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_row public.bookings;
begin
  -- NULL-SAFE. `x <> NULL` is NULL, not TRUE, so an IF built on it never
  -- fires: before this check, cancel_own_booking('<any id>', null) passed the
  -- name check and cancelled ANY booking. Reject missing input first, and
  -- compare with IS DISTINCT FROM, which treats NULL as a real value.
  if p_booking_id is null or nullif(btrim(p_booker_name), '') is null then
    return json_build_object('ok', false, 'error', 'Booking and name are required.');
  end if;

  -- FOR UPDATE: a cancel and a release of the same booking cannot interleave.
  select * into v_row from public.bookings where booking_id = p_booking_id for update;

  if not found then
    return json_build_object('ok', false, 'error', 'Booking not found.');
  end if;

  if lower(btrim(v_row.booked_by)) is distinct from lower(btrim(p_booker_name)) then
    return json_build_object('ok', false, 'error', 'Name does not match booking.');
  end if;

  -- Only live bookings. Cancelling a Rejected or already-Cancelled row would
  -- rewrite history ("refused" becoming "withdrawn").
  if v_row.status not in ('Pending', 'Confirmed') then
    return json_build_object('ok', false,
      'error', 'Only a pending or confirmed booking can be cancelled.');
  end if;

  -- Not after it has finished: that would erase used hours from utilisation
  -- reporting. Compared in IST, the timezone the times are entered in.
  if public.booking_end_ts(v_row.booking_date, v_row.start_time,
                           v_row.end_time, v_row.end_date)
     <= (now() at time zone 'Asia/Kolkata') then
    return json_build_object('ok', false,
      'error', 'This booking has already finished and cannot be cancelled.');
  end if;

  update public.bookings set status = 'Cancelled' where booking_id = p_booking_id;

  return json_build_object('ok', true, 'action', 'cancelled', 'BookingID', p_booking_id);
end;
$$;

-- Release = end a running booking early. Guards:
--   - every argument required (NULL arguments used to skip the checks below,
--     because comparisons with NULL are never TRUE);
--   - only Confirmed bookings;
--   - may only SHORTEN (an earlier version let anyone extend any booking by
--     a year with a single call);
--   - the new end must be after the start: end <= start is read as an
--     overnight booking and would turn "release" into a 24-hour block;
--   - the new end cannot be in the past: release means "from now".
create or replace function public.release_own_booking(
  p_booking_id  text,
  p_booker_name text,
  p_end_time    time,
  p_end_date    date
)
returns json
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_row     public.bookings;
  v_start   timestamp;
  v_old_end timestamp;
  v_new_end timestamp;
begin
  if p_booking_id is null or nullif(btrim(p_booker_name), '') is null
     or p_end_time is null or p_end_date is null then
    return json_build_object('ok', false, 'error', 'All release details are required.');
  end if;

  select * into v_row from public.bookings where booking_id = p_booking_id for update;

  if not found then
    return json_build_object('ok', false, 'error', 'Booking not found.');
  end if;

  if lower(btrim(v_row.booked_by)) is distinct from lower(btrim(p_booker_name)) then
    return json_build_object('ok', false, 'error', 'Name does not match booking.');
  end if;

  if v_row.status <> 'Confirmed' then
    return json_build_object('ok', false, 'error', 'Only a Confirmed booking can be released.');
  end if;

  v_start   := v_row.booking_date + v_row.start_time;
  v_old_end := public.booking_end_ts(v_row.booking_date, v_row.start_time,
                                     v_row.end_time, v_row.end_date);
  v_new_end := p_end_date + p_end_time;

  if v_new_end > v_old_end then
    return json_build_object('ok', false, 'error', 'Release cannot extend a booking.');
  end if;

  if v_new_end <= v_start then
    return json_build_object('ok', false, 'error', 'Release time is at or before the booking start — cancel it instead.');
  end if;

  -- 5 minutes' grace for a slow device clock or a form left open briefly.
  if v_new_end < (now() at time zone 'Asia/Kolkata') - interval '5 minutes' then
    return json_build_object('ok', false, 'error', 'Release time cannot be in the past.');
  end if;

  update public.bookings
     set end_time = p_end_time,
         end_date = p_end_date
   where booking_id = p_booking_id;

  return json_build_object('ok', true, 'action', 'released', 'BookingID', p_booking_id);
end;
$$;


-- ============================================================================
-- 9. CHANGE MARKER
-- ============================================================================
-- Each open tab asks this every 60 seconds and on focus, and downloads the
-- bookings table only when the answer changes — instead of downloading the
-- whole table every minute.
--   m = highest audit_id -> moves on every change
--   c = audit row count  -> also moves when a transaction holding a LOWER
--                           audit_id commits after a higher one (which would
--                           leave m unchanged)
-- Reveals only two counters, so it is safe for anon.
create or replace function public.bookings_change_marker()
returns jsonb
language sql
stable
security definer
set search_path = public, pg_temp
as $$
  select jsonb_build_object('m', coalesce(max(audit_id), 0), 'c', count(*))
  from public.booking_audit_log
$$;


-- ============================================================================
-- 10. LOGIN RATE LIMIT
-- ============================================================================
-- At most 10 failed admin logins per client IP per 5 minutes, enforced here
-- because the browser's own counter resets on refresh. Only FAILED attempts
-- are logged (log_failed_login is called by js/api/auth.js after a wrong
-- password), so normal use never counts towards the limit.
-- Limitation: Supabase Auth itself can be called directly with the
-- publishable key; Supabase's built-in auth rate limit applies there.

create or replace function public.check_login_rate_limit()
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_recent_cnt integer;
  v_limit      integer  := 10;
  v_window     interval := interval '5 minutes';
  v_oldest     timestamptz;
  v_ip         inet     := public.client_ip();
begin
  delete from public.login_attempt_log where created_at < now() - interval '30 minutes';

  select count(*), min(created_at)
    into v_recent_cnt, v_oldest
  from public.login_attempt_log
  where created_at > now() - v_window
    and ip is not distinct from v_ip;

  if v_recent_cnt >= v_limit then
    return jsonb_build_object(
      'ok', false,
      'retry_after_seconds', greatest(1, extract(epoch from (v_oldest + v_window - now()))::int)
    );
  end if;

  return jsonb_build_object('ok', true);
end;
$$;

create or replace function public.log_failed_login()
returns void
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
  insert into public.login_attempt_log (ip) values (public.client_ip());
end;
$$;


-- ============================================================================
-- 10b. ADMIN IDLE TIMEOUT (server-side)
-- ============================================================================
-- The browser signs the admin out after 10 minutes without activity, but a
-- browser timer is advice, not enforcement: the Supabase session is a JWT
-- plus a refresh token in localStorage, and on its own the server would
-- honour it indefinitely. These functions make the server enforce it too.
--
--   Browser                          Server
--   real activity (click/key/...) -> admin_heartbeat()  at most once a minute
--   background refresh            -> nothing (does not count as activity)
--   10 min idle                   -> admin_end_session(), then sign-out
--   12 min idle (any reason)      -> is_admin() = false: every admin write
--                                    and admin RLS policy refuses the session
--   stale session seen again      -> revoked: refresh token deleted
--
-- Revocation deletes the session from auth.sessions (Supabase's own table;
-- its refresh tokens go with it). If this project's database role may not
-- delete there, the delete is skipped with a NOTICE — is_admin() still
-- refuses the session, so it remains powerless, only its token survives
-- until Supabase expires it. Appendix B has an optional job that revokes
-- sessions abandoned with the browser closed.

-- Revoke one admin session: tombstone the activity row (permanent) and
-- delete the Supabase session so its refresh token stops working.
create or replace function public.revoke_admin_session(p_session_id uuid)
returns void
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
  if p_session_id is null then
    return;
  end if;
  insert into public.admin_session_activity (session_id, last_seen, revoked_at)
  values (p_session_id, now(), now())
  on conflict (session_id) do update
    set revoked_at = coalesce(public.admin_session_activity.revoked_at, now());
  begin
    delete from auth.sessions where id = p_session_id;
  exception when others then
    raise notice 'Admin session % tombstoned but not deleted from auth.sessions (%). is_admin() refuses it regardless.',
      p_session_id, sqlerrm;
  end;
end;
$$;

-- Called by the browser on real user activity (throttled to once a minute)
-- and right after sign-in. Returns {ok:true} or {ok:false, expired:true}.
--   - An existing session is extended only if it is still within the limit:
--     the first click after an overnight absence must END the session, not
--     revive it (the same race the browser guards against in js/app.js).
--   - A session with no record yet may start one only with a token issued in
--     the last 2 minutes, i.e. a fresh sign-in. An old token cannot start
--     the clock afresh.
create or replace function public.admin_heartbeat()
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_sid uuid := public.jwt_session_id();
  v_row public.admin_session_activity;
  v_iat bigint;
begin
  if auth.role() is distinct from 'authenticated' or not public.is_admin_account() then
    raise exception 'Admin access required.' using errcode = '42501';
  end if;
  if v_sid is null then
    raise exception 'Sign-in token has no session id.' using errcode = '42501';
  end if;

  select * into v_row from public.admin_session_activity
   where session_id = v_sid for update;

  if found then
    if v_row.revoked_at is not null
       or v_row.last_seen <= now() - public.admin_idle_limit() then
      perform public.revoke_admin_session(v_sid);
      return jsonb_build_object('ok', false, 'expired', true);
    end if;
    update public.admin_session_activity set last_seen = now()
     where session_id = v_sid;
    return jsonb_build_object('ok', true);
  end if;

  begin
    v_iat := (auth.jwt() ->> 'iat')::bigint;
  exception when others then
    v_iat := null;
  end;
  if v_iat is null or v_iat < extract(epoch from now())::bigint - 120 then
    perform public.revoke_admin_session(v_sid);
    return jsonb_build_object('ok', false, 'expired', true);
  end if;

  insert into public.admin_session_activity (session_id, user_id)
  values (v_sid, auth.uid());
  return jsonb_build_object('ok', true);
end;
$$;

-- Called by the browser on logout and on idle timeout, BEFORE signing out,
-- so the session loses admin rights at the server immediately (sign-out
-- alone leaves the access token usable until it expires, up to an hour).
-- Only ever ends the caller's own session.
create or replace function public.admin_end_session()
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
  if auth.role() is distinct from 'authenticated' or not public.is_admin_account() then
    raise exception 'Admin access required.' using errcode = '42501';
  end if;
  perform public.revoke_admin_session(public.jwt_session_id());
  return jsonb_build_object('ok', true);
end;
$$;

-- Optional scheduled job (Appendix B): revoke admin sessions abandoned with
-- the browser closed — nothing else would ever look at them again — and
-- purge tombstones older than 90 days. Returns the number revoked.
create or replace function public.expire_idle_admin_sessions()
returns integer
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  r record;
  v_count integer := 0;
begin
  for r in
    select session_id from public.admin_session_activity
     where revoked_at is null
       and last_seen <= now() - public.admin_idle_limit()
  loop
    perform public.revoke_admin_session(r.session_id);
    v_count := v_count + 1;
  end loop;
  delete from public.admin_session_activity
   where coalesce(revoked_at, last_seen) < now() - interval '90 days';
  return v_count;
end;
$$;


-- ============================================================================
-- 11. ARCHIVE AND REPORTING VIEWS
-- ============================================================================

-- Move bookings more than p_days old (not Pending) into bookings_archive.
-- Run daily by pg_cron (Appendix B), or by hand from the SQL editor.
--   - p_days must be >= 1: a negative value would archive every booking.
--   - Columns are named, not `select *`, so drift between the two tables
--     fails loudly instead of writing values into the wrong columns.
--   - Each move is recorded in the audit trail as a DELETE.
create or replace function public.archive_old_bookings(p_days integer default 90)
returns integer
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_count integer;
begin
  if p_days is null or p_days < 1 then
    raise exception 'p_days must be >= 1 (got %).', p_days;
  end if;

  with moved as (
    delete from public.bookings
    where booking_date < (current_date - p_days)
      and status <> 'Pending'
    returning
      booking_id, room, booked_by, purpose, booking_date, start_time,
      end_time, attendees, status, end_date, conflict_resolved,
      conflict_note, created_at
  )
  insert into public.bookings_archive (
    booking_id, room, booked_by, purpose, booking_date, start_time,
    end_time, attendees, status, end_date, conflict_resolved,
    conflict_note, created_at
  )
  select
    booking_id, room, booked_by, purpose, booking_date, start_time,
    end_time, attendees, status, end_date, conflict_resolved,
    conflict_note, created_at
  from moved;

  get diagnostics v_count = row_count;
  return v_count;
end;
$$;

-- Reporting views: live + archive as one dataset (bookings keeps only ~90
-- days). For the SQL editor; not granted to the app's roles (section 12).
-- security_invoker = true is NOT optional: without it a view runs as its
-- owner and bypasses every RLS policy above.
-- To remove: drop room_utilisation_monthly first (it depends on bookings_all).
create or replace view public.bookings_all
with (security_invoker = true) as
  select
    booking_id, room, booked_by, purpose, booking_date, start_time,
    end_time, attendees, status, end_date, conflict_resolved,
    conflict_note, created_at,
    'live'::text as source
  from public.bookings
  union all
  select
    booking_id, room, booked_by, purpose, booking_date, start_time,
    end_time, attendees, status, end_date, conflict_resolved,
    conflict_note, created_at,
    'archive'::text as source
  from public.bookings_archive;

comment on view public.bookings_all is
  'Live + archived bookings as one dataset, for reporting in the SQL editor. security_invoker=true so RLS still applies. Not granted to anon or authenticated.';

-- Booked hours per room per month, Confirmed only. coalesce(end_date, ...)
-- handles overnight bookings, which would otherwise compute negative hours.
create or replace view public.room_utilisation_monthly
with (security_invoker = true) as
  select
    room,
    date_trunc('month', booking_date)::date as month,
    count(*)                                as bookings,
    round(sum(
      extract(epoch from (
        (coalesce(end_date, booking_date) + end_time)
        - (booking_date + start_time)
      )) / 3600.0
    )::numeric, 1)                          as booked_hours,
    round(avg(attendees)::numeric, 1)       as avg_attendees,
    max(attendees)                          as max_attendees
  from public.bookings_all
  where status = 'Confirmed'
  group by room, date_trunc('month', booking_date);

comment on view public.room_utilisation_monthly is
  'Booked hours and headcount per room per month, confirmed only, across live + archive.';


-- ============================================================================
-- 12. PRIVILEGES — every grant in one place
-- ============================================================================
-- Supabase's default privileges grant ALL on every new table/view and
-- EXECUTE on every new function directly to anon and authenticated.
-- Revoking from PUBLIC alone is therefore not enough: every object below is
-- revoked from public, anon AND authenticated, then granted back explicitly.
--
--   anon (public visitors)   authenticated (the admin)
--   ----------------------   -------------------------------------------
--   create_bookings_atomic   everything anon has, plus the admin RPCs,
--   cancel_own_booking       is_admin(), admin_heartbeat(),
--                            admin_end_session(), read access to the audit log
--   release_own_booking
--   bookings_change_marker   service_role: archive_old_bookings (scheduled job)
--   check_login_rate_limit
--   log_failed_login
--
-- bookings: anon may only READ it directly (the public board). Every write
-- goes through the SECURITY DEFINER functions in sections 7-8, which run as
-- the owner and need no grant. Removing direct INSERT/UPDATE/DELETE closes
-- whatever the RLS write policies might miss (e.g. a forged created_at,
-- which pinned a row to the top of "Recently added"), and TRUNCATE, which
-- RLS does not govern at all. The admin keeps direct UPDATE for one call:
-- apiSetConflictResolved in js/api/bookings.js (still RLS-gated to is_admin()).

-- 12.1 Tables and views: no direct access for app roles.
revoke insert, update, delete, truncate on public.bookings from public, anon;
revoke insert, delete, truncate on public.bookings from authenticated;
grant select on public.bookings to anon, authenticated;
grant update on public.bookings to authenticated;
revoke all on public.booking_audit_log from public, anon, authenticated;
revoke all on public.booking_idempotency from public, anon, authenticated;
revoke all on public.booking_rate_log from public, anon, authenticated;
revoke all on public.login_attempt_log from public, anon, authenticated;
revoke all on public.bookings_archive from public, anon, authenticated;
revoke all on public.bookings_all from public, anon, authenticated;
revoke all on public.room_utilisation_monthly from public, anon, authenticated;
revoke all on public.admin_session_activity from public, anon, authenticated;
-- The admin may read the audit trail (row access still limited by RLS).
grant select on public.booking_audit_log to authenticated;

-- 12.2 Internal functions: called only by triggers or by other functions in
-- this file (which run as the owner). No app role may call them.
revoke all on function public.client_ip()                                  from public, anon, authenticated;
revoke all on function public.base36_to_bigint(text)                       from public, anon, authenticated;
revoke all on function public.booking_end_ts(date, time, time, date)       from public, anon, authenticated;
revoke all on function public.booking_actor_key()                          from public, anon, authenticated;
revoke all on function public.audit_booking_change()                       from public, anon, authenticated;
revoke all on function public.audit_log_is_append_only()                   from public, anon, authenticated;
revoke all on function public.enforce_room_capacity()                      from public, anon, authenticated;
revoke all on function public.enforce_no_confirmed_overlap()               from public, anon, authenticated;
revoke all on function public.enforce_booking_rate_limit()                 from public, anon, authenticated;
revoke all on function public.is_admin_account()                           from public, anon, authenticated;
revoke all on function public.admin_idle_limit()                           from public, anon, authenticated;
revoke all on function public.jwt_session_id()                             from public, anon, authenticated;
revoke all on function public.revoke_admin_session(uuid)                   from public, anon, authenticated;

-- 12.3 is_admin(): evaluated by the admin RLS policies as the caller.
revoke all on function public.is_admin()                                   from public, anon, authenticated;
grant execute on function public.is_admin()                                to authenticated;

-- 12.4 Public functions (each enforces its own rules inside).
revoke all on function public.create_bookings_atomic(jsonb, text, boolean) from public, anon, authenticated;
revoke all on function public.cancel_own_booking(text, text)               from public, anon, authenticated;
revoke all on function public.release_own_booking(text, text, time, date)  from public, anon, authenticated;
revoke all on function public.bookings_change_marker()                     from public, anon, authenticated;
revoke all on function public.check_login_rate_limit()                     from public, anon, authenticated;
revoke all on function public.log_failed_login()                           from public, anon, authenticated;
grant execute on function public.create_bookings_atomic(jsonb, text, boolean) to anon, authenticated;
grant execute on function public.cancel_own_booking(text, text)               to anon, authenticated;
grant execute on function public.release_own_booking(text, text, time, date)  to anon, authenticated;
grant execute on function public.bookings_change_marker()                     to anon, authenticated;
grant execute on function public.check_login_rate_limit()                     to anon, authenticated;
grant execute on function public.log_failed_login()                           to anon, authenticated;

-- 12.5 Admin functions: authenticated only, and is_admin() checked inside.
revoke all on function public.update_booking_atomic(jsonb, boolean)                from public, anon, authenticated;
revoke all on function public.update_booking_statuses_atomic(text[], text, boolean) from public, anon, authenticated;
revoke all on function public.approve_bookings_atomic(jsonb)                       from public, anon, authenticated;
revoke all on function public.delete_bookings_atomic(text[])                       from public, anon, authenticated;
revoke all on function public.replace_booking_atomic(text, jsonb, text)            from public, anon, authenticated;
grant execute on function public.update_booking_atomic(jsonb, boolean)                to authenticated;
grant execute on function public.update_booking_statuses_atomic(text[], text, boolean) to authenticated;
grant execute on function public.approve_bookings_atomic(jsonb)                       to authenticated;
grant execute on function public.delete_bookings_atomic(text[])                       to authenticated;
grant execute on function public.replace_booking_atomic(text, jsonb, text)            to authenticated;
-- Session functions: authenticated only; each checks the admin account inside
-- and only ever acts on the caller's own session.
revoke all on function public.admin_heartbeat()                                    from public, anon, authenticated;
revoke all on function public.admin_end_session()                                  from public, anon, authenticated;
grant execute on function public.admin_heartbeat()                                    to authenticated;
grant execute on function public.admin_end_session()                                  to authenticated;

-- 12.6 Scheduled job only. It deletes from bookings and bypasses RLS.
revoke all on function public.archive_old_bookings(integer)                from public, anon, authenticated;
grant execute on function public.archive_old_bookings(integer)             to service_role;
revoke all on function public.expire_idle_admin_sessions()                 from public, anon, authenticated;
grant execute on function public.expire_idle_admin_sessions()              to service_role;


-- ============================================================================
-- 13. REALTIME AND API RELOAD
-- ============================================================================
-- bookings is in the Supabase realtime publication. The app does not
-- subscribe today (it uses the change marker in section 9); kept so realtime
-- can be adopted later without a database change.
do $$
begin
  if not exists (
    select 1 from pg_publication_tables
    where pubname = 'supabase_realtime'
      and schemaname = 'public'
      and tablename = 'bookings'
  ) then
    alter publication supabase_realtime add table public.bookings;
  end if;
end $$;

-- Make new and changed functions visible to the API immediately.
notify pgrst, 'reload schema';


-- ============================================================================
-- APPENDIX A — HEALTH CHECKS  (run any time; each should return zero rows
-- unless stated otherwise)
-- ============================================================================
--
-- A1. Every public table has RLS on:
--
--   select tablename from pg_tables
--   where schemaname = 'public' and rowsecurity = false;
--
-- A2. What anon can execute. Expect exactly six rows:
--     bookings_change_marker, cancel_own_booking, check_login_rate_limit,
--     create_bookings_atomic, log_failed_login, release_own_booking.
--
--   select p.proname
--   from pg_proc p join pg_namespace n on n.oid = p.pronamespace
--   where n.nspname = 'public' and has_function_privilege('anon', p.oid, 'execute')
--   order by 1;
--
-- A3. Every SECURITY DEFINER function pins its search_path including pg_temp
--     (without pg_temp, a caller's temporary table could shadow a real one):
--
--   select p.proname, p.proconfig
--   from pg_proc p join pg_namespace n on n.oid = p.pronamespace
--   where n.nspname = 'public' and p.prosecdef
--     and not coalesce(array_to_string(p.proconfig, ',') like '%pg_temp%', false);
--
-- A4. No admin policy is unconditional:
--
--   select policyname, cmd, qual, with_check from pg_policies
--   where schemaname = 'public' and tablename = 'bookings'
--     and policyname like 'Admins%'
--     and (qual = 'true' or with_check = 'true');
--
-- A5. bookings and bookings_archive have identical columns (name, position,
--     type AND nullability), or archive_old_bookings() fails:
--
--   select coalesce(b.column_name, a.column_name) as column_name,
--          b.ordinal_position as in_bookings, a.ordinal_position as in_archive,
--          b.is_nullable as null_live, a.is_nullable as null_arch
--   from      (select column_name, ordinal_position, data_type, is_nullable
--              from information_schema.columns
--              where table_schema='public' and table_name='bookings') b
--   full join (select column_name, ordinal_position, data_type, is_nullable
--              from information_schema.columns
--              where table_schema='public' and table_name='bookings_archive') a
--          on a.column_name = b.column_name
--   where a.column_name is null or b.column_name is null
--      or b.ordinal_position <> a.ordinal_position
--      or b.data_type   <> a.data_type
--      or b.is_nullable <> a.is_nullable;
--
-- A6. No view is granted to the app's roles:
--
--   select c.relname, g.grantee, g.privilege_type
--   from pg_class c
--   join pg_namespace n on n.oid = c.relnamespace
--   join information_schema.role_table_grants g
--     on g.table_schema = n.nspname and g.table_name = c.relname
--   where n.nspname = 'public' and c.relkind = 'v'
--     and g.grantee in ('anon','authenticated','PUBLIC');
--
-- A7. Every view uses security_invoker (anything listed without it bypasses RLS):
--
--   select c.relname, c.reloptions from pg_class c
--   join pg_namespace n on n.oid = c.relnamespace
--   where n.nspname = 'public' and c.relkind = 'v';
--
-- A9. Admin sessions (expect your current session with a recent last_seen;
--     stale rows should have revoked_at set if the Appendix B job runs):
--   select session_id, last_seen, revoked_at,
--          now() - last_seen as idle_for
--     from public.admin_session_activity
--    order by last_seen desc limit 10;
--
-- A8. Latest booking activity (expect rows — this is the audit trail):
--
--   select occurred_at, action, booking_id, actor_role, actor_email, client_ip,
--          old_row ->> 'status' as old_status, new_row ->> 'status' as new_status
--   from public.booking_audit_log
--   order by occurred_at desc
--   limit 100;


-- ============================================================================
-- APPENDIX B — SCHEDULED JOB  (pg_cron; not created by this file)
-- ============================================================================
-- Kept out of this file so re-running it never reschedules infrastructure.
--
--   Job name : archive-old-bookings-daily
--   Schedule : 30 21 * * *   (21:30 UTC = 03:00 IST)
--   Command  : select public.archive_old_bookings(90)
--
-- Effect: bookings more than 90 days past (except Pending) move to
-- bookings_archive, so the app shows a rolling ~90-day window. Older data is
-- in the reporting views. Unanswered Pending requests are never archived —
-- auto-rejecting someone's request is a policy decision, not a cron job's.
--
-- Create (once):
--   select cron.schedule('archive-old-bookings-daily', '30 21 * * *',
--                        'select public.archive_old_bookings(90)');
-- Health:
--   select jobname, schedule, active from cron.job;
--   select status, return_message, start_time from cron.job_run_details
--   where jobid = (select jobid from cron.job where jobname = 'archive-old-bookings-daily')
--   order by start_time desc limit 5;
-- Remove:
--   select cron.unschedule('archive-old-bookings-daily');
--
-- OPTIONAL second job — revoke abandoned admin sessions (section 10b):
--   Job name : expire-idle-admin-sessions
--   Schedule : */5 * * * *   (every 5 minutes)
--   Command  : select public.expire_idle_admin_sessions()
-- Without it the timeout is still enforced (is_admin() refuses idle
-- sessions); this only deletes their refresh tokens sooner.
--   select cron.schedule('expire-idle-admin-sessions', '*/5 * * * *',
--                        'select public.expire_idle_admin_sessions()');


-- ============================================================================
-- APPENDIX C — MAINTENANCE  (optional, run by hand)
-- ============================================================================
--
-- C1. Apply the section 3 booking rules to OLD rows as well.
--     Step 1 — list rows that break them (expect zero rows):
--
--   select booking_id, booked_by, booking_date, start_time, end_time, end_date, status
--   from public.bookings
--   where length(btrim(booked_by)) < 1
--      or (conflict_note is not null and char_length(conflict_note) > 500)
--      or end_date is null
--      or end_date not between booking_date and booking_date + 1
--      or (end_date + end_time) <= (booking_date + start_time)
--      or (end_date + end_time) >  (booking_date + start_time + interval '24 hours');
--
--     Rows listed here cannot be edited or approved until corrected (every
--     UPDATE is checked against the rules). Fix or delete them, then:
--
--     Step 2:
--   alter table public.bookings validate constraint bookings_booked_by_nonblank;
--   alter table public.bookings validate constraint bookings_conflict_note_length;
--   alter table public.bookings validate constraint bookings_end_date_valid;
--   alter table public.bookings validate constraint bookings_positive_duration;
--   alter table public.bookings validate constraint bookings_max_duration;
--
-- C2. Backfill created_at from booking ids (one-off; rewrites the column).
--     App ids are 'b' + creation time in base 36 (8 chars) + 12 random chars.
--     Legacy ids also start with 'b' but decode to 2055-2059, so the result
--     is range-checked, not just pattern-matched.
--
--   alter table public.bookings alter column created_at drop default;
--   update public.bookings set created_at = null where created_at is not null;
--   update public.bookings
--   set created_at = to_timestamp(
--         public.base36_to_bigint(substring(booking_id from 2 for 8)) / 1000.0)
--   where booking_id ~ '^b[0-9a-z]{8}'
--     and public.base36_to_bigint(substring(booking_id from 2 for 8))
--         between 1704067200000
--             and (extract(epoch from now()) * 1000)::bigint + 86400000;
--   alter table public.bookings alter column created_at set default now();
--
-- NOT MANAGED HERE: public.rls_auto_enable(), an event trigger that turns RLS
-- on for any new public table. It needs superuser, so it cannot live in this
-- file. Leave it in place — it is the safety net for future tables.


-- ============================================================================
-- APPENDIX D — ACCEPTED TRADE-OFFS  (decided, not oversights)
-- ============================================================================
-- D1. Booker names, purposes and times of Pending/Confirmed bookings are
--     readable by anyone with the page (the public board shows them). Fine
--     for an intranet tool; never put confidential details in "purpose".
-- D2. Public cancel / release checks the typed name against booked_by, which
--     is visible on the board. Prevents accidents, not deliberate misuse.
--     Mitigated by the audit trail (who, when, IP) and Teams notifications.
--     A real fix would be a per-booking secret token issued at creation.
-- D3. Rate limits key on client IP from request headers; a determined user
--     can vary them. They stop floods and accidents, not a targeted attack.


-- ============================================================================
-- APPENDIX E — SELF-TEST
-- ============================================================================
-- Proves sections 3-9 work on THIS database. Run after this file:
--   copy everything between the BEGIN and END lines below into a NEW query
--   (without the /* and */ lines) and Run.
--
-- It ALWAYS ends with an error, on purpose — ending with an error is what
-- rolls back every test row. Read the message:
--   "SELFTEST PASSED: 25 checks ..."  -> everything works.
--   "SELFTEST FAILED [Tn]: ..."       -> that check failed.
-- Uses room 'vedvyas' ten years ahead, so real bookings are never touched.
/*
------------------------------- BEGIN SELF-TEST -------------------------------
do $$
declare
  c_admin  constant text := json_build_object(
             'role','authenticated',
             'email','shaunakmistry4@gmail.com',   -- must equal is_admin_account()
             'sub','00000000-0000-0000-0000-00000000a001',
             'session_id','00000000-0000-0000-0000-00000000a5e1')::text;
  c_sid    constant uuid := '00000000-0000-0000-0000-00000000a5e1';
  c_anon   constant text := json_build_object('role','anon')::text;
  d        date := current_date + 3650;
  v_pass   integer := 0;
  v_res    jsonb;
  v_n      integer;
  v_status text;
  v_end    time;
begin
  -- Active session record for the test admin (rolled back at the end).
  insert into public.admin_session_activity (session_id, last_seen)
  values (c_sid, now())
  on conflict (session_id) do update set last_seen = now(), revoked_at = null;

  -- T0 ---------------------------------------------------------------
  perform set_config('request.jwt.claims', c_admin, true);
  if not public.is_admin() then
    raise exception 'SELFTEST FAILED [T0]: the admin email in this test does not match public.is_admin(). Edit c_admin above.' using errcode='ZZ001';
  end if;
  v_pass := v_pass + 1;

  -- T1 admin creates Confirmed A 10:00-11:00 ------------------------
  v_res := public.create_bookings_atomic(jsonb_build_array(jsonb_build_object(
    'booking_id','zzstA','room','vedvyas','booked_by','Selftest A','purpose','t',
    'booking_date',d,'start_time','10:00','end_time','11:00','attendees',5,
    'status','Confirmed','end_date',d)), 'selftest-key-0000001', false);
  if (v_res->>'created')::int <> 1 then
    raise exception 'SELFTEST FAILED [T1]: admin create returned %', v_res using errcode='ZZ001';
  end if;
  v_pass := v_pass + 1;

  -- T2 overlapping Confirmed is refused -----------------------------
  begin
    perform public.create_bookings_atomic(jsonb_build_array(jsonb_build_object(
      'booking_id','zzstB','room','vedvyas','booked_by','Selftest B',
      'booking_date',d,'start_time','10:30','end_time','11:30',
      'status','Confirmed','end_date',d)), 'selftest-key-0000002', false);
    raise exception 'SELFTEST FAILED [T2]: an overlapping Confirmed booking was accepted' using errcode='ZZ001';
  exception when sqlstate '23P01' then v_pass := v_pass + 1;
  end;

  -- T3 admin override allows it, and the override flag is reset ----
  perform public.create_bookings_atomic(jsonb_build_array(jsonb_build_object(
    'booking_id','zzstB','room','vedvyas','booked_by','Selftest B',
    'booking_date',d,'start_time','10:30','end_time','11:30',
    'status','Confirmed','end_date',d)), 'selftest-key-0000003', true);
  if coalesce(current_setting('app.allow_booking_conflict', true),'off') <> 'off' then
    raise exception 'SELFTEST FAILED [T3]: override flag left on after the RPC' using errcode='ZZ001';
  end if;
  v_pass := v_pass + 1;

  -- T4 public Pending request in an occupied slot is accepted -------
  perform set_config('request.jwt.claims', c_anon, true);
  perform public.create_bookings_atomic(jsonb_build_array(jsonb_build_object(
    'booking_id','zzstP','room','vedvyas','booked_by','Selftest P',
    'booking_date',d,'start_time','10:00','end_time','11:00','attendees',3,
    'status','Pending','end_date',d)), 'selftest-key-0000004', false);
  select status into v_status from public.bookings where booking_id='zzstP';
  if v_status is distinct from 'Pending' then
    raise exception 'SELFTEST FAILED [T4]: public request status is %', v_status using errcode='ZZ001';
  end if;
  v_pass := v_pass + 1;

  -- T5 public cannot create Confirmed ------------------------------
  begin
    perform public.create_bookings_atomic(jsonb_build_array(jsonb_build_object(
      'booking_id','zzstX1','room','vedvyas','booked_by','X',
      'booking_date',d,'start_time','18:00','end_time','19:00',
      'status','Confirmed','end_date',d)), 'selftest-key-0000005', false);
    raise exception 'SELFTEST FAILED [T5]: public created a Confirmed booking' using errcode='ZZ001';
  exception when sqlstate '42501' then v_pass := v_pass + 1;
  end;

  -- T6 public cannot backdate --------------------------------------
  begin
    perform public.create_bookings_atomic(jsonb_build_array(jsonb_build_object(
      'booking_id','zzstX2','room','vedvyas','booked_by','X',
      'booking_date',current_date - 2,'start_time','18:00','end_time','19:00',
      'status','Pending','end_date',current_date - 2)), 'selftest-key-0000006', false);
    raise exception 'SELFTEST FAILED [T6]: public created a past-dated booking' using errcode='ZZ001';
  exception when sqlstate '22023' then v_pass := v_pass + 1;
  end;

  -- T7 same request key twice = created once -----------------------
  v_res := public.create_bookings_atomic(jsonb_build_array(jsonb_build_object(
    'booking_id','zzstP2','room','vedvyas','booked_by','Selftest P',
    'booking_date',d,'start_time','10:00','end_time','11:00',
    'status','Pending','end_date',d)), 'selftest-key-0000004', false);
  select count(*) into v_n from public.bookings where booking_id in ('zzstP','zzstP2');
  if v_n <> 1 or coalesce((v_res->>'duplicate')::boolean,false) is not true then
    raise exception 'SELFTEST FAILED [T7]: duplicate key created rows again (%), response %', v_n, v_res using errcode='ZZ001';
  end if;
  v_pass := v_pass + 1;

  -- T8 public cannot call admin RPCs -------------------------------
  begin
    perform public.update_booking_statuses_atomic(array['zzstP'], 'Confirmed', false);
    raise exception 'SELFTEST FAILED [T8]: public changed a status via admin RPC' using errcode='ZZ001';
  exception when sqlstate '42501' then v_pass := v_pass + 1;
  end;

  -- T9 approving P (clashes with A) is refused, P stays Pending -----
  perform set_config('request.jwt.claims', c_admin, true);
  begin
    perform public.update_booking_statuses_atomic(array['zzstP'], 'Confirmed', false);
    raise exception 'SELFTEST FAILED [T9]: approval into an occupied slot was accepted' using errcode='ZZ001';
  exception when sqlstate '23P01' then v_pass := v_pass + 1;
  end;
  select status into v_status from public.bookings where booking_id='zzstP';
  if v_status <> 'Pending' then
    raise exception 'SELFTEST FAILED [T9b]: refused approval still changed status to %', v_status using errcode='ZZ001';
  end if;

  -- T10 approve-anyway via approve_bookings_atomic -----------------
  perform public.approve_bookings_atomic(jsonb_build_array(
    jsonb_build_object('booking_id','zzstP','room',null,'override',true)));
  select status into v_status from public.bookings where booking_id='zzstP';
  if v_status <> 'Confirmed'
     or coalesce(current_setting('app.allow_booking_conflict', true),'off') <> 'off' then
    raise exception 'SELFTEST FAILED [T10]: approve-anyway status % / flag not reset', v_status using errcode='ZZ001';
  end if;
  v_pass := v_pass + 1;

  -- T11 batch is all-or-nothing ------------------------------------
  begin
    perform public.create_bookings_atomic(jsonb_build_array(
      jsonb_build_object('booking_id','zzstC1','room','vedvyas','booked_by','C',
        'booking_date',d,'start_time','14:00','end_time','15:00','status','Confirmed','end_date',d),
      jsonb_build_object('booking_id','zzstC2','room','vedvyas','booked_by','C',
        'booking_date',d,'start_time','10:15','end_time','10:45','status','Confirmed','end_date',d)),
      'selftest-key-0000011', false);
    raise exception 'SELFTEST FAILED [T11]: conflicting batch was accepted' using errcode='ZZ001';
  exception when sqlstate '23P01' then null;
  end;
  if exists (select 1 from public.bookings where booking_id='zzstC1') then
    raise exception 'SELFTEST FAILED [T11]: half of a failed batch was saved' using errcode='ZZ001';
  end if;
  v_pass := v_pass + 1;

  -- T12 admin release-early of a shared (overlapping) booking works -
  perform public.update_booking_atomic(jsonb_build_object(
    'booking_id','zzstA','room','vedvyas','booked_by','Selftest A','purpose','t',
    'booking_date',d,'start_time','10:00','end_time','10:45','attendees',5,
    'status','Confirmed','end_date',d), false);
  select end_time into v_end from public.bookings where booking_id='zzstA';
  if v_end <> '10:45' then
    raise exception 'SELFTEST FAILED [T12]: release-early did not shorten (end %)', v_end using errcode='ZZ001';
  end if;
  v_pass := v_pass + 1;

  -- T13 public release of a shared booking works -------------------
  perform set_config('request.jwt.claims', c_anon, true);
  v_res := public.release_own_booking('zzstB', 'selftest b', '11:00', d)::jsonb;
  if coalesce((v_res->>'ok')::boolean,false) is not true then
    raise exception 'SELFTEST FAILED [T13]: public release failed: %', v_res using errcode='ZZ001';
  end if;
  v_pass := v_pass + 1;

  -- T14 public cancel of an admin-overbooked booking works ---------
  perform set_config('request.jwt.claims', c_admin, true);
  perform public.create_bookings_atomic(jsonb_build_array(jsonb_build_object(
    'booking_id','zzstO','room','vedvyas','booked_by','Selftest O',
    'booking_date',d,'start_time','20:00','end_time','21:00','attendees',40,
    'status','Confirmed','end_date',d)), 'selftest-key-0000014', false);
  perform set_config('request.jwt.claims', c_anon, true);
  v_res := public.cancel_own_booking('zzstO', 'Selftest O')::jsonb;
  if coalesce((v_res->>'ok')::boolean,false) is not true then
    raise exception 'SELFTEST FAILED [T14]: cancelling an overbooked booking failed: %', v_res using errcode='ZZ001';
  end if;
  v_pass := v_pass + 1;

  -- T15 public capacity is still enforced --------------------------
  begin
    perform public.create_bookings_atomic(jsonb_build_array(jsonb_build_object(
      'booking_id','zzstX3','room','vedvyas','booked_by','X',
      'booking_date',d,'start_time','18:00','end_time','19:00','attendees',31,
      'status','Pending','end_date',d)), 'selftest-key-0000015', false);
    raise exception 'SELFTEST FAILED [T15]: public request exceeded room capacity' using errcode='ZZ001';
  exception
    when sqlstate 'ZZ001' then raise;
    when others then
      if sqlerrm not like '%holds up to%' then
        raise exception 'SELFTEST FAILED [T15]: unexpected error %', sqlerrm using errcode='ZZ001';
      end if;
      v_pass := v_pass + 1;
  end;

  -- T16 overnight booking with a wrong end_date is refused ----------
  perform set_config('request.jwt.claims', c_admin, true);
  begin
    perform public.create_bookings_atomic(jsonb_build_array(jsonb_build_object(
      'booking_id','zzstX4','room','vedvyas','booked_by','X',
      'booking_date',d + 3,'start_time','22:00','end_time','01:00',
      'status','Confirmed','end_date',d + 3)), 'selftest-key-0000016', false);
    raise exception 'SELFTEST FAILED [T16]: invalid end_date accepted' using errcode='ZZ001';
  exception when sqlstate '23514' then v_pass := v_pass + 1;
  end;

  -- T17 blank name refused -----------------------------------------
  begin
    perform public.create_bookings_atomic(jsonb_build_array(jsonb_build_object(
      'booking_id','zzstX5','room','vedvyas','booked_by','   ',
      'booking_date',d + 3,'start_time','09:00','end_time','10:00',
      'status','Confirmed','end_date',d + 3)), 'selftest-key-0000017', false);
    raise exception 'SELFTEST FAILED [T17]: blank name accepted' using errcode='ZZ001';
  exception when sqlstate '23514' then v_pass := v_pass + 1;
  end;

  -- T18 recurring replace: same slot reused, original removed ------
  perform public.create_bookings_atomic(jsonb_build_array(jsonb_build_object(
    'booking_id','zzstR','room','vedvyas','booked_by','Selftest R',
    'booking_date',d + 5,'start_time','16:00','end_time','17:00',
    'status','Confirmed','end_date',d + 5)), 'selftest-key-0000018', false);
  perform public.replace_booking_atomic('zzstR', jsonb_build_array(
    jsonb_build_object('booking_id','zzstR1','room','vedvyas','booked_by','Selftest R',
      'booking_date',d + 5,'start_time','16:00','end_time','17:00','status','Confirmed','end_date',d + 5),
    jsonb_build_object('booking_id','zzstR2','room','vedvyas','booked_by','Selftest R',
      'booking_date',d + 6,'start_time','16:00','end_time','17:00','status','Confirmed','end_date',d + 6)),
    'selftest-key-0000019');
  if exists (select 1 from public.bookings where booking_id='zzstR')
     or (select count(*) from public.bookings where booking_id in ('zzstR1','zzstR2')) <> 2 then
    raise exception 'SELFTEST FAILED [T18]: recurring replace result is wrong' using errcode='ZZ001';
  end if;
  v_pass := v_pass + 1;

  -- T19 bulk delete with a missing id changes nothing --------------
  begin
    perform public.delete_bookings_atomic(array['zzstR1','zzst-does-not-exist']);
    raise exception 'SELFTEST FAILED [T19]: delete with a missing id succeeded' using errcode='ZZ001';
  exception when sqlstate 'P0002' then null;
  end;
  if not exists (select 1 from public.bookings where booking_id='zzstR1') then
    raise exception 'SELFTEST FAILED [T19]: failed bulk delete still removed a row' using errcode='ZZ001';
  end if;
  v_pass := v_pass + 1;

  -- T20 audit trail recorded the changes ---------------------------
  select count(*) into v_n from public.booking_audit_log
   where booking_id in ('zzstA','zzstB','zzstP','zzstO','zzstR');
  -- A: insert+update, B: insert+update, P: insert+update, O: insert+update, R: insert+delete
  if v_n < 10 then
    raise exception 'SELFTEST FAILED [T20]: expected >= 10 audit rows, found %', v_n using errcode='ZZ001';
  end if;
  if not exists (select 1 from public.booking_audit_log
                  where booking_id='zzstO' and action='UPDATE' and actor_role='anon'
                    and new_row->>'status'='Cancelled') then
    raise exception 'SELFTEST FAILED [T20]: public cancellation not attributed in audit' using errcode='ZZ001';
  end if;
  v_pass := v_pass + 1;

  -- T21 audit rows cannot be altered -------------------------------
  begin
    delete from public.booking_audit_log where booking_id = 'zzstA';
    raise exception 'SELFTEST FAILED [T21]: audit row was deletable' using errcode='ZZ001';
  exception when sqlstate '42501' then v_pass := v_pass + 1;
  end;

  -- T22 change marker moves on every booking change, readable by anon --
  perform set_config('request.jwt.claims', c_anon, true);
  v_res := public.bookings_change_marker();
  perform set_config('request.jwt.claims', c_admin, true);
  perform public.update_booking_statuses_atomic(array['zzstR1'], 'Cancelled', false);
  if public.bookings_change_marker() = v_res then
    raise exception 'SELFTEST FAILED [T22]: change marker did not move after a change' using errcode='ZZ001';
  end if;
  v_pass := v_pass + 1;

  -- T23 server-side idle timeout: a session idle past the limit is not admin --
  perform set_config('request.jwt.claims', c_admin, true);
  update public.admin_session_activity
     set last_seen = now() - public.admin_idle_limit() - interval '1 minute'
   where session_id = c_sid;
  if public.is_admin() then
    raise exception 'SELFTEST FAILED [T23]: idle admin session still treated as admin' using errcode='ZZ001';
  end if;
  begin
    perform public.update_booking_statuses_atomic(array['zzstR1'], 'Confirmed', false);
    raise exception 'SELFTEST FAILED [T23]: idle admin session could still write' using errcode='ZZ001';
  exception when sqlstate '42501' then null;
  end;
  v_pass := v_pass + 1;

  -- T24 heartbeat cannot revive a stale session; it revokes it ------------
  v_res := public.admin_heartbeat();
  if coalesce((v_res ->> 'ok')::boolean, true)
     or (select revoked_at from public.admin_session_activity where session_id = c_sid) is null then
    raise exception 'SELFTEST FAILED [T24]: heartbeat revived or did not revoke a stale session: %', v_res using errcode='ZZ001';
  end if;
  v_pass := v_pass + 1;

  raise exception 'SELFTEST PASSED: % checks. All test data has been rolled back.', v_pass
    using errcode = 'ZZ000';
end $$;
-------------------------------- END SELF-TEST --------------------------------
*/
