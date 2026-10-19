-- ============================================================
-- Self-test for schema.sql section 14 (audit, atomic RPCs, conflicts,
-- constraints). Run AFTER schema.sql, in Supabase -> SQL Editor.
--
-- HOW TO READ THE RESULT
--   It ALWAYS ends with an error on purpose, because ending with an error is
--   what guarantees every test row is rolled back. Read the message:
--
--     "SELFTEST PASSED: 22 checks ..."   -> everything works.
--     "SELFTEST FAILED [Tn]: ..."        -> that check failed; send it to me.
--     any other error                    -> send the full message.
--
-- Uses room 'vedvyas' about 10 years in the future, so it cannot touch real
-- bookings. Nothing is committed under any outcome.
-- ============================================================
do $$
declare
  c_admin  constant text := json_build_object(
             'role','authenticated',
             'email','shaunakmistry4@gmail.com',   -- must equal is_admin()
             'sub','00000000-0000-0000-0000-00000000a001')::text;
  c_anon   constant text := json_build_object('role','anon')::text;
  d        date := current_date + 3650;
  v_pass   integer := 0;
  v_res    jsonb;
  v_n      integer;
  v_status text;
  v_end    time;
begin
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

  raise exception 'SELFTEST PASSED: % checks. All test data has been rolled back.', v_pass
    using errcode = 'ZZ000';
end $$;
