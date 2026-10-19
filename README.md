A lightweight, room booking system for managing training and conference rooms.

## Admin session

- The admin is signed out after **10 minutes without activity** (clicks, keys, scroll, mouse movement, touch), with a warning 2 minutes before. Activity in any open tab counts for all tabs.
- **Enforced by the server, not only the browser.** The browser reports real activity at most once a minute (`admin_heartbeat`). The database refuses every admin action from a session it has not heard from within 12 minutes (10 + 2 minutes' grace), even if the browser is bypassed or the sign-in token is copied elsewhere. See `supabase/schema.sql` section 10b.
- Logging out or timing out ends the session at the server immediately and signs out **this browser only**. Other PCs using the admin account stay signed in.
- To change the timeout: edit `ADMIN_IDLE_TIMEOUT_MIN` in `js/config.js` **and** `admin_idle_limit()` in `supabase/schema.sql` (must be the config value + 2). `node scripts/verify.mjs` fails if they disagree.

## Deploying a release

1. **Database first.** Supabase → SQL Editor → paste the whole `supabase/schema.sql` → Run. Safe to re-run; no data is deleted.
2. Optional: run the self-test in Appendix E of `schema.sql` (expect `SELFTEST PASSED`).
3. Then publish the site files. Doing this the other way round leaves the new site calling database functions that do not exist yet, and the admin cannot log in.
4. `node scripts/verify.mjs` — every check must pass.
