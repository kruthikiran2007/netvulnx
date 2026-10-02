# AUTHENTICATION.md — Accounts, sessions, and the audit log

Milestone 8. NetVulnX now has real authentication: the app is no longer
open to anyone who can reach the URL.

## First run: creating the admin account

1. Start the app (`python run.py`) and open http://127.0.0.1:5000.
2. With no accounts in the database, every page redirects to **/setup**.
3. Choose a username (3–40 chars, letters/digits/`_`/`-`) and a password
   (minimum 8 characters). This becomes the **admin** account.
4. `/setup` disappears forever once an account exists — re-visiting it
   redirects to the login page, and POSTing to it returns 403.

## Logging in and out

- **/login** — username + password. Wrong credentials return 401 with the
  same message whether the username exists or not (no user enumeration).
- After login you're sent back to the page you originally requested
  (`?next=...`, validated to stay inside the app — no open redirects).
- **Log out** is a POST (CSRF-protected), in the top nav next to your
  username. Admins also see an **Audit** link.

## How passwords are stored

Only a **salted hash** is kept (`werkzeug.security.generate_password_hash`,
scrypt-based). Properties this gives you:

- Two users with the same password get different hashes (unique salt).
- There is no way to recover a password from the hash — login just tests
  a guess against it with `check_password_hash`.
- Nothing in the database, logs, or audit trail ever contains a plaintext
  password.

## Sessions

A successful login stores only the user's id in Flask's signed session
cookie (already `HttpOnly` + `SameSite=Lax` since Milestone 7). Each
request loads the user from the database, so deleting the account (or the
database) ends the session immediately.

## The audit log

Security-relevant actions append to the `audit_events` table — actor,
action, detail, timestamp, IP. The app never edits or deletes these rows.
Recorded events:

| action | when |
|---|---|
| `user.created` | first admin account created |
| `login.ok` / `login.failed` | login attempts (failed ones log the attempted username) |
| `logout` | logout |
| `scan.created` | scan submitted |
| `scan.authorized` / `scan.cancelled` | authorization gate decision |
| `finding.triaged` | finding status changed |

Admins view the latest 200 events at **/audit** (non-admins get 403).

## Production checklist

Authentication is necessary but not sufficient for exposing the app.
Before it leaves your machine:

- [ ] Set `NETVULNX_SECRET_KEY` to a long random value (the app warns
      loudly when the dev fallback is in use).
- [ ] Serve behind HTTPS (reverse proxy) and set
      `SESSION_COOKIE_SECURE=True` — the local dev server has no TLS, so
      this stays off by default; see SECURITY.md.
- [ ] Keep `host="127.0.0.1"` in run.py unless you mean to share the app
      on your network — and then only with accounts you created.
- [ ] Back up `netvulnx.db` — it now holds accounts and the audit trail.

## What's still ahead

- Password reset / change flows (today: recreate the account).
- Roles beyond admin/regular (viewer, operator) — Phase 3.
- Brute-force throttling on /login (rate limiting) — recommended next.
- See ROADMAP.md for the full plan.
