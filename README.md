# StressMap — Exam Stress Check-In

A full-stack web app (frontend + backend) for a quiet, quiz-style stress check-in for NEET/JEE/UPSC aspirants, with real user accounts and saved history.

## What's inside
- **Frontend** — `public/index.html`: login/register, the 25-question check-in, and the result report card (radar chart, category marksheet, tips, YouTube suggestions).
- **Backend** — `server.js`: a plain Node.js server (no Express, no npm packages at all) with:
  - `POST /api/register` — name, mobile number, password
  - `POST /api/login` — name, password
  - `POST /api/logout`
  - `GET  /api/me` — current logged-in user
  - `POST /api/results` — save a completed check-in
  - `GET  /api/results` — fetch the logged-in user's past check-ins
- **Database** — SQLite, using Node's own built-in `node:sqlite` module. A file called `stressmap.db` is created automatically the first time you run the server — no separate database install needed.

## Requirements
- Node.js **v22.5 or newer** (needed for the built-in SQLite support). Check with:
  ```
  node --version
  ```

## Run it
No `npm install` is required — everything uses only Node's built-in modules.

```
node server.js
```

Then open **http://localhost:3000** in your browser.

To use a different port:
```
PORT=5000 node server.js
```

## How login/register works
- **Register** asks for name, 10-digit mobile number, and a password (min. 6 characters).
- **Login** asks for name and password only (as requested).
- Because login is by name, each name must be unique across the app — if a name is taken, registration will ask for a slightly different one.
- Passwords are never stored in plain text — they're hashed with Node's built-in `scrypt` (salted, one-way hash) before being saved.
- Sessions use a random token stored in an HTTP-only cookie (7-day expiry), checked against a `sessions` table in the database — not a JWT, but equally secure for this use case since the token never leaves the server unreadable.

## Before you put this on the public internet
This is a genuinely working backend, not a demo/mock, but a few things are worth doing before real users rely on it in production:
1. Serve it over **HTTPS** and add the `Secure` flag to the session cookie (in `setSessionCookie` in `server.js`).
2. Add basic **rate limiting** on `/api/login` and `/api/register` to slow down brute-force attempts.
3. Back up `stressmap.db` regularly, or move to a managed database if you expect heavy concurrent traffic (SQLite is great up to a moderate scale, but a single file has limits).
4. Consider adding a "forgot password" flow, since there's currently no email/SMS integration for password resets.

## Customizing
- Colors and fonts are all defined as CSS variables at the top of `public/index.html`.
- The 25 questions, categories, and tips live near the top of the `<script>` block in the same file — edit the `categories` and `catMeta` objects to change wording, scoring, or advice.
