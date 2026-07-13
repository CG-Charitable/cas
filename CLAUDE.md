# CLAUDE.md

Guidance for Claude Code when working in this repo.

## What this is

CAS is a standalone Centralized Authentication Service (single-sign-on
server). It is not itself a protected API — it's the thing other apps
redirect to in order to authenticate a user, then hand back a signed JWT.
There is no database; all state is either a signed cookie/JWT, an in-memory
Map, or a JSON file on disk.

## Runtime structure

- `index.js` — the entire server. One Express app, no route files/routers.
  Reading it top to bottom in order (config → keys → CSRF state → helpers →
  Google routes → Microsoft routes → logout → CORS → public key/verify
  endpoints) is the fastest way to understand the whole system.
- `auth/keys.js` — loads `auth_private.pem` / `auth_public.pem` from disk,
  generating a new RSA keypair on first run if they're missing. Also builds
  the JWKS representation served at `/auth/jwks.json`.
- `tools/listEndpoints.js` — introspects `app._router.stack` to list every
  registered route. Wired in via `exposeEndpoints(app)` at the bottom of
  `index.js`, exposing `/endpoints/html` and `/endpoints/json`.
- `public/` — static assets served directly by Express
  (`express.static`). `index.html` is the server's own landing page (not a
  client app); `api.js` is a small helper library client apps can copy for
  driving the OAuth redirect + token verification flow from a browser.
- `clients.json` — the registry of client apps allowed to use this server,
  keyed by `id`, each with an `allowedRedirects` allowlist. Loaded once at
  startup; there's no hot-reload or admin UI for editing it.
- `auth.json` — unrelated legacy/local file, gitignored, not read anywhere
  in `index.js`. Don't assume it's part of the auth flow.

## Auth flow (the part worth understanding before changing anything)

1. Client redirects the browser to `/auth/google` or `/auth/microsoft` with
   `client_id` + `redirect_uri`.
2. `initOAuth()` validates both against `clients.json` /
   `validateRedirectUri()`, generates a random `state` (stored in the
   in-memory `pendingStates` Map, single-use, 10 min TTL), and redirects to
   the provider.
3. Provider redirects back to `/auth/callback/{google,microsoft}` with a
   `code` + `state`. The state is consumed (checked once, then deleted) as
   CSRF protection.
4. On success, the server:
   - sets an httpOnly `cas_session` cookie (a long-lived RS256 JWT — this is
     what "remembers" the user across future logins), and
   - redirects the browser back to the client's `redirect_uri` with a
     short-lived (`JWT_EXPIRY = 10m`) RS256 JWT in the `token` query param.
5. The client app verifies that token — either locally via
   `/auth/jwks.json`, or server-to-server via `POST /auth/verify`.

**SSO skip-through:** `initOAuth()` will skip the provider round-trip
entirely and immediately re-issue a token if the user already has a valid
`cas_session` cookie. This is gated behind `SSO_ENABLED` (`process.env.SSO
=== "true"`, default off) — see `index.js` around `SSO_ENABLED` and the
`if (SSO_ENABLED && req.query.prompt !== "login")` check in `initOAuth()`.
Treat this flag as security-relevant: it controls whether authentication can
be silently bypassed via cookie, so don't change its default without a
reason.

**Two JWTs, different lifetimes, same keypair:** the session cookie
(30 days) and the per-login token handed to clients (10 minutes) are both
signed with `auth_private.pem` — don't confuse them when tracing a bug;
`createJWT()` makes the short one, `setSessionCookie()` makes the long one.

## CORS

`/auth/jwks.json` is open to all origins (the public key isn't sensitive).
`/auth/verify` is restricted to origins derived from every client's
`allowedRedirects` in `clients.json` (see `ALLOWED_ORIGINS`). If a new client
needs to call `/auth/verify` cross-origin, it must be registered with a
matching redirect URI first — there's no separate CORS allowlist to edit.

## Conventions to follow when editing

- No router files, no framework beyond Express + a few middlewares — keep
  new routes in `index.js` unless the file genuinely outgrows that.
- Config is read from `process.env` at module load, with defaults inline
  (see the top of `index.js`). Follow that pattern for new flags rather than
  introducing a config file.
- Secrets/local files (`auth.json`, `auth_private.pem`, `auth_public.pem`,
  `.env`, `package-lock.json`) are gitignored — don't add secret-bearing
  files to git without confirming they belong.
- This repo was copied from a sibling project (`api-lib`) minus `.git` and
  `node_modules`; don't assume shared history with that repo's git log.
