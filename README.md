# CAS

A small, self-hosted Centralized Authentication Service. Client applications
redirect users here to sign in with Google or Microsoft, and get back a
short-lived RS256 JWT they can verify locally (via JWKS) or by calling this
server.

## Setup

```bash
npm install
cp .env.example .env   # then fill in the values below
node index.js
```

### Environment variables (`.env`)

| Variable | Required | Description |
|---|---|---|
| `PORT` | no (default `80`) | Port the server listens on |
| `NODE_ENV` | no (default `development`) | `production` enforces HTTPS redirect URIs (except `localhost`) |
| `AUTH_BASE_URL` | no (default `http://localhost:${PORT}`) | Public base URL used to build OAuth callback URLs |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | to enable Google login | From the [Google Cloud Console](https://console.cloud.google.com/apis/credentials) |
| `MS_CLIENT_ID` / `MS_CLIENT_SECRET` | to enable Microsoft login | From the [Azure Portal](https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps) |
| `SSO` | no (default `false`) | When `true`, a valid session cookie lets a user skip re-authentication on subsequent logins. Off by default — every login goes through the provider. |

Google/Microsoft OAuth redirect URIs should point at:
`${AUTH_BASE_URL}/auth/callback/google` and `${AUTH_BASE_URL}/auth/callback/microsoft`.

### Registering client apps (`clients.json`)

Any app that wants to use this server must be listed in `clients.json`, with
the exact redirect URIs it's allowed to use:

```json
[
  {
    "id": "app1",
    "name": "My Application (Dev)",
    "allowedRedirects": [
      "http://localhost:3001/auth/callback"
    ]
  }
]
```

Redirect URIs are matched exactly (no prefix/wildcard matching), and must be
HTTPS in production (localhost excepted).

## How a client app integrates

1. Redirect the browser to `/auth/google` or `/auth/microsoft` with
   `client_id` and `redirect_uri` query params.
2. The user authenticates with the provider, then is redirected back to your
   `redirect_uri` with a `?token=...` JWT.
3. Verify the token either:
   - **Locally**, using the public key from `/auth/jwks.json` (no network
     round-trip per request), or
   - **Server-to-server**, by `POST`ing `{ token }` to `/auth/verify`.
4. To sign a user out, send them to `/auth/logout` (optionally with
   `client_id` + `redirect_uri` to redirect afterward).

`public/api.js` has small helper functions (`googleOAuth`, `microsoftOAuth`,
`verifyAuthToken`, `request`) for driving this flow from a browser.

## Endpoints

Visit `/endpoints/html` on a running server for a live, auto-generated list
of every registered route (built from `tools/listEndpoints.js`).

## RSA keys

`auth_private.pem` / `auth_public.pem` sign and verify the issued JWTs. If
they don't exist, the server generates and saves a new keypair on startup —
see `auth/keys.js`. In production, generate these ahead of time and manage
them outside of source control.
