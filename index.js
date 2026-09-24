require("dotenv").config({ quiet: true });

const express = require("express");
const path = require("path");
const crypto = require("crypto");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const { OAuth2Client } = require("google-auth-library");
const { sendEmail } = require("./tools/mail.js");
const { loadKeys, publicKeyToJwks } = require("./auth/keys.js");
const { expose: exposeEndpoints } = require("./tools/listEndpoints.js");

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const PORT = process.env.PORT || 80;
const NODE_ENV = process.env.NODE_ENV || "development";
const AUTH_BASE_URL =
  process.env.AUTH_BASE_URL || `http://localhost:${PORT}`;

// When enabled, a valid CAS session cookie lets a client skip the OAuth
// round-trip entirely and get a token re-issued silently. Off by default —
// every login must go through the provider unless explicitly turned on.
const SSO_ENABLED = process.env.SSO === "true";

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const MS_CLIENT_ID = process.env.MS_CLIENT_ID;
const MS_CLIENT_SECRET = process.env.MS_CLIENT_SECRET;

const GOOGLE_CALLBACK = `${AUTH_BASE_URL}/auth/callback/google`;
const MS_CALLBACK = `${AUTH_BASE_URL}/auth/callback/microsoft`;

const MS_AUTH_URL =
  "https://login.microsoftonline.com/common/oauth2/v2.0/authorize";
const MS_TOKEN_URL =
  "https://login.microsoftonline.com/common/oauth2/v2.0/token";
const MS_GRAPH_URL = "https://graph.microsoft.com/v1.0/me";

// Email one-time-code login. Codes are sent via tools/mail.js (Gmail, SMTP
// when EMAIL_TYPE=smtp, or local sendmail when EMAIL_TYPE=linux). If neither is configured, development mode
// logs the code to the console instead, and production disables email login.
const EMAIL_SENDING_CONFIGURED =
  process.env.EMAIL_TYPE === "linux" ||
  (process.env.EMAIL_TYPE === "smtp" &&
    !!(process.env.SMTP_USER && process.env.SMTP_PASS)) ||
  !!(process.env.GMAIL_USER && process.env.GMAIL_PASS);
const EMAIL_LOGIN_ENABLED =
  EMAIL_SENDING_CONFIGURED || NODE_ENV !== "production";

// No 0/O or 1/I/L — codes are typed by hand, so avoid look-alike characters.
const EMAIL_CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
const EMAIL_CODE_LENGTH = 6;
const EMAIL_CODE_TTL_MS = 10 * 60 * 1000;
const EMAIL_CODE_MAX_ATTEMPTS = 3;
const EMAIL_MAX_SENDS_PER_STATE = 3; // initial send + 2 resends
const EMAIL_RESEND_COOLDOWN_MS = 30 * 1000;
const EMAIL_MAX_SENDS_PER_HOUR = 10; // per address, across all login attempts

// JWT issued by this server expires quickly — client apps must establish their
// own session from the payload and should not store or forward this token.
const JWT_EXPIRY = "10m";

// CAS session cookie keeps the user's identity so they can skip the OAuth
// round-trip when they come back within the session window.
const SESSION_COOKIE = "cas_session";
const SESSION_EXPIRY_SECONDS = 30 * 24 * 60 * 60; // 30 days

// ---------------------------------------------------------------------------
// Load registered clients and RSA keys
// ---------------------------------------------------------------------------

let CLIENTS = [];
try {
  CLIENTS = require("./clients.json");
} catch {
  console.warn(
    "[AUTH] clients.json not found — no client apps are registered. " +
      "Create clients.json to allow OAuth logins."
  );
}

const { privateKey, publicKey } = loadKeys();
const JWKS = publicKeyToJwks(publicKey);

// ---------------------------------------------------------------------------
// Google OAuth client
// ---------------------------------------------------------------------------

const googleOAuthClient = new OAuth2Client(
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  GOOGLE_CALLBACK
);

// ---------------------------------------------------------------------------
// Express setup
// ---------------------------------------------------------------------------

const app = express();
app.use(cookieParser());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

// ---------------------------------------------------------------------------
// CSRF state store
// State is a 32-byte hex string tied to (redirect_uri, client_id, provider).
// States expire after 10 minutes and are consumed exactly once.
// ---------------------------------------------------------------------------

const pendingStates = new Map();

// Email login codes, keyed by the login's state. Only a SHA-256 hash of the
// code is kept. Entry: { email, codeHash, expires, attempts, sends, lastSent }.
const pendingEmailCodes = new Map();

// Recent send timestamps per email address, to stop one inbox being flooded
// by many parallel login attempts.
const emailSendLog = new Map();

setInterval(() => {
  const now = Date.now();
  for (const [key, val] of pendingStates) {
    if (now > val.expires) pendingStates.delete(key);
  }
  for (const [key, val] of pendingEmailCodes) {
    if (now > val.expires) pendingEmailCodes.delete(key);
  }
  for (const [key, times] of emailSendLog) {
    const recent = times.filter((t) => now - t < 60 * 60 * 1000);
    if (recent.length) emailSendLog.set(key, recent);
    else emailSendLog.delete(key);
  }
}, 5 * 60 * 1000);

function generateState(redirectUri, clientId, provider) {
  const state = crypto.randomBytes(32).toString("hex");
  pendingStates.set(state, {
    redirect_uri: redirectUri,
    client_id: clientId,
    provider,
    expires: Date.now() + 10 * 60 * 1000,
  });
  return state;
}

function consumeState(state) {
  const data = pendingStates.get(state);
  if (!data) return null;
  pendingStates.delete(state);
  if (Date.now() > data.expires) return null;
  return data;
}

// Like consumeState, but leaves the state in place — the email flow needs it
// across several requests (send code, resend, each verify attempt). It is
// consumed on successful login or when attempts run out.
function peekState(state, provider) {
  if (typeof state !== "string") return null;
  const data = pendingStates.get(state);
  if (!data || data.provider !== provider) return null;
  if (Date.now() > data.expires) {
    pendingStates.delete(state);
    return null;
  }
  return data;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function findClient(clientId) {
  return CLIENTS.find((c) => c.id === clientId) || null;
}

function validateRedirectUri(client, redirectUri) {
  // Exact string match only — no prefix matching, no wildcards.
  if (!client.allowedRedirects.includes(redirectUri)) return false;
  // In production, only allow HTTPS (except localhost for dev convenience).
  if (NODE_ENV === "production") {
    try {
      const url = new URL(redirectUri);
      if (url.protocol !== "https:" && url.hostname !== "localhost") {
        return false;
      }
    } catch {
      return false;
    }
  }
  return true;
}

function createJWT(userInfo) {
  return jwt.sign(userInfo, privateKey, {
    algorithm: "RS256",
    expiresIn: JWT_EXPIRY,
    issuer: "centralized-auth",
  });
}

function redirectWithToken(res, redirectUri, token) {
  const url = new URL(redirectUri);
  url.searchParams.set("token", token);
  res.redirect(url.toString());
}

function setSessionCookie(res, userInfo) {
  const token = jwt.sign(userInfo, privateKey, {
    algorithm: "RS256",
    expiresIn: SESSION_EXPIRY_SECONDS,
    issuer: "centralized-auth",
  });
  res.cookie(SESSION_COOKIE, token, {
    httpOnly: true,
    secure: NODE_ENV === "production",
    sameSite: "lax",
    maxAge: SESSION_EXPIRY_SECONDS * 1000,
  });
}

function getSessionUser(req) {
  const token = req.cookies?.[SESSION_COOKIE];
  if (!token) return null;
  try {
    const { iat, exp, iss, ...user } = jwt.verify(token, publicKey, {
      algorithms: ["RS256"],
      issuer: "centralized-auth",
    });
    return user;
  } catch {
    return null;
  }
}

function initOAuth(req, res, provider, buildAuthUrl) {
  const { client_id, redirect_uri } = req.query;

  if (!client_id || !redirect_uri) {
    return res
      .status(400)
      .json({ error: "client_id and redirect_uri are required" });
  }

  const client = findClient(client_id);
  if (!client) {
    return res.status(403).json({ error: "Unknown client_id" });
  }

  if (!validateRedirectUri(client, redirect_uri)) {
    return res
      .status(403)
      .json({ error: "redirect_uri is not allowed for this client" });
  }

  if (SSO_ENABLED && req.query.prompt !== "login") {
    const sessionUser = getSessionUser(req);
    if (sessionUser) {
      const authToken = createJWT({ ...sessionUser, client_id });
      return redirectWithToken(res, redirect_uri, authToken);
    }
  }

  const state = generateState(redirect_uri, client_id, provider);
  res.redirect(buildAuthUrl(state));
}

// ---------------------------------------------------------------------------
// Google OAuth
// ---------------------------------------------------------------------------

app.get("/auth/google", (req, res) => {
  if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
    return res
      .status(503)
      .json({ error: "Google OAuth is not configured on this server" });
  }
  initOAuth(req, res, "google", (state) =>
    googleOAuthClient.generateAuthUrl({
      access_type: "online",
      scope: ["openid", "email", "profile"],
      prompt: "select_account",
      state,
    })
  );
});

app.get("/auth/callback/google", async (req, res) => {
  const { code, state, error } = req.query;

  if (error) {
    return res.status(400).send("Google authentication was cancelled or failed.");
  }

  if (!code || !state) {
    return res.status(400).json({ error: "Missing code or state" });
  }

  const stateData = consumeState(state);
  if (!stateData) {
    return res.status(403).json({ error: "Invalid or expired state" });
  }

  try {
    const { tokens } = await googleOAuthClient.getToken({
      code,
      redirect_uri: GOOGLE_CALLBACK,
    });

    const ticket = await googleOAuthClient.verifyIdToken({
      idToken: tokens.id_token,
      audience: GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();

    const userInfo = {
      sub: payload.sub,
      email: payload.email,
      name: payload.name,
      picture: payload.picture || null,
      provider: "google",
    };

    setSessionCookie(res, userInfo);
    const authToken = createJWT({ ...userInfo, client_id: stateData.client_id });
    redirectWithToken(res, stateData.redirect_uri, authToken);
  } catch (err) {
    console.error("[AUTH] Google callback error:", err.message);
    res.status(500).json({ error: "Google authentication failed" });
  }
});

// ---------------------------------------------------------------------------
// Microsoft OAuth
// ---------------------------------------------------------------------------

app.get("/auth/microsoft", (req, res) => {
  if (!MS_CLIENT_ID || !MS_CLIENT_SECRET) {
    return res
      .status(503)
      .json({ error: "Microsoft OAuth is not configured on this server" });
  }
  initOAuth(req, res, "microsoft", (state) => {
    const params = new URLSearchParams({
      client_id: MS_CLIENT_ID,
      response_type: "code",
      redirect_uri: MS_CALLBACK,
      response_mode: "query",
      scope: "openid profile email User.Read",
      state,
    });
    return `${MS_AUTH_URL}?${params}`;
  });
});

app.get("/auth/callback/microsoft", async (req, res) => {
  const { code, state, error } = req.query;

  if (error) {
    return res
      .status(400)
      .send("Microsoft authentication was cancelled or failed.");
  }

  if (!code || !state) {
    return res.status(400).json({ error: "Missing code or state" });
  }

  const stateData = consumeState(state);
  if (!stateData) {
    return res.status(403).json({ error: "Invalid or expired state" });
  }

  try {
    const tokenResponse = await fetch(MS_TOKEN_URL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: MS_CLIENT_ID,
        client_secret: MS_CLIENT_SECRET,
        code,
        redirect_uri: MS_CALLBACK,
        grant_type: "authorization_code",
      }),
    });

    const tokenData = await tokenResponse.json();
    if (tokenData.error) {
      console.error("[AUTH] MS token exchange failed:", tokenData.error);
      return res.status(401).json({ error: "Token exchange failed" });
    }

    const profileResponse = await fetch(MS_GRAPH_URL, {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    const profile = await profileResponse.json();

    const email = profile.mail || profile.userPrincipalName;
    if (!email) {
      return res.status(400).json({ error: "Could not retrieve user email" });
    }

    const userInfo = {
      sub: profile.id,
      email,
      name: profile.displayName || email,
      picture: null,
      provider: "microsoft",
    };

    setSessionCookie(res, userInfo);
    const authToken = createJWT({ ...userInfo, client_id: stateData.client_id });
    redirectWithToken(res, stateData.redirect_uri, authToken);
  } catch (err) {
    console.error("[AUTH] Microsoft callback error:", err.message);
    res.status(500).json({ error: "Microsoft authentication failed" });
  }
});

// ---------------------------------------------------------------------------
// Email one-time code
// Same entry point shape as the OAuth providers, but the "provider" is our own
// page: the user enters an email, gets a 6-character code, and types it in.
// ---------------------------------------------------------------------------

// Deliberately strict — the address ends up in mail headers, so keep it to
// plain characters (no whitespace, quotes, or line breaks).
const EMAIL_RE = /^[a-z0-9._%+-]+@[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}$/;

function generateEmailCode() {
  let code = "";
  for (let i = 0; i < EMAIL_CODE_LENGTH; i++) {
    code += EMAIL_CODE_ALPHABET[crypto.randomInt(EMAIL_CODE_ALPHABET.length)];
  }
  return code;
}

function hashEmailCode(code) {
  return crypto.createHash("sha256").update(code).digest();
}

async function sendEmailCode(email, code) {
  if (!EMAIL_SENDING_CONFIGURED) {
    console.log(`[AUTH] (dev, email not configured) Login code for ${email}: ${code}`);
    return;
  }
  const minutes = EMAIL_CODE_TTL_MS / 60000;
  await sendEmail(
    email,
    `Your sign-in code: ${code}`,
    `
      <div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;max-width:420px;margin:0 auto;padding:32px 24px;color:#1e293b">
        <h2 style="margin:0 0 8px;font-size:20px;font-weight:600">Your sign-in code</h2>
        <p style="margin:0 0 24px;color:#64748b;font-size:14px">Enter this code to finish signing in.</p>
        <div style="font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:32px;font-weight:700;letter-spacing:8px;text-align:center;padding:16px;background:#f1f5f9;border-radius:12px;color:#312e81">${code}</div>
        <p style="margin:24px 0 0;color:#94a3b8;font-size:12px">This code expires in ${minutes} minutes. If you didn't try to sign in, you can ignore this email.</p>
      </div>`
  );
}

app.get("/auth/email", (req, res) => {
  if (!EMAIL_LOGIN_ENABLED) {
    return res
      .status(503)
      .json({ error: "Email login is not configured on this server" });
  }
  initOAuth(req, res, "email", (state) =>
    `/auth/email/login?${new URLSearchParams({ state })}`
  );
});

// The code-entry page. The state in the URL ties it to the client_id and
// redirect_uri validated by /auth/email.
app.get("/auth/email/login", (req, res) => {
  if (!peekState(req.query.state, "email")) {
    return res.status(403).json({ error: "Invalid or expired state" });
  }
  res.sendFile(path.join(__dirname, "pages", "email-login.html"));
});

app.post("/auth/email/send", async (req, res) => {
  const { state } = req.body;
  const email = String(req.body.email || "").trim().toLowerCase();

  const stateData = peekState(state, "email");
  if (!stateData) {
    return res
      .status(403)
      .json({ error: "This sign-in link has expired.", restart: true });
  }
  if (!EMAIL_RE.test(email) || email.length > 254) {
    return res.status(400).json({ error: "Enter a valid email address." });
  }

  const now = Date.now();
  const existing = pendingEmailCodes.get(state);
  const sends = existing ? existing.sends : 0;

  if (sends >= EMAIL_MAX_SENDS_PER_STATE) {
    pendingEmailCodes.delete(state);
    pendingStates.delete(state);
    return res.status(429).json({
      error: "Too many codes requested. Start over from the app you were signing into.",
      restart: true,
    });
  }
  if (existing && now - existing.lastSent < EMAIL_RESEND_COOLDOWN_MS) {
    const wait = Math.ceil((EMAIL_RESEND_COOLDOWN_MS - (now - existing.lastSent)) / 1000);
    return res
      .status(429)
      .json({ error: `Wait ${wait}s before requesting another code.`, resendIn: wait });
  }

  const recent = (emailSendLog.get(email) || []).filter(
    (t) => now - t < 60 * 60 * 1000
  );
  if (recent.length >= EMAIL_MAX_SENDS_PER_HOUR) {
    return res.status(429).json({
      error: "Too many codes have been sent to this address. Try again later.",
    });
  }

  const code = generateEmailCode();
  try {
    await sendEmailCode(email, code);
  } catch (err) {
    console.error("[AUTH] Email send error:", err.message);
    return res.status(502).json({ error: "Couldn't send the email. Try again." });
  }

  recent.push(now);
  emailSendLog.set(email, recent);

  const expires = now + EMAIL_CODE_TTL_MS;
  pendingEmailCodes.set(state, {
    email,
    codeHash: hashEmailCode(code),
    expires,
    attempts: 0,
    sends: sends + 1,
    lastSent: now,
  });
  // Keep the state alive at least as long as the code it now carries.
  stateData.expires = Math.max(stateData.expires, expires);

  res.json({
    sent: true,
    email,
    expiresIn: EMAIL_CODE_TTL_MS / 1000,
    resendIn: EMAIL_RESEND_COOLDOWN_MS / 1000,
    resendsRemaining: EMAIL_MAX_SENDS_PER_STATE - (sends + 1),
  });
});

app.post("/auth/email/verify", (req, res) => {
  const { state } = req.body;
  const code = String(req.body.code || "").toUpperCase().replace(/[^A-Z0-9]/g, "");

  const stateData = peekState(state, "email");
  if (!stateData) {
    return res
      .status(403)
      .json({ error: "This sign-in link has expired.", restart: true });
  }

  const entry = pendingEmailCodes.get(state);
  if (!entry || !entry.codeHash || Date.now() > entry.expires) {
    pendingEmailCodes.delete(state);
    return res
      .status(410)
      .json({ error: "That code has expired. Request a new one.", expired: true });
  }

  const matches =
    code.length === EMAIL_CODE_LENGTH &&
    crypto.timingSafeEqual(hashEmailCode(code), entry.codeHash);

  if (!matches) {
    entry.attempts++;
    const attemptsRemaining = EMAIL_CODE_MAX_ATTEMPTS - entry.attempts;
    if (attemptsRemaining <= 0) {
      // Burn the code, but keep the entry so the send count and resend
      // cooldown still apply. A new code can be requested while sends remain.
      entry.codeHash = null;
      return res.status(401).json({
        error: "Too many incorrect attempts. Request a new code.",
        attemptsRemaining: 0,
        expired: true,
      });
    }
    return res.status(401).json({
      error: `Incorrect code. ${attemptsRemaining} attempt${attemptsRemaining === 1 ? "" : "s"} left.`,
      attemptsRemaining,
    });
  }

  pendingEmailCodes.delete(state);
  pendingStates.delete(state);

  const userInfo = {
    sub: entry.email,
    name: entry.email.split("@")[0],
    email: entry.email,
    provider: "email",
  };

  setSessionCookie(res, userInfo);
  const authToken = createJWT({ ...userInfo, client_id: stateData.client_id });
  const url = new URL(stateData.redirect_uri);
  url.searchParams.set("token", authToken);
  res.json({ redirect: url.toString() });
});

// ---------------------------------------------------------------------------
// Logout
// ---------------------------------------------------------------------------

// Clears the CAS session cookie. Optionally redirects to a registered
// redirect_uri afterward — requires client_id so the URI can be validated.
app.get("/auth/logout", (req, res) => {
  res.clearCookie(SESSION_COOKIE, {
    httpOnly: true,
    secure: NODE_ENV === "production",
    sameSite: "lax",
  });

  const { redirect_uri, client_id } = req.query;

  if (redirect_uri && client_id) {
    const client = findClient(client_id);
    if (client && validateRedirectUri(client, redirect_uri)) {
      return res.redirect(redirect_uri);
    }
    return res.status(403).json({ error: "Invalid client_id or redirect_uri" });
  }

  res.json({ success: true });
});

// ---------------------------------------------------------------------------
// CORS
// ---------------------------------------------------------------------------

// Derive the set of allowed origins from each client's registered redirect URIs.
// e.g. "https://app1.example.com/auth/callback" → "https://app1.example.com"
const ALLOWED_ORIGINS = new Set(
  CLIENTS.flatMap((c) =>
    c.allowedRedirects.map((uri) => {
      try { return new URL(uri).origin; } catch { return null; }
    })
  ).filter(Boolean)
);

// Apply CORS headers for a specific response.
// origin: "*" for public endpoints, or the validated request origin for restricted ones.
function setCors(res, origin) {
  res.setHeader("Access-Control-Allow-Origin", origin);
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
}

// ---------------------------------------------------------------------------
// Public key / token verification endpoints
// ---------------------------------------------------------------------------

// Expose the public key as JWKS so client apps can verify tokens locally
// without making a network round-trip on every request.
// CORS: open to all origins — the public key is not sensitive.
app.get("/auth/jwks.json", (_req, res) => {
  setCors(res, "*");
  res.json(JWKS);
});

// Server-to-server token verification endpoint.
// Client apps can POST a token here and receive the verified payload.
// CORS: restricted to registered client origins only.
app.options("/auth/verify", (req, res) => {
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.has(origin)) {
    setCors(res, origin);
  }
  res.sendStatus(204);
});

app.post("/auth/verify", (req, res) => {
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.has(origin)) {
    setCors(res, origin);
  }

  const { token } = req.body;
  if (!token) {
    return res.status(400).json({ error: "token is required" });
  }
  try {
    const payload = jwt.verify(token, publicKey, {
      algorithms: ["RS256"],
      issuer: "centralized-auth",
    });
    // Strip JWT metadata before returning — clients only need the user claims.
    const { iat, exp, iss, ...user } = payload;
    res.json({ valid: true, user });
  } catch (err) {
    res.status(401).json({ valid: false, error: err.message });
  }
});

// ---------------------------------------------------------------------------
// Dev tools & startup
// ---------------------------------------------------------------------------

exposeEndpoints(app);

app.listen(PORT, () => {
  console.log(`[AUTH] Server listening at ${AUTH_BASE_URL}`);
  console.log(`[AUTH] Registered clients: ${CLIENTS.map((c) => c.id).join(", ") || "none"}`);
});
