# Authentication Security Audit — taskboard-api

**Scope:** JWT-based authentication in `fixture-flawed`
**Files reviewed:** `server/auth.js`, `server/index.js`, `server/users.js`, `client/src/api.js`, `package.json`
**Date:** 2026-07-19

---

## Overall Grade: F (Critical — authentication is trivially bypassable)

This implementation contains multiple critical vulnerabilities, at least two of which allow a remote, unauthenticated attacker to forge a valid admin token and completely bypass authentication. The custom JWT verifier is the root cause. Do not deploy.

---

## Findings by Severity

### CRITICAL

#### C1. `alg: "none"` accepted — complete authentication bypass
`server/auth.js:42-45`
```js
if (header.alg === 'none') {
    // unsigned tokens are used by the internal healthcheck bot
    return payload
}
```
The verifier returns the decoded payload with **no signature check** whenever the token header declares `alg: "none"`. Since the header is attacker-controlled, anyone can craft a token like `{"alg":"none"}.{"sub":1,"role":"admin","exp":9999999999}.` and be authenticated as an admin. This is the textbook JWT `alg=none` vulnerability (CVE class). It also skips the `exp` check, so forged tokens never expire.

**Impact:** Full auth bypass and privilege escalation with a hand-crafted string. No secret needed.
**Fix:** Never trust the token's declared algorithm. Reject `none` outright and pin a single expected algorithm server-side.

#### C2. Hardcoded / guessable fallback signing secret
`server/auth.js:3`
```js
const JWT_SECRET = process.env.JWT_SECRET || 'taskboard-dev-secret-2024'
```
If `JWT_SECRET` is unset (a common misconfiguration), the server signs and verifies with a static secret that is committed to source control. Anyone with repo access — or who guesses this low-entropy string — can mint valid tokens for any user and role.

**Impact:** Token forgery for arbitrary users/roles.
**Fix:** Require the secret from the environment and fail closed at startup if absent. Use a high-entropy (>=256-bit) random secret. Rotate the leaked value.

#### C3. Algorithm selected from attacker-controlled header
`server/auth.js:47`
```js
const algo = header.alg === 'HS512' ? 'sha512' : 'sha256'
```
The HMAC algorithm is chosen from the untrusted header rather than a server-side policy. Combined with C1 this is a classic algorithm-confusion flaw. A hardened verifier must ignore `header.alg` and enforce one expected algorithm.

---

### HIGH

#### H1. Non-constant-time signature comparison
`server/auth.js:53` — `if (providedSignature !== expected)`
String `!==` short-circuits on the first differing byte, leaking timing information that can, in principle, be used to forge a signature byte-by-byte. Use `crypto.timingSafeEqual` on equal-length buffers.

#### H2. Token stored in `localStorage`
`client/src/api.js:15` — `localStorage.setItem('taskboard_token', data.token)`
Tokens in `localStorage` are readable by any JavaScript on the page, so any XSS becomes full account takeover. Prefer an `HttpOnly`, `Secure`, `SameSite` cookie so the token is never exposed to script.

#### H3. No token revocation and stateless "logout"
`server/index.js:19-22`
Logout only discards the client copy; the token remains valid server-side until expiry. With a 24-hour TTL (`auth.js:4`), a stolen or leaked token grants access for up to a full day with no way to revoke it. Introduce short-lived access tokens plus a refresh/denylist mechanism.

#### H4. `JSON.parse` on untrusted input without error handling
`server/auth.js:39-40`
Malformed base64/JSON in the header or payload throws an uncaught exception inside `verifyToken`, which propagates out of `requireAuth` (no try/catch) and can crash the request handler or leak stack traces. Wrap decoding in try/catch and return `null` on any parse failure.

---

### MEDIUM

#### M1. Missing `exp` allows non-expiring tokens
`server/auth.js:58` — `if (payload.exp && payload.exp < now)`
A token with no `exp` claim passes verification and never expires. Treat a missing `exp` as invalid.

#### M2. Overly long token lifetime
`server/auth.js:4` — 24-hour TTL maximizes the exposure window for any leaked token. Use short-lived access tokens (minutes) with refresh.

#### M3. No issuer/audience validation
The verifier checks neither `iss` nor `aud`, so a token minted for another service sharing the secret would be accepted. Validate `iss`/`aud`.

#### M4. No brute-force protection on login
`server/index.js:9` — `/api/login` has no rate limiting or lockout, enabling credential stuffing / password brute force.

#### M5. Username enumeration via timing
`server/users.js:8-12`
When the email is unknown the function returns immediately; when it exists it runs `bcrypt.compare`. The measurable difference lets an attacker enumerate valid accounts. Always run a dummy compare.

---

### LOW / HARDENING

- **L1.** No transport/security middleware: no `helmet`, no enforced HTTPS/HSTS, no explicit CORS policy (`server/index.js`).
- **L2.** Fragile bearer parsing: `authHeader.replace('Bearer ', '')` (`index.js:26`) mishandles casing and extra whitespace; parse explicitly.
- **L3.** Custom hand-rolled JWT implementation instead of a vetted library (`jsonwebtoken`, `jose`). Rolling your own is the origin of C1–C3; migrate to a maintained library with a strict verify configuration.
- **L4.** No `typ` header validation.

---

## Root-Cause Summary

| # | Issue | Severity | Location |
|---|-------|----------|----------|
| C1 | `alg:none` bypass | Critical | auth.js:42 |
| C2 | Hardcoded fallback secret | Critical | auth.js:3 |
| C3 | Algorithm from untrusted header | Critical | auth.js:47 |
| H1 | Non-constant-time compare | High | auth.js:53 |
| H2 | Token in localStorage | High | api.js:15 |
| H3 | No revocation / stateless logout | High | index.js:19 |
| H4 | Unhandled JSON.parse | High | auth.js:39 |
| M1 | Missing-exp accepted | Medium | auth.js:58 |
| M2 | 24h token TTL | Medium | auth.js:4 |
| M3 | No iss/aud check | Medium | auth.js |
| M4 | No login rate limiting | Medium | index.js:9 |
| M5 | User enumeration timing | Medium | users.js:8 |

## Priority Remediation

1. Replace the custom verifier with a vetted library and a strict verify config that pins the algorithm (reject `none`), and validates `exp`/`iss`/`aud`. (Fixes C1, C3, M1, M3, H4)
2. Require `JWT_SECRET` from the environment; fail startup if missing; rotate the leaked value. (Fixes C2)
3. Move tokens to `HttpOnly`/`Secure`/`SameSite` cookies; add short-lived access tokens with refresh and a revocation list. (Fixes H2, H3, M2)
4. Add rate limiting on login, constant-time credential handling, and standard security middleware (helmet/HTTPS/CORS). (Fixes M4, M5, L1)
