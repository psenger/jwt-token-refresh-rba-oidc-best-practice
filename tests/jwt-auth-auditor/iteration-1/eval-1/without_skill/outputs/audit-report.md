# Security Audit: ledgerly-api Authentication Code

**Scope:** `fixtures/fixture-solid` (Express API: `server/*.js`; browser client: `client/src/*.ts`; config: `package.json`, `.env.example`, `.gitignore`)
**Date:** 2026-07-19
**Grade: B+**

## Summary

This is a well-designed JWT access/refresh implementation that follows current best practice in most of the places that matter: pinned algorithm, validated issuer/audience, token-type claims, httpOnly/secure/SameSite=Strict cookies, refresh-token rotation with reuse detection and family revocation, fail-closed revocation checks, boot-time secret validation, and a single-flight refresh on the client. None of the classic JWT footguns (alg confusion, `none`, unverified decode, tokens in localStorage, secrets in the repo) are present.

It is not ready to ship as-is. The password-change endpoint has two real problems (no re-authentication, and it does not actually revoke all sessions despite claiming to), there is no rate limiting or brute-force defense on the open endpoints, sessions can slide forever with no absolute lifetime, and several runtime dependencies used by the code are missing from `package.json`, including a Redis client that is never connected, which would break refresh entirely in production (it fails closed, but it fails).

## What the code does well

- **Token verification is strict** (`server/tokens.js`): `jwtVerify` pins `algorithms: ['HS256']` and checks `issuer` and `audience`; a `token_use` claim (`access` vs `refresh`) is minted and checked on both paths, so a refresh token cannot be replayed as an access token or vice versa. `jti` is a `crypto.randomUUID()`. Clock tolerance is a modest 30s.
- **Secrets are validated at boot** (`server/config.js`): the signing key must be present and decode to at least 32 bytes of hex; TTLs must be positive integers. A bad deploy fails at startup rather than minting broken tokens. `.env` is gitignored and only `.env.example` (with a placeholder) is committed.
- **Cookie handling is correct** (`server/routes.js` `setAuthCookies`): both tokens are `httpOnly`, `secure`, `sameSite: 'strict'`, with `maxAge` matched to token TTL, and `Cache-Control: no-store` on token responses. Tokens never reach JavaScript or response bodies.
- **Rotation with reuse detection** (`/open/refresh`): every refresh burns the presented `jti` in a Redis denylist and mints a replacement in the same family; presenting an already-burned `jti` is treated as theft and revokes the entire family, per the OWASP recommendation. Family revocation is checked before jti revocation, and the user's `active` status is re-checked on every refresh.
- **Fail-closed revocation** (`server/revocation.js` + the `try/catch` in `/open/refresh`): if Redis errors, the awaits reject and the handler returns 401 rather than skipping the check. Denylist entries carry a TTL matching the token's remaining life, so the store self-evicts.
- **Structural route protection** (`server/index.js`): everything under `/api/secure` passes through the verification middleware; protection is not per-route opt-in.
- **Uniform error responses**: every auth failure returns the same generic `Authentication failed` with 401, avoiding oracle responses that distinguish "no such user" from "bad password" from "revoked token".
- **Password storage** (`server/users.js`): bcrypt with cost 12; login compares against a stored hash.
- **Client is disciplined** (`client/src/api.ts`): 401s trigger exactly one refresh (single-flight `refreshPromise`, `_retry` guard prevents loops), refresh failure clears client cache and redirects to login, `withCredentials` everywhere, no token handling in JS at all.

## Findings

### High

**H1. Password change requires no re-authentication.** `POST /api/secure/password` (`server/routes.js`) accepts `newPassword` with no `currentPassword` check. Anyone holding a live access token cookie (XSS-adjacent compromise, a borrowed browser session, a token valid for up to 10 minutes after theft) can permanently take over the account by setting a new password. Password change, like other sensitive operations, should demand fresh proof of the current password.

**H2. Password change does not revoke "every session" as the comment claims.** The comment reads "revoke every session, not just this one", but the code only calls `revocation.revokeFamily(payload.family, ...)` on the family of the refresh token presented in this request's cookie. Refresh-token families belonging to the user's other devices remain fully valid, and so do all outstanding access tokens. After a password change on a possibly-compromised account, an attacker's separate session survives. Fixing this needs a per-user revocation primitive (for example a `tokenVersion`/`auth_time` claim checked against the user record, or a `revoked:user:{sub}` key checked on refresh and ideally on access verification).

**H3. No rate limiting or brute-force defense on `/api/open/login` and `/api/open/refresh`.** Credential stuffing and password spraying against login are unthrottled, and refresh is a free signature-verification oracle. Add per-IP and per-account throttling (e.g. `express-rate-limit` plus account lockout/backoff) before shipping.

### Medium

**M1. Unbounded sliding sessions.** Every successful refresh mints a new refresh token with a full `refreshTtlSeconds` (24h) lifetime in the same family. A session that refreshes at least once a day lives forever; there is no absolute session expiry. Carry an original-auth timestamp through the family (or cap the family's lifetime in Redis) and force re-login after a maximum age, per OWASP session-management guidance.

**M2. Missing runtime dependencies; Redis client never connected.** `server/users.js` requires `bcryptjs` and `server/redisClient.js` requires `redis`, but `package.json` declares neither (nor does the client's `@tanstack/react-query` appear anywhere). Separately, node-redis v4 requires `client.connect()` before use and it is never called, so every revocation call would reject. The system fails closed (refresh and logout revocation return 401/no-op), but that means token refresh is entirely broken in production, and logout would silently fail to revoke server-side. If this mirrors the real deployment configuration, it is a ship blocker on availability grounds and a silent-revocation-failure on the logout path.

**M3. Unvalidated request bodies cause unhandled promise rejections.** No input validation anywhere. With Express 4 and bare `async` handlers, `bcrypt.compare(undefined, ...)` in `/open/login` (missing `password`) and `bcrypt.hash(undefined, 12)` in `/secure/password` (missing `newPassword`) throw, the promise rejects with no catch, the request hangs until client timeout, and Node logs an unhandled rejection (process-fatal on some configurations). `/open/login` and `/secure/password` have no `try/catch`, unlike `/open/refresh`. Validate body shape (and password strength for `newPassword`) and wrap handlers.

**M4. Access tokens are irrevocable for their full lifetime.** Logout, password change, family revocation, and user deactivation have no effect on already-issued access tokens; the `/api/secure` middleware checks only signature/claims. With a 600s TTL this is a common and often acceptable tradeoff, but combined with H1/H2 it widens the takeover window. Either shorten the access TTL or add a lightweight check (user tokenVersion, or jti denylist consulted on high-value routes) for sensitive operations.

### Low

**L1. CSRF relies solely on `SameSite=Strict`.** No CSRF token and no Origin/Referer check on state-changing endpoints. SameSite=Strict is strong in modern browsers, and `express.json()` limits form-based CSRF, but defense-in-depth (Origin header validation is cheap) is advisable for an app about to ship.

**L2. User-enumeration timing side channel in login.** `findUserByCredentials` returns immediately when the email is unknown but runs a full bcrypt compare when it is known. Compare against a dummy hash on the unknown-email path to equalize timing.

**L3. Rotation TOCTOU race.** In `/open/refresh`, `isJtiRevoked` is checked before `revokeJti` is written, with a DB lookup in between. Two concurrent presentations of the same refresh token can both pass and both receive new tokens, evading reuse detection for that pair. The client's single-flight refresh makes benign races rare; an atomic check-and-set (Redis `SET NX` on the jti at check time) closes it.

**L4. Cookie hardening headroom.** Cookies are not `__Host-` prefixed, and `clearCookie` passes only `path` (attributes should match the set call to guarantee clearing in all browsers). No `helmet`/security headers on the app, and `secure: true` cookies behind a reverse proxy need `app.set('trust proxy', ...)` to behave correctly.

**L5. No signing-key rotation support.** A single static HS256 secret with no `kid` header means key rotation requires invalidating every outstanding token. Fine at this scale, but worth a roadmap note (or moving to asymmetric keys if other services ever need to verify tokens).

## Grade rationale

The architecture and the token-handling core would earn an A-: this is textbook rotation-with-reuse-detection done fail-closed, with correct cookie flags and strict verification. The grade drops to **B+** because of concrete pre-ship defects: a password-change endpoint that neither re-authenticates nor delivers the all-session revocation its comment promises (H1, H2), no brute-force protection on the open endpoints (H3), unbounded session lifetime (M1), and a dependency/Redis-connection state that would break refresh in production (M2). All are cheap to fix relative to the quality of the surrounding code; with H1-H3 and M2 addressed, this ships comfortably.

## Priority fix list

1. Require current password on `POST /secure/password`; add per-user (all-family) revocation and use it there (H1, H2).
2. Add rate limiting to `/open/login` and `/open/refresh` (H3).
3. Declare `bcryptjs` and `redis` in `package.json`; call and await `client.connect()` at boot, and fail startup if Redis is unreachable (M2).
4. Enforce an absolute session lifetime per refresh-token family (M1).
5. Validate request bodies and wrap the two uncaught async handlers (M3).
