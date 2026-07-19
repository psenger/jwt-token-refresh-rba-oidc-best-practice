# Authentication Audit: ledgerly-api

**Grade: C** - Tier 1 passes cleanly, but a confirmed Tier 2 failure (password change does not revoke the user's other sessions) caps the grade at C.
Audit depth: pattern-level (JS/TS)
Scope: JWT access/refresh minting and verification (jose/HS256), cookie storage, refresh rotation with family reuse detection, Redis-backed revocation, auth middleware, login/logout/password-change handlers, axios client interceptor | Not present: risk-based auth/step-up, OTP, forgot-password flow, device binding, multi-service verification, external IdP/OIDC (rules-rba.md and rules-oidc.md not applicable)

## Scorecard
| Tier | Result | Failed rules |
|---|---|---|
| 1 - Forgery/theft | PASS | - |
| 2 - Revocation | FAIL | R12 (CONFIRMED) |
| 3 - Hardening | FAIL | R13 (PLAUSIBLE) |
| 4 - Adaptive auth | 1 finding | R03 (ADVISORY) |

## Findings

### R12 Revocation fires on account-security events - FAIL (CONFIRMED) [Tier 2]
- Where: server/routes.js:91-104
- Evidence:
  ```js
  await updatePassword(req.user.sub, req.body.newPassword)
  // The account may be compromised: revoke every session, not just this one.
  const presented = req.cookies.refreshToken
  if (presented) {
      try {
          const payload = await tokens.verifyRefreshToken(presented)
          await revocation.revokeFamily(payload.family, config.refreshTtlSeconds)
      } catch (err) { /* cookie already invalid */ }
  }
  ```
- Failure scenario: each login mints a fresh `family` (routes.js:33, `crypto.randomUUID()`), so a user with sessions on devices A and B holds two independent families. An attacker who stole the victim's credentials (or a refresh token) and logged in on device B holds family FB. The victim changes their password from device A: only the family in the *presented* cookie (FA) is revoked. FB is never touched, and because each rotation re-issues a full-TTL refresh token, the attacker's session keeps refreshing indefinitely. The comment says "revoke every session"; the code revokes exactly one. The revocation store has no user-to-families index, so revoking the rest is not even possible with the current schema.
- Fix: record a per-user revocation watermark at password change, and reject any refresh token issued before it. With the existing denylist this is two small additions:
  ```js
  // revocation.js
  async function revokeUserBefore(sub, ttlSeconds) {
      await redis.set(`revoked:user:${sub}`, Math.floor(Date.now() / 1000), { EX: ttlSeconds })
  }
  async function issuedBeforeUserRevocation(sub, iat) {
      const cutoff = await redis.get(`revoked:user:${sub}`)
      return cutoff !== null && iat <= parseInt(cutoff, 10)
  }
  ```
  Call `revokeUserBefore(req.user.sub, config.refreshTtlSeconds)` in the password handler (and any future email-change / suspension / "sign out everywhere" paths), and add `if (await revocation.issuedBeforeUserRevocation(payload.sub, payload.iat)) return 401` to the refresh handler alongside the family and jti checks. An alternative is maintaining a `families:user:<id>` set written at login and iterating it, at the cost of an extra write per login.
- Cite: OWASP Session Management Cheat Sheet (invalidate all sessions on password change); RFC 9700 Section 4.14.

### R13 Refresh endpoint is POST and rate limited - FAIL (PLAUSIBLE) [Tier 3]
- Where: server/routes.js:40 (refresh), server/routes.js:28 (login), server/index.js (no limiter middleware)
- Evidence: `router.post('/open/refresh', ...)` - POST is correct, but no rate-limiting middleware exists anywhere in the repo, and package.json declares no rate-limit dependency. The login endpoint is likewise unthrottled.
- Failure scenario: an attacker who has captured any refresh-token cookie value (or is credential-stuffing `/open/login`) can hammer the endpoint at network speed; nothing in the application slows guessing or amplifies the cost of abuse.
- Named assumption: rate limiting may be enforced upstream at a gateway or load balancer that is not part of this repository. If it is, this finding resolves to PASS; confirm with the team.
- Fix: add `express-rate-limit` (keyed by IP, since the user is unknown until after validation) on `/api/open/login` and `/api/open/refresh`, e.g. a small window such as 10 requests/minute per IP on login and a limit comfortably above the legitimate refresh cadence on refresh.
- Cite: RFC 9700; OWASP Session Management Cheat Sheet.

### R11 Logout deletes server-side state first - ADVISORY [Tier 2]
- Where: server/routes.js:75-89
- Evidence: the revocation happens before `clearCookie` (correct order), but the whole revocation block is wrapped in `try { ... } catch (err) { /* fall through: still clear cookies */ }` and the handler returns `{ ok: true }` regardless.
- Tradeoff: if Redis is down, logout clears the browser's cookies and reports success while the family stays valid server-side; anyone who copied the token keeps a working session until the refresh TTL lapses. The current behavior is a defensible availability choice (users can always "log out"), but consider logging the revocation failure and/or alerting, so a store outage during logout is visible rather than silent.
- Cite: OWASP Session Management Cheat Sheet (server-side invalidation).

### T25 Refresh cookie path-scoped to the refresh endpoint - ADVISORY [Tier 3]
- Where: server/routes.js:19-25
- Evidence: `res.cookie('refreshToken', refreshToken, { path: '/', ... })`
- Tradeoff: with `path: '/'`, the longest-lived credential rides on every request to the API, so proxies, APM, and error trackers all see it. Scoping the cookie to `path: '/api/open/refresh'` (and passing the same path to `clearCookie` in logout and password-change) puts it on the wire only during refresh. This is the source guide's stricter opinion; the current setup is not a standards violation.

### T26 Cache-Control: no-store on token-issuing responses - ADVISORY [Tier 3]
- Where: server/routes.js:101-103
- Evidence: `/secure/password` sends Set-Cookie (via `clearCookie`) without `Cache-Control: no-store`; login, refresh, and logout all set it.
- Tradeoff: defensible as-is, since the cleared cookies carry no token value, only expirations. Setting the header there too costs one line and removes the inconsistency.
- Cite: OWASP Session Management Cheat Sheet.

### T04 No raw database id in `sub` - ADVISORY [Tier 3]
- Where: server/tokens.js:12 and 23 (`.setSubject(String(userId))`)
- Evidence: `sub` carries the database user id directly; db.js is a stub, so the id format (UUID vs sequential integer) is not visible.
- Tradeoff: many production systems ship raw ids. If the Postgres primary key is a sequential integer, published ids leak volume/ordering and seed IDOR probing, which would upgrade this to a real enumeration risk; if it is a UUIDv4, this is a non-issue. Confirm the column type.

### R03 Sliding vs absolute session window chosen on purpose - ADVISORY [Tier 4]
- Where: server/routes.js:67 (`tokens.mintRefreshToken(user.id, payload.family)`)
- Evidence: every rotation mints a replacement refresh token with a fresh full `refreshTtlSeconds`, so an active session slides forever; there is no absolute cap on family age.
- Tradeoff: sliding windows are a legitimate UX choice, but nothing in the code or comments records the decision, and NIST SP 800-63B recommends a bounded reauthentication interval. If a cap is wanted, store the family's creation time (or put an `auth_time` claim in the refresh token that is copied, not refreshed, across rotations) and force re-login past a maximum age.

## Cannot determine from code

- Production values of `AUTH_ACCESS_TOKEN_TTL_SECONDS` and `AUTH_REFRESH_TOKEN_TTL_SECONDS`. The `.env.example` defaults (600s access, 86400s refresh) satisfy R01's 5-15 minute guidance; confirm the deployed values match.
- Whether a gateway or load balancer in front of the API provides the rate limiting missing from the application (settles R13).
- server/redisClient.js creates the client but nothing in the repo calls `client.connect()` (required by node-redis v4). If the real bootstrap also omits it, every store check throws and the refresh handler's catch returns 401: fail-closed and secure, but every refresh would fail. Confirm the connection lifecycle in the actual deployment.
- server/users.js requires `bcryptjs`, which is not declared in package.json; presumably trimmed from this snapshot, but confirm the production manifest.
- The audited directory is not a git repository, so the S01 history scan for ever-committed real keys could not run; run it on the actual repo.
- Whether the reuse-detection `console.warn` (routes.js:54) feeds an alerting pipeline; detection without a pager is detection nobody sees.

## What is done well

This is a genuinely strong implementation at the token layer. Verification uses `jose` with a pinned `algorithms: ['HS256']` allowlist, enforced `iss`/`aud`, sane `clockTolerance`, and a `token_use` type check on every verify, so refresh tokens can never pass as access tokens (T07, T13-T18). The signing key comes from the environment with no fallback default and is length-validated at boot along with the TTLs, so a bad deploy dies at startup (T08-T10, R02). Both tokens live in `httpOnly; secure; sameSite=strict` cookies with correctly converted lifetimes, and nothing touches localStorage (T22-T24, T27). The refresh lifecycle is textbook: store-backed denylist validation that fails closed, rotation that burns the old jti before minting, family-wide revocation on reuse with logging, user re-checked as active on every refresh, and logout that revokes server-side before clearing cookies (R04, R06, R07, R09, R10, R14, R11-ordering). The client interceptor gets every classic pitfall right: single-flight refresh cleared in `.finally()`, `_retry` guard set before awaiting, a separate refresh client with no 401 handler, 401-only triggering, optional chaining on `error.response`, query cache cleared on both sign-out and expiry, and SPA navigation via events (R15-R23). Secrets hygiene (`.gitignore`, placeholder-only `.env.example`) is correct (S01). The one real gap, R12, is a bounded fix on an otherwise solid revocation design.
