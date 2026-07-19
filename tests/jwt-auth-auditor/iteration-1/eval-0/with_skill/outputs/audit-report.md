# Authentication Audit: taskboard-api

**Grade: F** - Multiple Tier 1 failures; the verifier accepts `alg: none` and the signing key falls back to a public hardcoded default, so anyone can forge an admin token today (lowest failing tier: Tier 1).
Audit depth: pattern-level (JS/TS)
Scope: JWT minting, JWT verification, auth middleware, login/logout, client token handling | Not present: refresh tokens, rotation/reuse detection, session cookies, risk-based/step-up auth, OTP, password reset, external IdP/OIDC, JWKS, multi-service verification

## Scorecard
| Tier | Result | Failed rules |
|---|---|---|
| 1 - Forgery/theft | FAIL | T08, T09, T13, T16, T22, R01 |
| 2 - Revocation | FAIL | T17 (plus architectural: no server-side revocation, R11/R12) |
| 3 - Hardening | FAIL | T04, T26 |
| 4 - Adaptive auth | 0 findings | none present (RBA/OIDC not implemented) |

## Findings

### T13 Algorithm pinned to a constant - FAIL (CONFIRMED) [Tier 1]
- Where: `server/auth.js:42-47`
- Evidence:
  ```js
  if (header.alg === 'none') {
      // unsigned tokens are used by the internal healthcheck bot
      return payload
  }
  const algo = header.alg === 'HS512' ? 'sha512' : 'sha256'
  ```
- Failure scenario: An attacker crafts a token with header `{"alg":"none","typ":"JWT"}`, payload `{"sub":1,"role":"admin","exp":9999999999}`, and any (or empty) signature segment. `verifyToken` matches the `none` branch and returns the payload with no signature check and no expiry check. `requireAuth` then sets `req.user` to that payload. Full admin access with a self-minted token. Separately, the verifier dispatches the HMAC algorithm off the token's own `alg` header (`HS512` vs `sha256`), which is exactly the attacker-controlled-algorithm anti-pattern.
- Fix: Pin the algorithm to a single hardcoded constant and reject everything else. Drop the `none` branch entirely (build a separate authenticated path for the healthcheck bot). Prefer a vetted library: `jsonwebtoken.verify(token, secret, { algorithms: ['HS256'] })` or `jose` with a fixed `alg`. If hand-rolled, hardcode `sha256` and reject any `header.alg !== 'HS256'` before computing the HMAC.
- Cite: RFC 8725 Sections 3.1-3.2 (explicit algorithm, reject `none`).

### T08 Signing key from environment, no fallback default - FAIL (CONFIRMED) [Tier 1]
- Where: `server/auth.js:3`
- Evidence: `const JWT_SECRET = process.env.JWT_SECRET || 'taskboard-dev-secret-2024'`
- Failure scenario: Any deploy that forgets to set `JWT_SECRET` boots successfully and signs every token with the literal `'taskboard-dev-secret-2024'`, which is committed to this repo and therefore public. Anyone reading the source can compute a valid HS256 signature for `{"sub":1,"role":"admin"}` and mint indistinguishable forgeries. This is token forgery today, independent of the `alg:none` bug.
- Fix: Read the key with no fallback and fail hard when it is missing: `const JWT_SECRET = process.env.JWT_SECRET; if (!JWT_SECRET) throw new Error('JWT_SECRET is required')`. Never ship a literal signing secret in source. Rotate the exposed secret immediately.
- Cite: RFC 8725; OWASP JWT Cheat Sheet.

### T22 Tokens never in localStorage or sessionStorage - FAIL (CONFIRMED) [Tier 1]
- Where: `client/src/api.js:6,15-16,22-23`
- Evidence:
  ```js
  const token = localStorage.getItem('taskboard_token')
  ...
  localStorage.setItem('taskboard_token', data.token)
  ```
- Failure scenario: The access token lives in `localStorage`, readable by any JavaScript on the origin. A single XSS, a compromised npm dependency, or a malicious browser extension reads `taskboard_token` and exfiltrates it; because the token is a self-contained 24-hour bearer credential with no server-side revocation, the attacker replays it from any machine for up to a day. An httpOnly cookie would keep the token out of JS reach and turn this from a silent takeover into a contained incident.
- Fix: Store the session token in an httpOnly, secure, sameSite cookie set by the server (see T23), and stop returning the token in the JSON login body for JS to persist. Remove the `localStorage` reads/writes.
- Cite: OWASP Session Management Cheat Sheet.

### T16 Missing `exp` fails verification - FAIL (CONFIRMED) [Tier 1]
- Where: `server/auth.js:57-62`
- Evidence:
  ```js
  const now = Math.floor(Date.now() / 1000)
  if (payload.exp && payload.exp < now) {
      return null
  }
  return payload
  ```
- Failure scenario: The guard is `payload.exp && payload.exp < now`. A token with no `exp` claim (or `exp: 0`) makes `payload.exp` falsy, so the expiry block is skipped and the payload is returned as valid: a never-expiring token. Combined with T13/T08 (an attacker can already choose the payload), this removes the only lifetime bound on a forged token.
- Fix: Require `exp` to be present and numeric, and fail otherwise: `if (typeof payload.exp !== 'number' || payload.exp < now) return null`. Library verifiers enforce this when configured to require `exp`.
- Cite: RFC 7519 Section 4.1.4; a missing claim must fail, never default to pass.

### T09 HS256 key is at least 32 bytes - FAIL (CONFIRMED) [Tier 1]
- Where: `server/auth.js:3`
- Evidence: fallback secret `'taskboard-dev-secret-2024'` is 25 bytes; there is no boot-time length validation of `JWT_SECRET`.
- Failure scenario: The fallback secret is 25 bytes (200 bits), below the 256-bit minimum RFC 7518 requires for HS256, and nothing validates the length of an operator-supplied key either, so a short weak key is accepted silently and is more brute-forceable offline.
- Fix: Validate at boot: `if (Buffer.byteLength(JWT_SECRET) < 32) throw new Error('JWT_SECRET must be >= 32 bytes')`. Generate keys with `openssl rand -hex 32`.
- Cite: RFC 7518 Section 3.2.

### R01 Access token TTL is short (5-15 minutes) - FAIL (CONFIRMED) [Tier 1]
- Where: `server/auth.js:4,20`
- Evidence: `const TOKEN_TTL_SECONDS = 60 * 60 * 24 // 24 hours so users stay logged in all day` used directly as the `exp` offset.
- Failure scenario: There is no refresh token and no server-side revocation, so the 24-hour `exp` is the entire damage window for a stolen or leaked access token. A token captured from `localStorage`, a proxy log, or an error tracker stays valid for up to 24 hours regardless of logout or password change. The guide's threshold: up to ~60 minutes is advisory; hours-to-days is a failure.
- Fix: Cut the access TTL to 5-15 minutes and introduce a refresh token (httpOnly, path-scoped, store-backed, rotated) to keep users signed in without a long-lived bearer credential.
- Cite: RFC 9700; OWASP JWT Cheat Sheet.

### T17 `iss` and `aud` are checked - FAIL (CONFIRMED) [Tier 2]
- Where: `server/auth.js:14-29` (mint) and `33-63` (verify)
- Evidence: the payload sets only `sub`, `role`, `iat`, `exp`; the verifier never enforces an issuer or audience.
- Failure scenario: With no `aud`/`iss` binding, a token minted for one purpose or environment is accepted anywhere the same secret is used; there is no defense-in-depth boundary if this secret is ever shared with or reused by another component. Lower severity than the Tier 1 findings for a single service, but the standard expects both to be set and checked.
- Fix: Add `iss` and `aud` claims at mint time and enforce expected values in the verifier (library `issuer`/`audience` options, or explicit equality checks).
- Cite: RFC 8725 Section 3.8; RFC 9700.

### T26 `Cache-Control: no-store` on token-issuing responses - FAIL (CONFIRMED) [Tier 3]
- Where: `server/index.js:9-17` (`/api/login`)
- Evidence: the login handler returns `{ token, user }` in the JSON body with no `Cache-Control` header set.
- Failure scenario: The login response carrying the bearer token can be cached by an intermediary or shared proxy, leaving a token on disk for later retrieval.
- Fix: Set `res.set('Cache-Control', 'no-store')` (and `Pragma: no-cache`) on login and any future token-issuing responses.
- Cite: OWASP Session Management Cheat Sheet.

### T04 No raw database id in `sub` - FAIL (CONFIRMED) [Tier 3]
- Where: `server/index.js:15` and `server/auth.js:16` (`sub: userId`), seed data `server/users.js:4-5` (ids `1`, `2`)
- Evidence: `signToken(user.id, user.role)` places the raw primary key into `sub`; user ids are sequential integers (`1`, `2`).
- Failure scenario: `sub` is a base64url-visible, sequential integer primary key. It confirms record existence, leaks user volume and ordering, and seeds IDOR/enumeration probing (guess `sub: 3`, `4`, ...). The rule normally treats raw ids as advisory, but sequential integers upgrade it to an enumeration risk. (Lane is `[GUIDE]`; the rule's verdict note authorizes the upgrade for sequential integers.)
- Fix: Put a random public identifier (UUIDv4 column) in `sub`, not the primary key.
- Cite: OWASP JWT Cheat Sheet; guide rule T04.

### Architectural: no server-side session revocation (R11/R12) - ADVISORY [Tier 2]
- Where: `server/index.js:19-22` (`/api/logout`)
- Evidence: `// Client discards the token; nothing to do server-side since JWTs are stateless.` The handler returns `{ ok: true }` and revokes nothing.
- Tradeoff: Because tokens are stateless with no store and no refresh family, logout, password change, and "sign out everywhere" cannot invalidate an outstanding token; it stays valid until `exp` (24h). This is the direct consequence of the stateless design plus the long TTL (R01). Not scored as a standalone FAIL here since there is no refresh/store subsystem to fault, but it is a real operational gap: a copied token survives logout.
- Fix: Introduce store-backed refresh tokens with rotation and a short access TTL so security events can revoke sessions; at minimum maintain a server-side denylist keyed by `jti` for active access tokens.
- Cite: OWASP Session Management Cheat Sheet (server-side invalidation); RFC 9700 Section 4.14.

### T03 Roles-in-token decision is deliberate - ADVISORY [Tier 3]
- Where: `server/auth.js:16-17` (`role` claim), consumed at `server/index.js:31,36`
- Tradeoff: `role` is embedded in a 24-hour token and there is no documented decision or per-request re-check. A privilege downgrade does not take effect until the token expires (up to 24h). Shortening the access TTL (R01) bounds this; a brief comment recording the tradeoff, or a per-request role lookup, resolves the rule.
- Cite: guide rule T03.

### T15 Signature comparison is constant time - ADVISORY [Tier 3]
- Where: `server/auth.js:53` (`providedSignature !== expected`)
- Tradeoff: The hand-rolled verifier compares signatures with `!==`, which short-circuits and is theoretically a timing oracle. Use `crypto.timingSafeEqual` with a length guard, or (better) adopt a library verifier which handles this. Low practical severity relative to the Tier 1 findings, and moot once a library replaces the hand-rolled path.
- Cite: guide rule T15.

### T18 Clock-skew leeway - ADVISORY [Tier 3]
- Where: `server/auth.js:57-58`
- Tradeoff: No leeway is applied to the `exp` comparison, which can produce unreproducible 401s across servers with clock drift. Add ~30-60s tolerance (or a library `clockTolerance`). Minor.

### T10 Keys validated at boot, not first use - ADVISORY [Tier 2]
- Where: `server/auth.js:3`
- Tradeoff: The key is never validated at startup; a missing/short key surfaces as bad tokens at runtime rather than a failed deploy. Resolved by the boot-time checks recommended in T08/T09.

### T21 Auth applied structurally, not per route - ADVISORY [Tier 2]
- Where: `server/index.js:35` (`requireAuth` attached per route)
- Tradeoff: Protection is applied route-by-route. A new protected route added later without remembering `requireAuth` ships unauthenticated. Prefer router-level middleware so protection follows placement. Minor for a two-route app; matters as the surface grows.

## Cannot determine from code
- Whether `JWT_SECRET` is actually set in the production environment. The `||` fallback masks a missing value, so a misconfigured deploy would sign with the public default without any error. Confirm the deploy sets a strong secret and remove the fallback so misconfiguration fails loudly.
- Whether a `.gitignore` / `.env` / `.env.example` exists in the real repository. None are present in this fixture; the signing secret is hardcoded in source rather than sourced from a secrets file.
- Whether the identical placeholder `passwordHash` values in `server/users.js` (`$2a$10$abcdefghijklmnopqrstuv`, not a valid 60-char bcrypt hash) are seed/fixture data or representative of production. As written, `bcrypt.compare` against these would always return false. Treated as fixture data and out of scope for a finding; confirm real hashes are proper bcrypt output.

## What is done well
- Passwords are verified with `bcryptjs` via `bcrypt.compare`, not a plaintext or fast-hash comparison (`server/users.js:11`).
- No secrets or PII in the token payload: only `sub`, `role`, `iat`, `exp` are claimed (T01, T02 pass).
- NumericDate handling is correct: minting and verifying both use `Math.floor(Date.now() / 1000)` in seconds (T27 pass).
- In the HMAC path, the signature is checked before the expiry claim is evaluated (T14 pass for that path).
- Login and verification failures return a single generic message, avoiding an "expired vs bad signature" oracle (T19 pass); `verifyToken` returning `null` funnels all failures to one 401.
- The auth middleware grants access only on a truthy payload and otherwise returns 401; it does not log-and-continue (fails closed, T20 pass). Note the unhandled `JSON.parse` throw on a malformed token surfaces as a 500 rather than a clean 401, so harden `verifyToken` with a `try/catch` returning `null`.
- HS256 is topology-appropriate for this single signing-and-verifying service (T12 pass).
