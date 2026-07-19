# Rule Set: Refresh Token Lifecycle and Client Refresh Logic

Load this file when the codebase issues refresh tokens or contains client-side
token-refresh logic (interceptors, fetch wrappers). Lane markers as in rules-tokens.md.

---

## Lifetimes

### R01 Access token TTL is short (5-15 minutes) [Tier 1] [STANDARD]
- Check: the minted access token `exp`. An access token cannot be revoked; its TTL
  is the damage window for a stolen token.
- Verdict note: up to 60 minutes is ADVISORY; hours-to-days is a FAIL.
- Cite: RFC 9700; OWASP JWT Cheat Sheet.

### R02 TTLs from environment, validated at boot [Tier 3] [GUIDE]
- Check: `parseInt` + `Number.isInteger` guard (or equivalent) that crashes the
  process on malformed config rather than minting `exp: NaN` later.

### R03 Sliding vs absolute window chosen on purpose [Tier 4] [GUIDE]
- Check: if refresh tokens are not rotated, the session window is absolute
  (users dropped after exactly the refresh TTL regardless of activity). Confirm
  a comment/doc shows this is intended, not a surprise.

---

## Server-side revocability

### R04 Refresh validity requires a store check, not just a signature [Tier 2] [STANDARD]
- Check: the refresh endpoint verifies the signature AND looks the token's `jti`
  (or an opaque token id) up in a store. Signature-only refresh means nothing is
  revocable.
- Evidence: the refresh handler, from token receipt to new-token mint.
- Cite: RFC 9700 Section 4.14; OWASP JWT Cheat Sheet (deny/allow listing).
- Verdict note: the guide uses an allowlist (present = valid, default deny). An
  OWASP-style denylist (revoked ids listed) also passes this rule; do not flag a
  compliant denylist as a failure. Allowlist-vs-denylist preference is [GUIDE].

### R05 Store write on issue is awaited [Tier 2] [STACK]
- Check: the `jti` registration write is awaited before the response is sent,
  never fire-and-forget.
- Failure mode: a fast client hits refresh before the write lands, gets a
  spurious 401, and bounces to login; a silently failed write mints a
  permanently unusable token.

### R06 Store entries carry a TTL derived from token `exp` [Tier 3] [GUIDE]
- Check: `ttl = exp - now` so entries self-evict; otherwise a cleanup job exists.

### R07 Validation fails closed when the store is unreachable [Tier 2] [STANDARD]
- Check: a null/error result from the store denies the refresh. Look for catch
  blocks or falsy checks that continue on store failure.
- Failure mode: fail-open silently disables revocation, fingerprint checks, and
  reuse detection during exactly the outage an attacker can cause on purpose.
  When a security check cannot run, the answer is no.

### R08 Stored context validated, not just presence [Tier 3] [GUIDE]
- Check: the store entry's `sub` (and fingerprint, if device binding is used)
  is compared against the presented token, not merely found.

### R09 Rotation: every refresh burns the old token [Tier 3] [STANDARD]
- Check: the old `jti` is deleted and a new refresh token issued on every use;
  each refresh token is single-use.
- Cite: RFC 9700 Section 4.14 (refresh token rotation).
- Coupling: if rotation is present, client single-flight (R17) becomes Tier 2;
  rotation plus concurrent refresh without single-flight causes intermittent
  mass logouts that never reproduce locally.

### R10 Reuse detection revokes the whole family [Tier 3] [STANDARD]
- Check: presenting an already-burned `jti` deletes every descendant of that
  login (a `family` id set at login and copied to each rotation), and logs the
  event with family and user id.
- Failure mode: without this, a stolen refresh token works silently forever;
  theft never becomes detectable.
- Cite: RFC 9700 Section 4.14.2.

### R11 Logout deletes server-side state first, then clears cookies [Tier 2] [STANDARD]
- Check: the sign-out handler revokes the family/store entry before
  `clearCookie`. Clearing cookies alone is not logout.
- Failure mode: anyone who copied the token (proxy log, shared machine) keeps a
  working session; they never received your Set-Cookie.
- Cite: OWASP Session Management Cheat Sheet (server-side invalidation).

### R12 Revocation fires on account-security events [Tier 2] [STANDARD]
- Check: password change, email change, "sign out everywhere", suspension, and
  privilege downgrade all revoke the user's token families.
- Failure mode: the attacker's session survives the very event meant to end it;
  one of the most common production auth bugs.

### R13 Refresh endpoint is POST and rate limited [Tier 3] [STANDARD]
- Check: the refresh route is POST (a refresh mutates state; `sameSite: 'lax'`
  sends cookies on top-level GET navigation, making a GET refresh CSRF-reachable)
  and rate limited by fingerprint or IP (user id is unknown until after validation).

### R14 User re-checked on every refresh [Tier 3] [GUIDE]
- Check: the refresh handler confirms the user still exists and is active.
  Refresh (~every 5 minutes) is the free revocation heartbeat.

---

## Client-side refresh (JS/TS; [STACK] unless noted)

### R15 Refresh handled once, in an interceptor or single wrapper [Tier 2]
- Check: no token logic, expiry math, or refresh timers scattered in components.

### R16 Separate instances: the refreshing client has no 401 handler [Tier 2]
- Check: the instance (or code path) that performs the refresh call does not
  itself retry on 401.
- Failure mode: a failed refresh triggers a refresh, recursing until the tab
  locks up.

### R17 Single-flight refresh [Tier 3; Tier 2 if rotation present]
- Check: concurrent 401s share one in-flight refresh promise; the slot is
  cleared in `.finally()`, not `.then()`.
- Failure modes: without single-flight plus rotation, refreshes 2..N replay a
  burned token, the server sees reuse, and the family is revoked (intermittent
  logout). Clearing in `.then()` leaves a rejected promise poisoning the slot
  forever after one network blip.

### R18 Recursion guard set before awaiting [Tier 2]
- Check: `_retry` (or equivalent) marked on the original request before the
  refresh is awaited, and the handler refuses already-marked requests.

### R19 `error.response?.status` uses optional chaining [Tier 3]
- Check: network failures have no `response`; unguarded access throws inside the
  error handler and replaces the real error.

### R20 403 is never treated as 401 [Tier 2] [STANDARD]
- Check: refresh triggers only on 401. 401 means unauthenticated (refresh may
  fix it); 403 means authenticated but forbidden (refresh never fixes it).
- Failure mode: a valid user clicking something they lack permission for gets
  bounced to login, sometimes in a loop.
- Cite: RFC 9110 Sections 15.5.2 and 15.5.4.

### R21 Interceptor returns the response, not `response.data` [Tier 4]
- Check: unwrapping in the interceptor makes runtime shape diverge from
  `Promise<AxiosResponse<T>>` types; unwrap in one typed endpoint wrapper if wanted.

### R22 Client caches cleared on every session exit [Tier 3]
- Check: query cache (react-query etc.) cleared on both sign-out AND expiry
  paths; wiring one and forgetting the other briefly shows the next user the
  previous user's data.

### R23 Session expiry navigates via app event, not `window.location` [Tier 4]
- Check: SPA emits a navigation event instead of a hard reload.
