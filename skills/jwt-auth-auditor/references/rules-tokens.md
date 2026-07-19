# Rule Set: Token Minting, Verification, Storage, and Secrets

Load this file whenever the audited codebase mints or verifies JWTs, sets session
cookies, or holds signing/encryption keys. Rule IDs are stable; cite them in findings.

Lane markers: `[STANDARD]` backed by an RFC/OWASP/NIST requirement, may FAIL.
`[GUIDE]` stricter-than-standard opinion from the source guide, ADVISORY only.
`[STACK]` concrete Node/Express/React/axios pattern, apply only when the stack matches.

---

## Payload hygiene

### T01 No secrets or credentials in the payload [Tier 1] [STANDARD]
- Check: no passwords, API keys, card numbers, or session secrets in any claim.
- Evidence: the object passed to the sign/mint call.
- Failure mode: JWT payloads are base64url, world-readable; signed is not secret.
- Cite: RFC 8725; OWASP JWT Cheat Sheet.

### T02 No PII in the payload [Tier 2] [STANDARD]
- Check: no email, phone, legal name, or address claims.
- Failure mode: a token in a log file is a data leak.
- Cite: OWASP JWT Cheat Sheet.

### T03 Roles-in-token decision is deliberate [Tier 3] [GUIDE]
- Check: if roles/permissions are claims, the access TTL bounds the staleness window
  and a comment or doc records the tradeoff. If roles are looked up per request,
  that is also a pass.
- Failure mode: roles in a long-lived token survive privilege downgrade; an
  undocumented per-request lookup gets "optimized" into the token later,
  silently breaking revocation.

### T04 No raw database id in `sub` [Tier 3] [GUIDE]
- Check: `sub` carries an encrypted value or a separate random public id
  (UUIDv4 column), never the primary key. Sequential ids and Mongo ObjectIds
  (embedded timestamp, semi-monotonic) are worse than they look.
- Failure mode: published primary keys confirm record existence, leak volume and
  ordering, and seed IDOR probing.
- Verdict note: many production systems ship raw ids; report as ADVISORY unless
  ids are sequential integers, which upgrades it to a FAIL-worthy enumeration risk.

### T05 Id encryption uses AEAD with a fresh nonce [Tier 1 when present] [STANDARD]
- Check: if ids (or anything) are symmetrically encrypted: `aes-256-gcm` (or another
  AEAD), `crypto.randomBytes(12)` IV per call, IV and auth tag packed with the
  ciphertext, decrypt lets the auth-tag throw propagate.
- Failure modes: constant or derived nonce with GCM leaks the auth subkey and
  enables tag forgery (catastrophic, not degraded). Deterministic encryption makes
  ciphertext a stable pseudonym correlatable across logs. Bare CBC is malleable.
- Cite: NIST SP 800-38D (IV uniqueness).

### T06 `crypto.createCipher` never appears [Tier 1] [STACK]
- Check: grep for `createCipher(` (without `iv`). It takes no IV, uses a weak KDF,
  and is removed in Node 22 (DEP0106).
- Verdict: any occurrence is a CONFIRMED FAIL.

### T07 Access and refresh tokens are distinguishable [Tier 1] [STANDARD]
- Check: a type claim (payload `typ` / `token_use`) or separate signing keys per
  token type, enforced on every verify.
- Failure mode: with one key and no type check, a refresh token IS a valid access
  token; the long-lived guarded credential becomes a long-lived API pass.
- Cite: RFC 8725 Section 3.11 (explicit typing).

---

## Signing and keys

### T08 Signing key from environment, no fallback default [Tier 1] [STANDARD]
- Check: key read from env/secret manager; grep for `||` fallbacks next to the
  env read (`process.env.X || 'dev-secret'`) and for hardcoded key literals.
- Failure mode: a misconfigured prod deploy boots successfully and signs every
  token with a string from a public repo; forgeries are indistinguishable.
- Verdict: any fallback default on a signing key is a CONFIRMED Tier 1 FAIL.

### T09 HS256 key is at least 32 bytes [Tier 1] [STANDARD]
- Check: boot-time validation of key length, or a documented generation method
  (`openssl rand -hex 32`). RFC 7518 requires HS256 keys >= 256 bits.
- Cite: RFC 7518 Section 3.2.

### T10 Keys validated at boot, not first use [Tier 2] [GUIDE]
- Check: missing or short keys crash the process at startup with a clear error.
- Failure mode: `exp: NaN` or an unsigned-ish token at 3am instead of a failed deploy.

### T11 Signing and encryption keys are distinct [Tier 3] [GUIDE]
- Check: if ids are encrypted (T05), the encryption key differs from the signing key.
- Failure mode: one leak costs both properties; keys can never rotate independently.

### T12 HS256 vs RS256 matches the topology [Tier 2] [STANDARD]
- Check: single service signing and verifying may use HS256. The moment more than
  one service verifies, see rules O01-O04 in rules-oidc.md.
- Failure mode: a shared HS256 secret makes every holder a token factory.

---

## Verification (the highest-stakes function)

### T13 Algorithm pinned to a constant [Tier 1] [STANDARD]
- Check: the verifier compares `alg` to a hardcoded expected value (or passes an
  `algorithms: [...]` allowlist to the library). Never dispatches on the token's
  own header. `alg: none` and RS256-public-key-as-HMAC-secret confusion both
  hinge on this.
- Evidence: the exact verify call and its options; for hand-rolled code, the
  comparison line.
- Cite: RFC 8725 Sections 3.1-3.2.
- Verdict: reading `alg` from the token to choose the algorithm is a CONFIRMED
  Tier 1 FAIL.

### T14 Claims checked only after signature verifies [Tier 1] [STANDARD]
- Check: order of operations in the verifier. Structure, algorithm, signature,
  then claims. Libraries do this; hand-rolled code must be traced.
- Failure mode: trusting an attacker's arithmetic.

### T15 Signature comparison is constant time [Tier 2] [GUIDE]
- Check: hand-rolled verifiers use `crypto.timingSafeEqual` (with a length guard,
  it throws on mismatched lengths). Library verifiers pass automatically.
- Failure mode: `!==` short-circuits; timing oracles are realistic on shared
  hosts and local networks.

### T16 Missing `exp` fails verification [Tier 1] [STANDARD]
- Check: the expiry check validates `typeof exp === 'number'` before comparing,
  or the library is configured to require `exp`.
- Failure mode: `now >= undefined` is false; a token with no expiry reads as
  never-expired. A missing claim must fail, never default to pass.
- Cite: RFC 7519 Section 4.1.4.

### T17 `iss` and `aud` are checked [Tier 2] [STANDARD]
- Check: verifier enforces expected issuer and audience.
- Cite: RFC 8725 Section 3.8; RFC 9700.

### T18 Clock-skew leeway applied in the correct direction [Tier 3] [GUIDE]
- Check: leeway is added to `exp` and subtracted from `nbf` (or the library's
  `clockTolerance` is used). 30-60 seconds typical.
- Failure mode: reversed signs silently shorten or extend every token's life;
  no leeway produces unreproducible 401s across servers with clock drift.

### T19 One generic error for every verification failure [Tier 3] [GUIDE]
- Check: expired, malformed, bad signature, and missing all map to the same 401.
- Failure mode: "expired" vs "bad signature" is a free oracle for probing.

### T20 Auth middleware fails closed [Tier 1] [STANDARD]
- Check: every non-success path in the auth middleware rejects; no catch block
  that logs and calls `next()` without an error.
- Evidence: the middleware's catch and early-return paths, quoted.

### T21 Auth applied structurally, not per route [Tier 2] [GUIDE]
- Check: protection attaches at a route-tree root (router-level middleware,
  directory convention) so new routes are protected by placement.
- Failure mode: auth you must remember to apply is auth you will forget to apply.

---

## Storage and cookies

### T22 Tokens never in localStorage or sessionStorage [Tier 1] [STANDARD]
- Check: grep client code for `localStorage`/`sessionStorage` with token-ish keys,
  and for tokens returned in JSON response bodies to be stored by JS.
- Failure mode: any XSS, hostile dependency, or extension exfiltrates the token
  for use from another machine. httpOnly cookies turn that breach into an incident.
- Cite: OWASP Session Management Cheat Sheet (categorical); note the OWASP JWT
  sheet is more permissive, the guide deliberately follows Session Management.
- Verdict: session token in localStorage is a CONFIRMED Tier 1 FAIL.

### T23 Cookie flags: httpOnly, secure, sameSite [Tier 1] [STANDARD]
- Check: every session cookie sets `httpOnly: true`, `secure: true`, and
  `sameSite: 'strict'` or `'lax'`. `sameSite: 'none'` requires documented
  cross-site need plus CSRF tokens.
- Cite: OWASP Session Management Cheat Sheet; RFC 6265.

### T24 Cookie lifetime never exceeds token lifetime [Tier 3] [STANDARD]
- Check: cookie `expires`/`maxAge` derived from the token's `exp`. Watch the
  seconds-vs-milliseconds boundary: JWT `exp` is seconds, `Date` and Express
  `maxAge` want milliseconds.
- Cite: OWASP JWT Cheat Sheet.

### T25 Refresh cookie path-scoped to the refresh endpoint [Tier 3] [GUIDE]
- Check: the refresh token cookie's `path` is the refresh route, not `/`.
- Payoff: the longest-lived credential appears on the wire only during refresh;
  proxies, APM, and error trackers never see it.

### T26 `Cache-Control: no-store` on token-issuing responses [Tier 3] [STANDARD]
- Check: login, refresh, and any Set-Cookie-bearing auth response sets it.
- Failure mode: a cached login response is a token on a shared proxy's disk.
- Cite: OWASP Session Management Cheat Sheet.

### T27 NumericDate seconds handled correctly [Tier 2] [STANDARD]
- Check: claim math uses `Math.floor(Date.now() / 1000)`; conversions to `Date`
  multiply by 1000. The single most common JWT bug.
- Cite: RFC 7519 Section 2 (NumericDate).

---

## Secrets files

### S01 `.env` gitignored, `.env.example` has placeholders only [Tier 1] [STANDARD]
- Check: `.gitignore` covers `.env` and `.env.*` (with `!.env.example`);
  `.env.example` values are placeholders like `replace-me-openssl-rand-hex-32`.
  Also scan git history superficially: if a real key was ever committed, flag it.
- Failure mode: reviewers skim `.env.example` as docs; a real key there is public.

### S02 Configured TTLs are actually read by minting code [Tier 2] [GUIDE]
- Check: trace the TTL env var from `process.env` to the `exp` claim. It is
  common for a codebase to validate and export a TTL that nothing uses.
- Suggested fix: a test asserting minted `exp` matches configured TTL.
