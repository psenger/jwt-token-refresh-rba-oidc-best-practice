# Authentication Audit: fixture-python (FastAPI inventory service)

**Grade: F** - Multiple confirmed Tier 1 failures (T08 hardcoded fallback signing secret, T09 sub-256-bit key with no validation, T16 tokens without `exp` verify successfully); a deployment that omits `JWT_SECRET` boots silently and signs with a secret readable in the source, permitting token forgery.
Audit depth: standards-level (Python/FastAPI, not the JS/TS stack the pattern rules target)
Scope: JWT access-token minting/verification (python-jose, HS256), login handler, cookie-based token storage, auth dependency | Not present: refresh tokens, logout, RBA/step-up/OTP, password reset, OIDC/multi-service verification, client-side code

Because the stack is Python, this audit ran at standards depth. Stack-specific rule skipped as NOT-APPLICABLE: T06 (`crypto.createCipher`, Node-only). All other rules were audited on their underlying principle. The refresh (`rules-refresh.md`), RBA (`rules-rba.md`), and OIDC (`rules-oidc.md`) rule sets are entirely not applicable: those subsystems do not exist, and their absence in a single-service demo is not itself a defect.

## Scorecard

| Tier | Result | Failed rules |
|---|---|---|
| 1 - Forgery/theft | FAIL | T08, T09, T16 |
| 2 - Revocation | PASS | none (advisories: T10, T21) |
| 3 - Hardening | FAIL | T04 (advisory: T18) |
| 4 - Adaptive auth | 0 findings | - |

## Findings

### T08 Signing key from environment, no fallback default - FAIL (CONFIRMED) [Tier 1]

- Where: app/auth.py:6
- Evidence: `SECRET_KEY = os.environ.get("JWT_SECRET", "inventory-service-secret")`
- Failure scenario: A deployment where `JWT_SECRET` is unset (fresh environment, typo'd variable name, CI) boots successfully and signs every token with `"inventory-service-secret"`, a string visible to anyone with repo access. An attacker mints `{"sub": "1", "iss": "inventory.example", "aud": "inventory-web", ...}` signed with that string and `verify_access_token` accepts it; forgeries are indistinguishable from real tokens.
- Fix: read the key with no default and fail the boot:

  ```python
  SECRET_KEY = os.environ["JWT_SECRET"]  # KeyError at import time if missing
  ```

- Cite: RFC 8725 (key management); OWASP JWT Cheat Sheet.

### T16 Missing `exp` fails verification - FAIL (CONFIRMED) [Tier 1]

- Where: app/auth.py:27-33
- Evidence: `jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM], issuer=ISSUER, audience=AUDIENCE)` with no `options`.
- Traced library behavior (python-jose 3.3.0, `jose/jwt.py`): default options set `"require_exp": False`, and `_validate_exp` begins `if "exp" not in claims: return`. A signed token with no `exp` claim therefore verifies and never expires.
- Failure scenario: any party holding the signing key (including anyone exploiting the T08 default secret, or a leaked key prior to rotation) mints a token omitting `exp`; `require_auth` accepts it forever. The 15-minute TTL is enforced only by the minter's goodwill, not by the verifier.
- Fix: require the claim at verification:

  ```python
  jwt.decode(
      token, SECRET_KEY, algorithms=[ALGORITHM], issuer=ISSUER, audience=AUDIENCE,
      options={"require_exp": True, "require_iat": True, "require_sub": True},
  )
  ```

- Cite: RFC 7519 Section 4.1.4; a missing claim must fail, never default to pass.

### T09 HS256 key is at least 32 bytes - FAIL (CONFIRMED) [Tier 1]

- Where: app/auth.py:6-7
- Evidence: the fallback `"inventory-service-secret"` is 24 bytes, below the 256-bit minimum RFC 7518 requires for HS256, and there is no boot-time length validation of an env-supplied key nor a documented generation method (no `.env.example`, no README instruction such as `openssl rand -hex 32`).
- Failure scenario: an operator sets `JWT_SECRET=changeme`; the service signs with an 8-byte key that is brute-forceable offline from any single captured token, and nothing at startup objects.
- Fix: validate at import time:

  ```python
  SECRET_KEY = os.environ["JWT_SECRET"]
  if len(SECRET_KEY.encode()) < 32:
      raise RuntimeError("JWT_SECRET must be at least 32 bytes (openssl rand -hex 32)")
  ```

- Cite: RFC 7518 Section 3.2.

### T04 No raw database id in `sub` - FAIL (CONFIRMED) [Tier 3]

- Where: app/auth.py:16 (`"sub": str(user_id)`), fed from app/users.py:4 (`{"id": 1, ...}`), returned to clients at app/main.py:39 (`"owner": user["sub"]`)
- Evidence: `sub` carries the user table's sequential integer primary key, and `/api/items` echoes it back in the response body.
- Failure scenario: published sequential ids confirm account existence, leak user volume and signup ordering, and give an attacker a ready-made iteration space for IDOR probing against any future per-id endpoint. This rule is `[GUIDE]` lane, normally ADVISORY, but the rule's own verdict note escalates sequential integers to a FAIL-worthy enumeration risk.
- Fix: add a random public identifier (UUIDv4 column) per user and put that in `sub`; resolve it to the primary key server-side.
- Cite: source guide; OWASP (IDOR/enumeration guidance).

### T10 Keys validated at boot, not first use - ADVISORY [Tier 2, GUIDE]

- Where: app/auth.py:6
- Evidence: no startup validation; a missing key currently degrades to the fallback default rather than crashing.
- Tradeoff: the T08/T09 fixes above subsume this; noted separately so the boot-time placement (import time, not first request) is deliberate.

### T21 Auth applied structurally, not per route - ADVISORY [Tier 2, GUIDE]

- Where: app/main.py:38
- Evidence: `user: dict = Depends(require_auth)` attached to the single protected route individually.
- Tradeoff: fine at one route; as routes are added, each new handler must remember the dependency. FastAPI supports attaching it once at the router: `APIRouter(dependencies=[Depends(require_auth)])`, so new routes are protected by placement.

### T18 Clock-skew leeway applied in the correct direction - ADVISORY [Tier 3, GUIDE]

- Where: app/auth.py:27-33
- Evidence: python-jose defaults `"leeway": 0` and the decode call does not override it.
- Tradeoff: with multiple servers and real clock drift, tokens minted on one host can 401 unreproducibly on another for the first seconds of their life. Pass `options={"leeway": 30}` (or up to 60) alongside the T16 fix.

### Observations outside the rule catalog (auth-flow scope, no rule id)

- app/main.py:11: `async def login(response: Response, email: str, password: str)` declares bare scalars, which FastAPI binds as query parameters. Credentials arrive in the URL and land in access logs, proxy logs, and browser history. Accept them in a request body instead (Pydantic model or `Form(...)`).
- app/users.py:9-11: `bcrypt.verify` runs only when the email matches, so response timing distinguishes "unknown email" from "wrong password" despite the uniform 401 body, enabling account enumeration. Verify against a dummy hash when the email is not found.

## Cannot determine from code

- Is `JWT_SECRET` actually set (and to a >=32-byte random value) in every deployed environment? The code cannot show this; the T08 fallback makes the question urgent.
- Is there a key-rotation procedure? Nothing in the code supports multiple concurrent keys (no `kid` handling), so rotation currently invalidates all live tokens.
- Is the in-memory `_USERS` list a fixture stand-in for a real store? The audit assumed yes and did not grade persistence.
- Is TLS terminated in front of this service everywhere? `secure=True` on the cookie assumes HTTPS end to end.

## What is done well

- Algorithm pinned at verification: `algorithms=[ALGORITHM]` allowlist, so `alg: none` and algorithm-confusion attacks are closed (T13), and library verification gives correct operation order and constant-time comparison for free (T14, T15).
- `iss` and `aud` are both enforced at decode time (T17), which many single-service codebases skip.
- Cookie discipline is right: `httponly=True, secure=True, samesite="strict"` (T23), cookie `max_age` exactly matches the token TTL (T24), the token is never returned in a JSON body or touched by client-side storage (T22), and the login response sets `Cache-Control: no-store` (T26).
- 15-minute access TTL is an appropriately short window.
- Every verification failure collapses to one generic 401 "Authentication failed" (T19), and the auth dependency fails closed: `None` in, exception out, no path that proceeds unauthenticated (T20).
- Claim timestamps use integer epoch seconds (`int(time.time())`), so there is no seconds/milliseconds confusion (T27).
- Passwords are stored and checked with bcrypt rather than a fast hash.

The cookie and verification hygiene shows real care. The failures are concentrated in key management and one library default; the three Tier 1 fixes are together about ten lines, and applying them (plus re-running T08, T09, T16) would move this codebase to a B, with only the Tier 3 `sub` finding remaining.
