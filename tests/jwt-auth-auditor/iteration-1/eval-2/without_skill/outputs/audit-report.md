# JWT Handling Audit: fixture-python (FastAPI Inventory Service)

**Date:** 2026-07-19
**Scope:** `/app/auth.py`, `/app/main.py`, `/app/users.py`, `requirements.txt`
**Stack:** FastAPI 0.111.0, python-jose 3.3.0 (HS256), passlib 1.7.4 (bcrypt), cookie-based token transport

## Grade: C+

The core token mint/verify logic is done correctly (pinned algorithm, issuer/audience/expiry validation, short TTL, hardened cookie). The grade is pulled down by a hardcoded fallback signing secret, login credentials bound as URL query parameters, and reliance on an unmaintained JWT library with known CVEs.

---

## Findings

### Critical

#### C1. Hardcoded fallback JWT signing secret
`app/auth.py`, line 6:

```python
SECRET_KEY = os.environ.get("JWT_SECRET", "inventory-service-secret")
```

If `JWT_SECRET` is unset in the deployment environment, the service silently signs and verifies tokens with a secret that is published in source control. Anyone with repo access (or who guesses the string) can forge a valid token for any `sub` and pass `verify_access_token`, fully bypassing authentication. This failure mode is silent: the service starts and works normally, so a missing env var in one environment is easy to miss.

**Fix:** Fail closed at startup:

```python
SECRET_KEY = os.environ["JWT_SECRET"]  # raise if missing
```

Additionally enforce minimum entropy (e.g. reject secrets shorter than 32 bytes), since HS256 with a weak secret is offline-brute-forceable from any captured token.

### High

#### H1. Login credentials are query parameters
`app/main.py`, line 11:

```python
@app.post("/api/login")
async def login(response: Response, email: str, password: str):
```

In FastAPI, scalar parameters that are not path parameters default to **query** parameters, even on a POST. The plaintext password therefore travels in the URL (`/api/login?email=...&password=...`) and will be captured by access logs, reverse proxies, load balancers, browser history, and any APM/tracing that records request URLs.

**Fix:** Accept credentials in the request body, e.g. a Pydantic model or `OAuth2PasswordRequestForm`:

```python
class LoginRequest(BaseModel):
    email: str
    password: str

@app.post("/api/login")
async def login(response: Response, body: LoginRequest): ...
```

#### H2. Vulnerable / unmaintained JWT library (python-jose 3.3.0)
`requirements.txt`, line 3. python-jose 3.3.0 is affected by:

- **CVE-2024-33663**: algorithm-confusion issue with ECDSA keys. Not directly exploitable here because `algorithms=["HS256"]` is pinned and the key is symmetric, but it signals the library's security posture.
- **CVE-2024-33664**: denial of service via decompression of crafted JWE content.

The project was effectively unmaintained for years (fixes landed in 3.4.x after a long gap). Similarly, passlib 1.7.4 is unmaintained and breaks with bcrypt >= 4.1 (the unpinned `bcrypt` backend can make hashing fail at runtime).

**Fix:** Migrate to **PyJWT** (actively maintained, minimal surface) or at minimum upgrade to python-jose >= 3.4.0. For password hashing, use the `bcrypt` package directly or pin a compatible backend version.

### Medium

#### M1. No revocation or logout capability
Tokens are stateless with no `jti` claim, there is no logout endpoint, and no denylist/session store. A stolen token remains valid for its full 15-minute window and there is no way to invalidate tokens after a password change or compromise. The 15-minute TTL bounds the exposure, which is why this is medium rather than high, but there is no server-side kill switch at all.

**Fix:** Add a `jti` claim and a short-lived denylist (or a per-user token-version claim checked against the user record), plus a logout endpoint that clears the cookie and revokes the token.

#### M2. No refresh strategy
With only a 15-minute access token and no refresh token, users are silently logged out every 15 minutes (or teams respond by lengthening the access TTL, which is worse). There is no rotation, so there is also no reuse-detection signal.

**Fix:** Issue an opaque, server-stored refresh token (separate httponly cookie scoped to the refresh path) with rotation and reuse detection, keeping the access token short-lived.

#### M3. User enumeration via timing at login
`app/users.py`, lines 8-12: `bcrypt.verify` only runs when the email matches, so requests for nonexistent emails return in microseconds while real emails cost a full bcrypt verification (tens to hundreds of milliseconds). An attacker can enumerate valid accounts by timing. The generic 401 message is good, but the timing channel undoes it.

**Fix:** Verify against a dummy bcrypt hash when the user is not found, so both paths cost one bcrypt verification.

#### M4. No brute-force protection on login
There is no rate limiting, lockout, or credential-stuffing defense on `/api/login`. Combined with M3 this makes online password guessing practical.

**Fix:** Add per-IP and per-account rate limiting (middleware or gateway level).

### Low

#### L1. Cookie hardening could go further
The cookie sets `httponly`, `secure`, and `samesite=strict`, which is good. Two incremental improvements: use the `__Host-` name prefix (locks the cookie to this host, no subdomain override, forces `Secure` and `Path=/`), and set an explicit `path`.

#### L2. Missing `nbf` and `jti` claims
`nbf` is minor; `jti` matters as the prerequisite for revocation (see M1) and for log correlation.

#### L3. Error handling collapses all failures to `None`
`verify_access_token` swallows every `JWTError` identically. The client-facing response should stay generic (it does), but internally distinguishing expiry from signature failure and logging signature failures would surface forgery attempts. Low severity, observability rather than exploitability.

---

## What the service gets right

- **Algorithm pinned on verify** (`algorithms=["HS256"]`), preventing `alg` confusion and `none` acceptance.
- **Issuer and audience validated** on decode; both set on mint.
- **Short access-token TTL** (15 minutes) with `iat`/`exp` set from a single timestamp.
- **Token transported in an httponly, secure, SameSite=Strict cookie**, not localStorage, so XSS cannot read it and CSRF is largely mitigated.
- **Generic 401 messages** for both bad credentials and bad tokens (no oracle in the response body).
- **`Cache-Control: no-store`** on the login response.
- **bcrypt for password storage**, not a fast hash.
- Dependency confined to `Depends(require_auth)`, keeping the auth boundary in one place.

---

## Scorecard

| Category | Assessment |
|---|---|
| Signing key management | Fail (hardcoded fallback) |
| Algorithm handling | Pass |
| Claim validation (iss/aud/exp) | Pass |
| Token transport | Pass (cookie flags good; minor hardening left) |
| Credential handling at login | Fail (query params); bcrypt storage is good |
| Revocation / logout | Missing |
| Refresh strategy | Missing |
| Dependency hygiene | Fail (python-jose 3.3.0, passlib 1.7.4) |
| Abuse resistance (rate limit, enumeration) | Missing |

## Remediation priority

1. Remove the fallback secret; fail at startup without `JWT_SECRET` (C1).
2. Move login credentials into the request body (H1).
3. Replace python-jose with PyJWT; fix the passlib/bcrypt pin (H2).
4. Add logout plus a revocation mechanism with `jti` (M1, L2).
5. Add refresh-token rotation (M2).
6. Equalize login timing and add rate limiting (M3, M4).
