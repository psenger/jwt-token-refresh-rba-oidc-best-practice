# Rule Set: Risk-Based Authentication, OTP, and Password Reset

Load this file only when the codebase implements step-up authentication, device
fingerprinting, OTP verification, or password reset. If none of these exist,
report the whole set as NOT-APPLICABLE (absence of RBA is not a failure; it is
Tier 4 by the source guide's own priority order). Lane markers as in rules-tokens.md.

---

## Device fingerprinting

### A01 Fingerprint is salted (HMAC), not a plain hash [Tier 4] [GUIDE]
- Check: `createHmac('sha256', SALT)` over the material, salt from env.
- Failure mode: unsalted, anyone can precompute the fingerprint for a given
  user-agent and IP from public information.

### A02 Attacker-controlled header inputs are length-capped [Tier 3] [GUIDE]
- Check: user-agent and language substrings capped before hashing (a user-agent
  header can be megabytes).

### A03 Fingerprint scheme carries a version prefix [Tier 4] [GUIDE]
- Check: a `v1`-style tag in the material so inputs can migrate without silent
  mass mis-recognition.

### A04 IP inclusion is a deliberate, recorded choice [Tier 4] [GUIDE]
- Check: raw IP in the fingerprint logs mobile users out on every wifi/cellular
  switch. Acceptable answers: drop IP, coarsen to /24 or ASN, or a comment
  accepting the friction.

### A05 Only the hash is stored, never raw components [Tier 3] [GUIDE]
- Check: the device history stores the digest; a leaked table must be worthless.

### A06 Device history is capped [Tier 4] [GUIDE]
- Check: bounded list (~10) with least-recently-seen eviction; fingerprints decay
  as browsers update, so unbounded lists grow forever.

### A07 Devices enrolled only on proof of identity [Tier 3] [GUIDE]
- Check: enrollment happens on successful login AND successful password-reset
  completion, never on mere attempts.
- Failure modes: enroll-on-attempt lets an attacker visit once and return as a
  "known device"; skipping reset-completion enrollment leaves that user
  permanently high-risk.

### A08 Fingerprint binding is actually compared [Tier 3] [GUIDE]
- Check: wherever a session or token stores a fingerprint, some code path
  compares it and destroys the session on mismatch. An unchecked check is worse
  than no check: it is decoration that reads as protection.

---

## Risk scoring

### A09 High risk steps up, never blocks [Tier 4] [GUIDE]
- Check: the worst score demands more proof; there is no hard "denied" state.
  A high score is uncertainty, not an accusation.

### A10 Factor weights live in one named table [Tier 4] [GUIDE]
- Check: named factors with point values in one frozen structure; logs show
  factor names, not bare numbers.

### A11 Assessors are pure and tested on their numbers [Tier 4] [GUIDE]
- Check: scoring functions take data and return score plus factors (no DB, no
  req); tests assert the numeric score and factor list, not just "a token came
  back".

### A12 Unknown states score as risky, not safe [Tier 3] [GUIDE]
- Check: the default/unknown branch of device classification returns NEW-device
  points, not zero. An unknown is not evidence of safety.

### A13 Stored-date guards against NaN [Tier 4] [STACK]
- Check: `isNaN(date.getTime())` guard on stored last-seen dates; every NaN
  comparison is false, silently falling through to the wrong branch.

### A14 Every field the risk logic reads is in the query projection [Tier 3] [STACK]
- Check: if the user query uses `select`/projection, confirm it includes every
  field the risk code reads (`confirmedMobile` etc.). A missing field is
  `undefined`, `undefined === true` is false, and a whole step-up path silently
  disappears. Unit tests with full mocks cannot catch this; an integration test
  with the real query can.

### A15 Required factors degrade to what the user has [Tier 3] [GUIDE]
- Check: demanding an unenrolled factor (SMS for a user with no phone) permanently
  locks them out; the mapping must fall back to an available factor.

---

## Factor strength

### A16 SMS is not treated as a strong factor [Tier 3] [STANDARD]
- Check: preference order is WebAuthn/passkey, then TOTP, then push, then SMS
  last. NIST SP 800-63B-4 designates PSTN out-of-band (SMS and voice) restricted;
  OWASP MFA cheat sheet says migrate off SMS for high value.
- Cite: NIST SP 800-63B-4 Sections 3.1.3.3, 3.2.9; OWASP MFA Cheat Sheet.

### A17 Email is not an out-of-band authenticator [Tier 3] [STANDARD]
- Check: email OTP may add friction and audit trail but must not be counted as
  proof of device possession.
- Cite: NIST SP 800-63B-4 Section 3.1.3.1 ("Email SHALL NOT be used").

---

## OTP handling

### A18 OTPs compared in constant time [Tier 2] [GUIDE]
- Check: `crypto.timingSafeEqual` with a length guard, for OTPs and any
  hand-compared secret (reset tokens, webhook signatures, API keys).
- Failure mode: a timing oracle turns "guess the 6-digit code" (1M) into
  "guess each digit" (~60).

### A19 OTP attempts limited per factor, session destroyed on exhaustion [Tier 2] [STANDARD]
- Check: a small attempt cap (guide uses 3; NIST's outer bound is 100), counted
  per factor so email guesses do not consume the SMS budget.
- Cite: NIST SP 800-63B-4 (throttling); OWASP Authentication Cheat Sheet.

### A20 OTPs are never logged [Tier 2] [STANDARD]
- Check: risk decisions are logged (user, score, level, factor names, device
  status), but the OTP value never appears in logs, traces, or error reports.

### A21 OTPs are actually sent [Tier 2] [GUIDE]
- Check: an email/SMS dispatch call or event emission exists and is wired to a
  sender; generating, storing, and returning `nextStep` is not sending. Flag
  CANNOT-DETERMINE if the sender is external and unverifiable from code.

### A22 OTP override env vars cannot reach production [Tier 1 when present] [GUIDE]
- Check: any `AUTH_OTP_OVERRIDE`-style dev backdoor refuses to boot when
  `NODE_ENV === 'production'`.
- Failure mode: a convenient dev master key to every account.

---

## Account enumeration

### A23 Responses identical for existing and non-existing accounts [Tier 2] [STANDARD]
- Check three channels, all of them:
  - Message: "If an account exists..." wording regardless of existence.
  - Behavior: unknown emails proceed through the same flow shape (and are never
    routed to a step demanding a factor a non-existent user cannot have; that
    demand is itself a giveaway).
  - Timing: response time normalized to a floor (~500ms) in a `finally`, so the
    5ms failed-lookup path matches the ~100ms bcrypt path.
- Cite: OWASP Forgot Password Cheat Sheet (consistent message AND time).

---

## Password reset

### A24 Reset token is opaque, short-lived, single-use [Tier 2] [STANDARD]
- Check: random bytes (not a JWT), server-side store with TTL (~30 min),
  deleted in a `finally` so it is consumed even on a thrown error, delivered in
  an httpOnly cookie or URL per flow, path-scoped if a cookie.
- Cite: OWASP Forgot Password Cheat Sheet.

### A25 Reset completion revokes all sessions and does NOT auto-login [Tier 2] [STANDARD]
- Check: completing a reset revokes every token family (the account was likely
  compromised) and sends the user to the login page. Auto-login after reset is a
  second front door that bypasses login rate limiting, lockout, risk checks, and
  audit.
- Cite: OWASP Forgot Password Cheat Sheet.

### A26 TTL constant names match their units and values [Tier 3] [GUIDE]
- Check: `...Ms` names hold milliseconds, `...Seconds` hold seconds;
  `sessionTimeToLiveMs = 1800` is a landmine.

### A27 Risk decisions are logged with factors [Tier 3] [GUIDE]
- Check: userId, score, level, factor names, device status, required
  verifications; without it nobody can answer "why was this user stepped up"
  or tune thresholds. (Never the OTP; see A20.)

### A28 Thresholds tuned with shadow mode first [Tier 4] [GUIDE]
- Check: evidence (config flag, doc) that scoring ran log-only before enforcing.
  Usually CANNOT-DETERMINE from code; ask, do not fail.
