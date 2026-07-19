---
name: jwt-auth-auditor
description: Audit a codebase's JWT, refresh token, session cookie, risk-based authentication, and OIDC implementation against RFC 8725, RFC 9700, OWASP cheat sheets, and NIST SP 800-63B-4, producing a tiered scorecard with evidence-backed findings and concrete fixes. Use when the user asks to audit, review, grade, or harden authentication, sessions, JWTs, refresh tokens, login flows, token storage, password reset, or OIDC integration. Make sure to use this skill whenever the user requests a security assessment of authentication or session code, even if they never say the word JWT.
license: MIT
metadata:
  author: Philip A Senger
  source: https://github.com/psenger/jwt-token-refresh-rba-oidc-best-practice
---

# JWT Auth Auditor

Audit the authentication implementation of the codebase the user owns and is asking
you to assess. This is a defensive review of the user's own code: the goal is to find
weaknesses so the owner can fix them, and every finding must come with a suggested fix.

The rule set distills a field guide to JWT access/refresh tokens, cookie storage,
rotation with reuse detection, risk-based step-up authentication, and OIDC, aligned
to RFC 8725 (JWT BCP), RFC 9700 (OAuth 2.0 Security BCP), the OWASP cheat sheets
(Session Management, JWT, Forgot Password, MFA), and NIST SP 800-63B-4.

## Why the process below is strict about evidence

Most published security-audit skills produce noise: they pattern-match a checklist
and report plausible-sounding findings that fall apart on inspection. The reviews
that hold up share three habits, and this skill requires all three: trace the actual
code path before flagging (find the real verify call, the real rotation logic, not a
suspicious filename), classify every finding by confidence, and know when a rule
does not apply. A wrong CONFIRMED destroys the report's credibility; when in doubt,
downgrade to PLAUSIBLE and say what evidence would settle it.

## Workflow

### Phase 0: Recon

Map the auth surface before judging anything:

1. Identify the stack (languages, frameworks, auth libraries). Read `package.json`
   or the equivalent manifest.
2. Locate: token minting, token verification, auth middleware, login/logout
   handlers, refresh endpoint, cookie configuration, client-side token handling
   (interceptors, fetch wrappers), password reset, OTP/step-up code, secrets
   loading, `.env.example` and `.gitignore`.
3. Record what does NOT exist (no refresh tokens, no RBA, no multi-service
   verification). Absent subsystems make whole rule files not-applicable; absence
   of an optional subsystem is not a defect.

If the codebase has no authentication code at all, say so and stop; do not audit
imports of someone else's IdP SDK as if the user had written an auth system.

### Phase 1: Load the applicable rule sets

Read the reference files whose subject matter exists in the codebase:

- `references/rules-tokens.md` - minting, verification, storage, cookies, secrets.
  Load this whenever any JWT or session cookie exists.
- `references/rules-refresh.md` - refresh lifecycle, rotation, reuse detection,
  client refresh logic. Load when refresh tokens or client interceptors exist.
- `references/rules-rba.md` - step-up auth, device fingerprinting, OTP, password
  reset. Load when any of those exist.
- `references/rules-oidc.md` - multi-service verification, JWKS, external IdP,
  gateways. Load when more than one service verifies tokens or an IdP/gateway
  is integrated.

### Phase 2: Gather evidence per rule

For each applicable rule, find the code that satisfies or violates it and record
`file:line`. Rules distinguish three lanes, marked on every rule:

- `[STANDARD]`: backed by an RFC, OWASP, or NIST requirement. May FAIL.
- `[GUIDE]`: the source guide's opinion, stricter than or beyond the standards
  (e.g. jti allowlist rather than OWASP's denylist, 3 OTP attempts rather than
  NIST's 100). Never FAIL a codebase for a compliant alternative; report as
  ADVISORY with the reasoning.
- `[STACK]`: a concrete Node/Express/React/axios pattern. Apply only when the
  stack matches; for other stacks, audit the underlying principle if it
  translates, otherwise mark NOT-APPLICABLE.

For non-JS/TS codebases, say plainly in the report that the audit ran at
standards depth, not pattern depth, and which rules were skipped for that reason.

### Phase 3: Verdicts

Every applicable rule gets exactly one verdict:

- **PASS**: evidence found that the rule is satisfied.
- **FAIL (CONFIRMED)**: you traced the code path and can quote the defect. The
  failure scenario must be concrete: input/state, then wrong outcome.
- **FAIL (PLAUSIBLE)**: strong indication but an unverified assumption remains.
  Name the assumption.
- **ADVISORY**: a `[GUIDE]`-lane deviation, or a `[STANDARD]` rule where the code
  chose a defensible alternative. Explain the tradeoff, do not scold.
- **NOT-APPLICABLE**: the subsystem does not exist, or the rule is stack-specific
  and the stack differs.
- **CANNOT-DETERMINE**: the rule depends on runtime or operational behavior
  invisible in code (shadow-mode tuning, whether OTP email actually delivers,
  key handling in the deploy pipeline). List these as questions for the team,
  never as failures.

Before finalizing any FAIL (CONFIRMED), re-read the evidence adversarially: search
the rest of the repo for a compensating control (the check may live in middleware,
a proxy config, or the framework's defaults) and confirm the code path is actually
reachable. Framework awareness matters: a library verify call passes T13-T18 as a
group; do not demand hand-rolled constant-time comparison from someone correctly
using `jose` or `jsonwebtoken` with pinned algorithms.

### Phase 4: Grade and report

Rules carry priority tiers from the source guide's build order:

- **Tier 1** - forgery or theft enabling: httpOnly cookie storage, algorithm
  pinning, short access TTL, secrets from env with no fallback defaults, and
  peers marked Tier 1.
- **Tier 2** - revocation integrity: store-backed refresh validation, fail-closed
  checks, server-side logout, revocation on password change, single-flight
  (when rotating), and peers.
- **Tier 3** - hardening: rotation with reuse detection, path-scoped refresh
  cookie, rate limiting, and peers.
- **Tier 4** - judgement calls: device binding, RBA, architecture advisories.

Letter grade from the lowest failing tier (count only FAIL verdicts; ADVISORY and
CANNOT-DETERMINE never lower the grade):

| Grade | Meaning |
|---|---|
| A | Tiers 1-3 pass; at most Tier 4 findings |
| B | Tiers 1-2 pass; Tier 3 failures |
| C | Tier 1 passes; Tier 2 failures |
| D | Any single Tier 1 failure |
| F | Multiple Tier 1 failures, or any finding that permits token forgery or silent account takeover today |

A PLAUSIBLE Tier 1 failure caps the grade at C and must appear in the summary with
what would confirm it.

## Report structure

ALWAYS use this exact template:

```markdown
# Authentication Audit: <project name>

**Grade: <A-F>** - <one-sentence justification naming the lowest failing tier>
Audit depth: <pattern-level (JS/TS) | standards-level (other stack)>
Scope: <subsystems found> | Not present: <subsystems absent>

## Scorecard
| Tier | Result | Failed rules |
|---|---|---|
| 1 - Forgery/theft | PASS/FAIL | ... |
| 2 - Revocation | PASS/FAIL | ... |
| 3 - Hardening | PASS/FAIL | ... |
| 4 - Adaptive auth | n findings | ... |

## Findings
<one block per FAIL/ADVISORY, ordered by tier then confidence>
### <rule id> <rule title> - <FAIL (CONFIRMED|PLAUSIBLE) | ADVISORY> [Tier n]
- Where: <file:line>
- Evidence: <quoted code, trimmed>
- Failure scenario: <concrete input/state, then wrong outcome>
- Fix: <specific change, with code when short>
- Cite: <RFC/OWASP/NIST reference from the rule>

## Cannot determine from code
<bulleted questions for the team>

## What is done well
<brief; genuine passes worth keeping, so the report is calibrated, not a scold>
```

Order findings most severe first. If the user asks you to fix the findings, fix
CONFIRMED findings first and re-run the affected rule checks afterward; never
apply fixes for PLAUSIBLE findings without confirming them.

## Boundaries

- Audit only code the user owns or is authorized to assess; this skill is for
  defensive review, not for locating exploitable targets in third-party systems.
- Do not fabricate line numbers or evidence. A finding you cannot anchor to a
  file does not go in the report.
- Do not report generic non-auth issues (DoS, dependency CVEs, input validation
  outside auth flows); other tools cover those, and scope discipline is what
  keeps this report readable.
