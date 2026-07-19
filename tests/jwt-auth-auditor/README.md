# jwt-auth-auditor evaluation harness

Test fixtures and recorded evaluation runs for the `jwt-auth-auditor` skill
(`../../skills/jwt-auth-auditor`). This directory is the evidence that the skill
finds real defects, stays quiet on correct code, and does not fabricate findings.

## Layout

```
tests/jwt-auth-auditor/
├── evals/evals.json          3 test prompts + expected outcomes
├── fixtures/                 3 codebases to audit
│   ├── fixture-flawed/       Node/Express + React, hand-rolled JWT, 6 seeded defects
│   ├── fixture-solid/        Node/Express + jose + Redis rotation, meant to score high
│   └── fixture-python/       FastAPI + python-jose, a deliberately off-target stack
└── iteration-1/
    ├── benchmark.json        aggregate results and conclusions
    └── eval-<n>/
        ├── eval_metadata.json         prompt + assertions for this case
        ├── with_skill/outputs/        report produced following the skill
        ├── without_skill/outputs/     baseline report, no skill (control)
        ├── */grading.json             assertion pass/fail with evidence
        └── */timing.json              tokens and wall-clock
```

## What each fixture tests

- **fixture-flawed** measures detection. Six defects are seeded: algorithm taken
  from the token header including an `alg:none` bypass, a hardcoded fallback
  signing secret, a missing-`exp` token that passes verification, a token in
  `localStorage`, a 24-hour access TTL with no refresh, and a client-only logout.
- **fixture-solid** measures false-positive discipline. It uses an OWASP-style
  `jti` denylist (not the source guide's allowlist) specifically to check the
  skill does not fault a compliant alternative. It should grade high.
- **fixture-python** measures cross-stack honesty. The skill's code patterns are
  Node/JS; on Python it must say it audited at standards depth and must not
  report axios/Node rules as failures against Python.

## How iteration-1 was run

Each fixture was audited twice with model `claude-fable-5`: once by an agent
following the skill (`with_skill/`) and once by an agent with no skill
(`without_skill/`, the control). Reports were graded against the per-case
assertions; see `iteration-1/benchmark.json` for the aggregate.

## Headline results

All 16 valid with-skill assertions passed, with zero confirmed false positives
and zero fabricated file paths. The skill's advantage over an already-strong
baseline is structure and reproducibility (tier-based grade, stable rule ids,
standards citations, honest cross-stack depth labeling), not raw detection.

Two things surfaced that fed back into the code:

1. **fixture-solid contained an unintended real bug** the auditor caught: the
   password-change handler revoked only the presented cookie's token family, so
   sessions from other logins survived. It has since been fixed (per-user
   revocation watermark) so the fixture is a clean high-scoring control. The
   `iteration-1` reports were produced against the pre-fix fixture and are kept
   as-is; a future `iteration-2/` should re-run against the fixed fixture and
   expect an A or B.
2. The skill excluded the `python-jose` known CVEs by its no-dependency-CVE
   scope rule; the baseline reported them. Whether to allow findings against the
   auth library itself is an open tuning question noted in the benchmark.

## Reproducing

Point an agent at a fixture with the instruction to read
`../../skills/jwt-auth-auditor/SKILL.md` and follow it, then grade the resulting
report against that case's `eval_metadata.json`. Run a no-skill agent on the same
prompt as a control.
