# CLAUDE.md: KYA Gateway, prove it, harden it, demo it

> **Archived, historical.** This was the brief handed to the coding agent that hardened the
> proof of concept on 22 September 2026. It is kept for context: it explains why the work in
> [`../HARDENING_REPORT.md`](../HARDENING_REPORT.md) was done in that order. Current guidance
> for agents is [`../../AGENTS.md`](../../AGENTS.md); current plans are
> [`../ROADMAP.md`](../ROADMAP.md). Paths and file names mentioned below may be out of date.

You are a coding agent (Claude Code). This file is your brief for this session.
Goal: leave this repo in a state where anyone can run **one command** and see, from evidence
files, that the KYA Gateway works; then package a short demo and a research write-up.

**The rule that overrides everything else: nothing counts unless it is verifiable.**
Every claim you make in REPORT.md or DEMO.md must name the command that proves it and the
evidence file that command produced. If you cannot prove it, say it is unproven.

## 0. Context (read first, 10 minutes)

- `README.md`: what the gateway does and how the modules fit.
- `docs/CONTEXT.md`: product context from the RFD and research doc.
- `docs/BASELINE_FINDINGS.md`: what was verified on 22 Sep 2026, including interop results.
- `docs/ROADMAP.md`: the longer build plan and defect list (D1 to D9). Only the items listed in
  section 2 below are in scope now.
- Spec: https://www.ietf.org/archive/id/draft-meunier-webbotauth-httpsig-protocol-00.html
  and RFC 9421. Cite section numbers in code comments when you implement spec behaviour.

## 1. Reproduce the baseline (must pass before you change code)

```bash
git init -q && git add -A && git commit -qm "baseline: POC as received"
scripts/verify.sh --network        # or without --network if you have no internet
```

Expected in `evidence/`: `Overall: PASS` in `SUMMARY.md`; `pytest-offline.log` 12 passed;
`pytest-interop.log` 7 passed; `demo.log` ends with `DEMO CHECK: PASS`; with `--network`,
`pytest-network.log` 4 passed and 1 skipped (the skip is expected: that directory only holds
the RFC 9421 test key, which production mode rejects).
Compare `evidence/directory_survey.json` with `evidence/baseline-2026-09-22/`.

If it fails: fix the **environment** (Python 3.11+, Node 18+, `npm install` in `interop/js`),
never the tests. If it still fails, stop and write REPORT.md explaining exactly what failed.

Commit: `M0: baseline verified`.

## 2. Implement (demo-week scope only)

Fix these four defects from `docs/ROADMAP.md`, each as: failing test first, then fix, then
`scripts/verify.sh`, then commit `M1-Dx: ...`.

| ID | Defect | Must-pass test |
| --- | --- | --- |
| D1 | Rate limit on unverified traffic keyed on attacker-chosen keyid, so rotating keyids bypasses it | 5 requests, 5 different keyids, same client, limit 2: requests 3 to 5 get `rate_limit`. Middleware passes a client key (hashed IP /24 or /48 prefix, never the raw IP) to the policy engine. |
| D2 | `/_kya/*` admin endpoints are public | `KYA_ADMIN_TOKEN` unset: 404. Wrong bearer token: 401. Right token: 200. Demo must still pass (give it a token). |
| D5 | No cap on the number of signature labels | 1,000 labels: `invalid`, reason `too many signatures`, under 50 ms. Default cap 3, configurable. |
| D9 | `Cache-Control: no-store` / `no-cache` ignored when caching directories | Local directory server with each header: no-store fetches every time, max-age=60 fetches once in 60 s, missing header uses default TTL. |

Then extend `demo/run_demo.py` with **scenario 9: key rotation**. The Acme directory rotates
to a new key, an old-key request is still verified while the old key is published, and after
the old key is removed (and cache expires, per D9) it becomes `unverified`. Add it to
`EXPECTED` so `--check` enforces it.

Rules while implementing:
- Never delete, skip, or loosen an existing test or security check. `dev_mode` is demo-only.
- No request bodies, raw IPs, cookies, or user identifiers in the audit log.
- Keep all 12 IETF/unit tests, 7 interop tests, and the demo check green at every commit.

## 3. Research (time box: 2 hours total, every finding reproducible)

Put code in `research/`, outputs in `evidence/`, and your write-up in `research/FINDINGS.md`.
Each finding: what you checked, the exact command, the evidence file, date and time (UTC).

- **R1 Who signs today.** Extend `CANDIDATES` in `research/survey_directories.py` with at least
  10 more origins of AI agents, crawlers, browser-automation services, and agent payment
  companies. For each, write the public source that suggested it (URL) in
  `research/candidates.md`. Specifically try to find where Google and Amazon Bedrock AgentCore
  publish Web Bot Auth keys, since both are reported to sign. Run the survey.
- **R2 Interop matrix.** Keep the JS tests. If `cargo` is available, add a cross-check with the
  Rust crate `web-bot-auth` (crates.io, v0.7.0 as of Sep 2026) in `interop/rust/`, both
  directions, as `@pytest.mark.interop` tests that skip when cargo is missing.
- **R3 Drift check.** Re-test the three baseline surprises and record whether they still hold:
  the live Cloudflare server rejecting the dictionary form, Cloudflare's directory publishing
  `nbf` in milliseconds, ChatGPT keys expiring about 7 days out with `no-store`.
- **R4 Verifier cost.** Add `bench/verify_bench.py`: 10,000 verifications with a cached Ed25519
  key; report p50 and p95 to `evidence/bench.json`. Add it to `verify.sh`.

Do not invent market numbers. If something cannot be measured from a public endpoint, list it
under "Unknowns" instead.

## 4. Demo package

- `DEMO.md`: a 3-minute script for a non-technical co-founder. Steps with exact commands,
  what appears on screen, and one sentence on why it matters. Include the dashboard
  (`evidence/dashboard_snapshot.html`) and the tamper-detection moment.
- Record the terminal session with `asciinema rec evidence/demo.cast -c "python -m demo.run_demo"`
  if asciinema is installed; otherwise the demo output in `evidence/demo.log` (written by
  verify.sh) is enough.

## 5. REPORT.md (write last, keep it short)

1. **Verdict**: one paragraph. Does it work? Point to `evidence/SUMMARY.md`.
2. **What changed**: commits, one line each.
3. **Proof table**: `Claim | Command | Evidence file | Result`, one row per claim. At minimum:
   IETF vectors pass, interop both directions, live server behaviour, demo check, each of
   D1/D2/D5/D9, key rotation scenario, benchmark.
4. **Research findings**: summary of R1 to R4 with links to `research/FINDINGS.md`.
5. **Spec questions**: every `SPEC-QUESTION` comment, with the section and your reading.
6. **Security findings**: anything new, with severity and whether fixed.
7. **Product feedback for the RFD**: what the evidence says about the idea (for example, how
   many real operators publish keys, which formats matter in practice).
8. **Unknowns and next steps**: the three most valuable next steps.

## Definition of done

- [ ] `scripts/verify.sh --network` ends with `Overall: PASS` (or offline PASS plus a stated reason)
- [ ] D1, D2, D5, D9 fixed with tests; key rotation scenario in the demo check
- [ ] `research/FINDINGS.md`, `research/candidates.md`, `evidence/directory_survey.json`, `evidence/bench.json` exist
- [ ] `DEMO.md` and `REPORT.md` written; every claim in them has a command and an evidence file
- [ ] Git history shows one commit per step; `evidence/` committed
