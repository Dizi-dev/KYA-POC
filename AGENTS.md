# Guide for coding agents

You are working in **KYA Gateway**: middleware that verifies AI-agent signatures
(Web Bot Auth / RFC 9421), applies a YAML policy, and writes a tamper-evident audit log.
Read [`README.md`](README.md) for the product and [`DEVELOPERS.md`](DEVELOPERS.md) for the
engineering detail. This file is the short orientation: where things are, what the rules are,
and how to finish a task properly.

## Orientation in 60 seconds

```
kya_gateway/     the product. ~900 lines, no framework magic, start here
  sigbase.py     rebuilds the RFC 9421 signature base
  keys.py        key discovery, SSRF guard, directory cache
  verifier.py    the four outcomes: unsigned / verified / invalid / unverified
  policy.py      first-match YAML rules -> allow / block / rate_limit / charge
  audit.py       SQLite hash chain
  middleware.py  ASGI glue, client-key derivation, /_kya/* admin, dashboard
  signer.py      agent-side signer, used by demo and tests only
tests/           spec vectors, defect regressions, interop (JS + Rust)
demo/            run_demo.py (scripted, self-checking), live.py (interactive panel)
examples/        my_shop.py (real integration), walkthrough.py (live internet)
research/        surveys and drift checks against the real ecosystem
bench/           latency benchmark
scripts/verify.sh  runs everything, writes evidence/
docs/            architecture, security, roadmap, context, reports
```

## The rules

Breaking any of these is worse than not finishing the task.

1. **Never weaken a test or a security check to make something pass.** If a test is genuinely
   wrong, fix it in a separate commit and explain why.
2. **The IETF Appendix C.2 vectors must pass at every commit** (`tests/test_ietf_vectors.py`).
3. **Unit tests must not use the public internet.** Local servers or stubs only. Anything
   needing the network goes behind `@pytest.mark.network` and only runs with `KYA_NETWORK=1`.
4. **Never log request bodies, raw IP addresses, cookies or user identifiers.** Operator URL,
   key id and tag are fine. There is a test asserting raw IPs never reach the audit log.
5. **`dev_mode=True` is demo-only.** It disables HTTPS-only directories and the SSRF guard.
6. **When the spec is ambiguous, choose the stricter reading**, add a
   `# SPEC-QUESTION: <section> ...` comment, and mention it in your summary.
7. **Evidence or it did not happen.** Any claim you make names the command that proves it and
   the file that command wrote, under `evidence/`.
8. **Match the surrounding style**: type hints on public functions, comments that explain
   *why* (usually citing a spec section or a defect ID), no decorative noise.

## Definition of done for a code change

```bash
scripts/verify.sh                 # must end with Overall: PASS
```

That runs: 51 offline tests, 15 interop tests, the scripted demo (13 scenarios including key
rotation and tamper detection), and the benchmark. For anything touching key discovery,
caching or the live ecosystem, also run `scripts/verify.sh --network`.

Then, in your summary: what changed, which command proves it, and which evidence file to look
at. If something is unproven, say so plainly.

## How to pick up work

1. [`DEVELOPERS.md`](DEVELOPERS.md) → "Next steps, in order". Each item has an acceptance
   test already written out. Take the first unstarted one unless told otherwise.
2. Write the failing test first. `tests/test_defects.py` is the model: each group names the
   defect ID and what it protects against.
3. Fix it. Keep the change small enough to describe in one line.
4. `scripts/verify.sh`, then commit as `<ID>: <what changed>` (for example
   `M1-D3: async directory fetches`).

## Things that look like bugs but are not

- **Redirects are refused on purpose** (draft section 5.8). Several real operators publish
  behind a redirect and therefore appear unreachable in `research/survey_directories.py`.
- **The RFC 9421 test key is rejected** outside `dev_mode`, which is why one network test
  skips against Cloudflare's research directory.
- **Cloudflare's live server rejects the draft-00 dictionary `Signature-Agent` form.** Their
  own library produces it. The server lags the draft; `drift_check` tracks it.
- **`nbf`/`exp` above 1e11 are treated as milliseconds.** Cloudflare's directory publishes
  them that way.
- **The demo key directory caches for 2 seconds.** That exists so the rotation scenario can
  show a removed key expiring. Never copy that value into production defaults.
- **`interop/rust/target/` and `.venv/` are ignored.** The Rust interop tests build on demand
  and skip entirely when `cargo` is missing.

## Before you claim the ecosystem changed

The surveys and drift checks talk to live third-party endpoints. A single failure is more
likely to be a network blip than a real change. Re-run once, compare against
`evidence/signed_agents_survey.json` and `evidence/drift.json`, and report the difference as
a finding with the date, not as a broken test.

## Where the history is

- [`docs/HARDENING_REPORT.md`](docs/HARDENING_REPORT.md): what was fixed on 22 Sep 2026, with
  the proof table and every security finding.
- [`docs/BASELINE_FINDINGS.md`](docs/BASELINE_FINDINGS.md): what the proof of concept looked
  like before that work.
- [`research/FINDINGS.md`](research/FINDINGS.md): the ecosystem research, with commands and
  timestamps.
- [`docs/archive/`](docs/archive/): the original session brief and roadmap, kept for context.
