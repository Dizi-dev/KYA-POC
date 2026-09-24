# CLAUDE.md

Guidance for Claude Code and other coding agents working in this repository.

**Read [`AGENTS.md`](AGENTS.md) first.** It is the full agent guide: repo map, the working
rules, the definition of done, and how to pick up the next task. This file exists so agents
that look for `CLAUDE.md` by convention find their way there.

Quick orientation:

| Question | Answer |
| --- | --- |
| What is this? | Middleware that verifies AI-agent signatures (Web Bot Auth / RFC 9421), applies a YAML policy, and writes a tamper-evident audit log. See [`README.md`](README.md). |
| How do I know my change is good? | `scripts/verify.sh` must end with `Overall: PASS`. Add `--network` for anything touching key discovery or caching. |
| What should I work on? | [`DEVELOPERS.md`](DEVELOPERS.md) → "Next steps, in order". Each item has an acceptance test. |
| What must I never do? | Weaken a test or a security check; let unit tests touch the internet; log bodies, raw IPs, cookies or user identifiers; enable `dev_mode` outside a local demo. |
| Where is the history? | [`docs/HARDENING_REPORT.md`](docs/HARDENING_REPORT.md), [`research/FINDINGS.md`](research/FINDINGS.md), and [`docs/archive/`](docs/archive/). |

Claims need evidence: name the command you ran and the file under `evidence/` it produced. If
something is unproven, say so plainly rather than implying it works.
