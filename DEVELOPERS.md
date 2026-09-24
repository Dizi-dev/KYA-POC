# Developer handoff

Everything a new engineer (or agent) needs to run this, trust it, keep it honest over time,
and know what to build next. Read [`README.md`](README.md) first for what the product is.

- [Set up](#set-up)
- [Run everything](#run-everything)
- [Test layers](#test-layers)
- [Living tests](#living-tests-the-part-people-forget)
- [Continuous integration](#continuous-integration)
- [Next steps, in order](#next-steps-in-order)
- [Working rules](#working-rules)
- [Gotchas that cost us time](#gotchas-that-cost-us-time)
- [Debugging a verification](#debugging-a-verification)
- [Open decisions](#open-decisions)
- [Handoff checklist](#handoff-checklist)

## Set up

| Requirement | Version | Needed for |
| --- | --- | --- |
| Python | 3.11+ (developed on 3.14) | everything |
| Node | 18+ (developed on 24) | interop against Cloudflare's JS library |
| Rust / cargo | any recent stable | interop against Cloudflare's Rust crate (tests skip without it) |
| Internet | optional | the `--network` layers only |

```bash
scripts/verify.sh          # creates .venv, installs deps, runs the offline suite end to end
```

That is the whole setup. If you prefer to do it by hand:

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
cd interop/js && npm install --no-audit --no-fund && cd ../..
cd interop/rust && cargo build --release && cd ../..
```

## Run everything

| Command | What it does | Writes |
| --- | --- | --- |
| `scripts/verify.sh` | Offline: spec vectors, unit, security, JS+Rust interop, demo, benchmark | `evidence/*` and `evidence/SUMMARY.md` |
| `scripts/verify.sh --network` | The above plus live server checks, both surveys, the walkthrough, drift check | same, plus network logs |
| `.venv/bin/python -m pytest -q -m "not interop and not network"` | 51 offline tests | |
| `.venv/bin/python -m pytest -q -m interop` | 15 cross-implementation tests | |
| `KYA_NETWORK=1 .venv/bin/python -m pytest -q -m network -rs` | 5 live tests (1 expected skip) | |
| `.venv/bin/python -m demo.run_demo --evidence evidence/demo.json` | Scripted demo, exits non-zero on any wrong decision | `evidence/demo.json` |
| `.venv/bin/python -m demo.live` | Interactive panel on :8002 (starts a demo shop on :8000 and a key directory on :8001) | |
| `.venv/bin/python -m examples.walkthrough` | Production-mode run against live ChatGPT/Google directories | `evidence/walkthrough.json` |
| `.venv/bin/python -m research.survey_directories --dataset` | Probes every registered signing operator | `evidence/signed_agents_survey.json` |
| `.venv/bin/python -m research.drift_check` | Re-tests the three known ecosystem surprises | `evidence/drift.json` |
| `.venv/bin/python -m bench.verify_bench` | 10,000 verifications, p50/p95 | `evidence/bench.json` |

`evidence/SUMMARY.md` is the human-readable result: one row per step, plus sha256 of every
file produced. Treat a failing row as a real failure; do not "fix" it by relaxing a test.

## Test layers

| Layer | Marker | Count | Lives in |
| --- | --- | --- | --- |
| Spec conformance: IETF Appendix C.2 vectors, thumbprints, HMAC refusal, test-key refusal | none | 10 | `tests/test_ietf_vectors.py` |
| Security and defect regressions: D1, D2, D5, D9 and review findings E1–E5 | none | 22 | `tests/test_defects.py` |
| Interop, Cloudflare JavaScript `web-bot-auth` 0.2.0 | `interop` | 7 | `tests/test_interop.py` |
| Interop, Cloudflare Rust `web-bot-auth` 0.7.0 | `interop` | 8 | `tests/test_interop_rust.py` |
| Live endpoints: Cloudflare's research server, real directories | `network` | 5 | `tests/test_interop.py` |
| End-to-end behaviour, including key rotation and tamper detection | n/a | 13 scenarios | `demo/run_demo.py` |
| Production-mode behaviour against the live internet | n/a | 7 steps | `examples/walkthrough.py` |
| Performance | n/a | p50/p95 | `bench/verify_bench.py` |

Network tests never run by default. They need `KYA_NETWORK=1`, so CI and offline machines
stay deterministic.

### What each regression test is protecting

Do not delete these without understanding what they caught:

| Test group | Protects against |
| --- | --- |
| `test_d1_*` | Rate-limit bypass by rotating attacker-chosen key ids; raw IPs reaching the audit log |
| `test_d2_*` | Public admin endpoints leaking the audit log and dashboard |
| `test_d5_*` | Unbounded work (and unbounded directory fetches) from thousands of signature labels |
| `test_d9_*` | Ignoring `no-store` / `no-cache` and serving stale keys after rotation |
| `test_e1_*`, `test_e2_*` | Lookalike-domain matches (`acme.com.attacker.io` satisfying an `acme.com` rule or allowlist) |
| `test_e3_*` | Malformed signature parameters crashing the verifier into a 500 with no audit row |
| `test_e4_*` | Sending an `Accept` header real directories reject (Klaviyo answered 406) |
| `test_e5_*` | Quadratic nonce store: latency growing with traffic, exploitable as a slow-down |

## Living tests, the part people forget

Code tests prove the code. They do not prove the gateway still works **in an ecosystem that
changes weekly**. Operators rotate keys, publish new formats, move directories, and the draft
spec keeps moving. These checks are what keep the thing honest after handoff.

### 1. Ecosystem drift, weekly

```bash
.venv/bin/python -m research.drift_check --out evidence/drift.json
.venv/bin/python -m research.survey_directories --dataset --out evidence/signed_agents_survey.json
```

Watch for, and treat each as a finding rather than a failure:

- **Loadable count dropping.** Today 87 of 96. A sharp drop means either our fetching broke
  or operators changed something (media type, redirect, path).
- **A new key algorithm appearing.** Today all 100 keys are Ed25519. The first RSA or EC key
  in the wild means real agents exist that we cannot verify.
- **New `Cache-Control` behaviour**, especially more `no-store`, which multiplies our fetch
  load.
- **`kid` values that are not RFC 7638 thumbprints.** Four operators already do this,
  Google included. If a real request arrives keyed by a non-thumbprint `kid`, verification
  fails with "key not published" and we need a lookup fallback.
- **The three baseline surprises** in `drift_check`: Cloudflare's live server rejecting the
  dictionary form, millisecond `nbf`, ChatGPT's weekly-rotating `no-store` keys. When one
  flips, the ecosystem moved and our defaults may need to move with it.

### 2. Reference implementation drift, monthly

Cloudflare's libraries are our independent oracle. Pin bumps are how we find out the draft
changed.

```bash
cd interop/js && npm outdated            # web-bot-auth, currently pinned at 0.2.0
cargo search web-bot-auth --limit 1      # crate, currently pinned at 0.7.0 in interop/rust
```

When a new version appears: bump, run `pytest -m interop`, and read the diff of their
verification rules. Twice now their behaviour told us more than the draft text did.

### 3. Spec drift, on every new draft revision

`draft-meunier-webbotauth-httpsig-protocol-00` is a moving target and the working group had
adopted nothing as of mid-2026. When `-01` lands, diff it against our
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) decisions and every `SPEC-QUESTION:` comment
in the code (`grep -rn "SPEC-QUESTION" kya_gateway/`).

### 4. Performance regression, every release

```bash
.venv/bin/python -m bench.verify_bench
```

Fail the release if p95 exceeds **1 ms** on comparable hardware, and investigate any p50
above ~0.25 ms. E5 was caught exactly this way: latency grew with the number of live nonces.

### 5. Once it is deployed anywhere, operational checks

These do not exist yet and are part of the pilot work. Each is a small cron or health check:

| Check | Cadence | Alert when |
| --- | --- | --- |
| `verify_chain()` on the audit database | hourly | not intact, ever |
| Outcome mix (`verified` / `unverified` / `invalid` / `unsigned`) | daily | `unverified` share jumps, which usually means a directory we depend on broke |
| Directory fetch latency and error rate per operator | continuous | p95 above ~1 s, or error rate above a few percent |
| Audit log growth and disk headroom | daily | retention policy not yet implemented, so this will bite |
| Admin token age | quarterly | rotate; the token is the only thing protecting the audit log |
| Backup of the audit database | daily | the chain proves edits, it cannot survive deletion |
| `log_only` still on for a pilot site | on deploy | enforcing by accident on a design partner is the worst possible first impression |

### 6. Demo health, before any external demo

```bash
.venv/bin/python -m demo.run_demo      # must end with DEMO CHECK: PASS
.venv/bin/python -m examples.walkthrough   # needs internet; must end with WALKTHROUGH CHECK: PASS
```

The walkthrough depends on live third-party endpoints, so run it the morning of a demo, not
the week before.

## Continuous integration

Two workflows in [`.github/workflows/`](.github/workflows/):

- **`tests.yml`** runs on every push and pull request: Python 3.11 and 3.12, the offline
  suite, the JS interop suite, the Rust interop suite, the scripted demo, and the benchmark.
  No network tests, so it is deterministic.
- **`living-checks.yml`** runs weekly and on manual dispatch: the live network tests, both
  surveys and the drift check, and uploads the resulting `evidence/` files as artifacts. It
  is allowed to fail loudly; that failure is the signal that the ecosystem moved.

## Next steps, in order

Defect IDs match [`docs/ROADMAP.md`](docs/ROADMAP.md) and the original review. Everything
here has a stated acceptance test, so "done" is not a matter of opinion.

### Before any pilot

1. **D3: stop blocking the event loop.** Move key resolution to `httpx.AsyncClient` and run
   SQLite writes in a thread pool.
   *Accept:* 50 concurrent requests while one directory sleeps 2 s; the other 49 are not
   delayed. Today they are.
2. **D6: coalesce fetches.** One in-flight fetch per directory URL, shared by waiters, plus a
   per-host concurrency cap.
   *Accept:* 100 concurrent requests for the same uncached directory produce exactly 1 fetch.
3. **Decide the `no-store` policy.** Honouring it literally costs 340–430 ms per ChatGPT
   request. Options: a short floor (a few seconds), background refresh, or stale-while-
   revalidate. This is a deliberate spec deviation, so write it down in
   [`docs/SECURITY.md`](docs/SECURITY.md) when you choose.
   *Accept:* a documented decision plus a test pinning the chosen behaviour.
4. **Shared state for multiple workers.** Redis-backed nonce store and rate limiter behind
   the existing interfaces (`KYA_REDIS_URL`), and `BEGIN IMMEDIATE` for the audit append
   (D7).
   *Accept:* 4 processes × 200 appends leave the chain intact; rate limits hold across
   workers; tests can use `fakeredis`.
5. **Trusted proxy configuration (D8, E9).** A `trusted_proxy_host_header` option for
   `@authority`, and a way to take the real client address from `X-Forwarded-For` when the
   deployment says it is safe.
   *Accept:* tests for both modes; behind a proxy, two different clients land in different
   rate-limit buckets.

### To make the pitch real

6. **Deploy `examples/my_shop.py` publicly in `log_only` mode and get a real agent to visit.**
   This is the single highest-value experiment in the repo: it answers which `keyid` and
   which `Signature-Agent` form real operators actually send, and whether anything verifies
   end to end.
   *Accept:* one audit row with `outcome=verified` and an operator we did not create.
7. **RSA-PSS and EC key support**, the prerequisite for both payment proofs.
   *Accept:* draft Appendix C.1 RSA vectors pass; Visa's and Skyfire's published key sets
   parse.
8. **Finish Visa TAP**, then **add Skyfire KYAPay**, each as an adapter behind a common claim
   (`operator, keyid, tag, intent, user_ref, scope, proof_type`), leaving policy, audit and
   dashboard untouched.
   *Accept:* a request carrying both an identity signature and a payment proof produces one
   claim with both, and policy can require the payment proof for a checkout path.

### Product and packaging

9. `pyproject.toml`, a `kya` console script, and a published package.
10. Pure ASGI middleware instead of `BaseHTTPMiddleware` (no body buffering, streaming safe).
11. Dashboard v1: filters, per-operator per-day counts, verified share of agent traffic.
12. Audit anchoring: periodically publish the head hash somewhere external so deletion is
    detectable, plus a retention policy with a signed "truncated before" marker.
13. Reverse-proxy deployment mode (`kya proxy --upstream ...`) for sites that cannot add
    middleware, which is most WooCommerce and Node shops.

### Watching, not building

14. **Google AP2.** The spec does not define how a merchant gets verification keys; their own
    issue on it is open. Re-check quarterly. Build nothing until it lands.

## Working rules

These are not style preferences; each one exists because breaking it cost us something.

- **Never weaken a test or a security check to make something pass.** If a test is wrong,
  fix the test in its own commit and say why.
- **The spec vectors must pass at every commit.**
- **Unit tests never touch the public internet.** Use a local server or a stub. Anything that
  needs the network goes behind `@pytest.mark.network`.
- **Nothing sensitive in the audit log**: no bodies, no raw IPs, no cookies, no user
  identifiers. Operator URL, key id and tag are fine.
- **When the spec is ambiguous, take the stricter reading**, leave a `SPEC-QUESTION:` comment
  with the section number, and list it in the report.
- **`dev_mode` is for local demos only.** It disables HTTPS-only and the SSRF guard.
- **Evidence or it did not happen.** A claim in a README, a report or a deck names the
  command that proves it and the file that command wrote.
- **One logical change per commit**, message prefixed with the milestone or defect ID where
  one applies (`M1-D9: ...`).

## Gotchas that cost us time

- **Base64 padding.** Flipping a character just before `==` can leave the decoded bytes
  identical, so a "tampered signature" test silently passes. Flip a bit in the decoded bytes
  instead. Anything keyed on the raw `Signature` header text must decode first.
- **`Accept` headers matter.** Ask for the directory media type, with JSON as a fallback.
- **Timestamps may be milliseconds.** Cloudflare's own directory publishes `nbf` in
  milliseconds; we treat anything above 1e11 as milliseconds.
- **`kid` is not always the thumbprint.** We index keys by RFC 7638 thumbprint, as
  Cloudflare's library does. Four operators publish something else.
- **Redirects are not followed, by design.** Several operators publish behind one, which is
  why they show as unreachable in the survey.
- **Starlette's `request.client` is the proxy** behind any reverse proxy, so rate-limit
  bucketing degenerates until you configure the real client address.
- **The demo directory uses a 2 second cache lifetime** so the key-rotation scenario can show
  expiry. Do not copy that value into anything real.

## Debugging a verification

When someone asks "why was this agent unverified?":

1. The reason is already in the response and the audit row: `KYA-Outcome`, `KYA-Decision`,
   and the `reason` field (`keyid not published in the agent's directory`, `signature does
   not match`, `directory unavailable: ...`, `too many signatures`, ...).
2. Reproduce the key lookup in isolation:
   ```python
   from kya_gateway.keys import KeyResolver
   r = KeyResolver()                       # production rules
   url = r._fetch_url("https://chatgpt.com", "directory")
   entry = r._fetch(url)                   # .error, .keys, .expires_at
   ```
3. Check what the operator actually publishes:
   ```bash
   curl -H "Accept: application/http-message-signatures-directory+json, application/json;q=0.9" \
        https://<origin>/.well-known/http-message-signatures-directory | jq
   ```
4. Compare thumbprints: `kya_gateway.keys.jwk_thumbprint(jwk)` against the `keyid` in the
   request's `Signature-Input`.
5. If the signature itself fails, rebuild the base with `sigbase.build_signature_base` and
   compare against what the signer covered. `@authority` mismatches behind a proxy are the
   usual cause.

## Open decisions

Things a human owner needs to decide; none of them should be guessed by an agent.

| Decision | Why it matters |
| --- | --- |
| **License** | The repo is public with no `LICENSE` file, so nobody may legally reuse it. Pick one (Apache-2.0 and MIT are the usual choices for middleware; AGPL if you want to force contributions back) |
| **`no-store` deviation** | Spec-literal behaviour is slow enough to hurt adoption. A deliberate documented deviation is fine; an undocumented one is not |
| **Redis or another shared store** | Needed before multi-worker deployment |
| **Hosted or self-hosted product** | Changes the dashboard, the audit anchoring and the packaging work |
| **Design partners** | Which two or three sites run the `log_only` pilot |

## Handoff checklist

- [x] One command reproduces every claim: `scripts/verify.sh --network`
- [x] Evidence committed, with hashes, including the pre-hardening baseline
- [x] Security findings documented, fixed ones with regression tests
- [x] Architecture, security model and roadmap written down
- [x] Agent-facing guide (`AGENTS.md`) for automated contributors
- [x] CI running the deterministic suites, plus a weekly ecosystem check
- [ ] License chosen
- [ ] Public deployment and one genuine third-party agent request observed
- [ ] Shared stores, so more than one worker can run
