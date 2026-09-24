# KYA Gateway roadmap (post-demo)

> **Archived, historical.** The original post-proof-of-concept build plan, including the
> D1–D9 defect list that later work refers to. Superseded by [`../ROADMAP.md`](../ROADMAP.md);
> defect status is tracked in [`../SECURITY.md`](../SECURITY.md). Kept because the defect IDs
> and their original acceptance tests are still cited throughout the repo.

This is the longer build plan. For the current session, follow CLAUDE.md at the repo root.

You are a coding agent working on this repository. Read this whole file before changing code.
Your job: implement the milestones below in order, run the tests after each one, and finish by
writing `REPORT.md` in the format at the end of this file.

## 1. What this project is

KYA Gateway is middleware that sits in front of a web app or API and, for every request:

1. **Verifies** AI agent signatures (Web Bot Auth, and Visa TAP which builds on it).
2. **Classifies** the request as `unsigned`, `verified`, `invalid`, or `unverified`.
3. **Decides** what to do using YAML policy rules: `allow`, `block`, `rate_limit`, or `charge`.
4. **Logs** the decision in a hash-chained audit log that reveals any later edit.

Target customers are small stores and APIs that are not behind Cloudflare, Akamai, DataDome,
or Shopify, because those platforms already verify agents for their own customers.

Normative specs (read the relevant section before implementing, cite section numbers in code
comments and in REPORT.md):

| Spec | Use it for |
| --- | --- |
| draft-meunier-webbotauth-httpsig-protocol-00 (IETF, June 2026): https://www.ietf.org/archive/id/draft-meunier-webbotauth-httpsig-protocol-00.html | Required params, Signature-Agent, discovery types, SSRF rules (5.8), outcomes (A.1), caching (A.4, A.5), test vectors (Appendix C) |
| RFC 9421 HTTP Message Signatures: https://www.rfc-editor.org/rfc/rfc9421 | Signature base (2.5), components (2.1, 2.2), verification algorithm (3.2), test keys (Appendix B.1) |
| RFC 7638 and RFC 8037 A.3 | keyid = JWK SHA-256 thumbprint |
| Visa TAP: https://github.com/visa/trusted-agent-protocol | Tag values and reference CDN proxy behaviour |
| Cloudflare reference code and JSON test vectors: https://github.com/cloudflare/web-bot-auth | Interop checks |

If the spec is ambiguous, pick the stricter reading, leave a `# SPEC-QUESTION:` comment, and
list it in REPORT.md. Do not guess silently.

## 2. Current state (proof of concept)

```
kya_gateway/
  sigbase.py     RFC 9421 signature base builder
  keys.py        KeyResolver: static keys + Signature-Agent directory fetch, SSRF limits, cache
  verifier.py    Verifier: four outcomes, freshness, nonce replay, Ed25519 verify
  policy.py      PolicyEngine: first-match YAML rules
  audit.py       AuditLog: SQLite hash chain, verify_chain()
  middleware.py  FastAPI/Starlette middleware, /_kya/dashboard, /_kya/audit.json, /_kya/verify-chain
  signer.py      Agent-side signer (demo and tests)
demo/            store.py, agent_directory.py, run_demo.py (end-to-end scenario)
tests/           test_ietf_vectors.py (12 tests, all passing)
policy.yaml      Demo policy
```

Baseline commands (run these first and record the output in REPORT.md):

```bash
pip install -r requirements.txt
python -m pytest -q
python -m demo.run_demo
```

Expected baseline: `12 passed`, and the demo prints 10 audited requests, then
`chain broken at entry 5` after it tampers with the database.

## 3. Rules for you

- Never delete, skip, or weaken an existing test to make something pass. If a test is wrong,
  explain why in REPORT.md and fix the test in a separate commit.
- The IETF Appendix C test vectors must pass at every commit.
- Unit tests must not use the public internet. Use local servers or mocks. Put any test that
  needs the network behind `@pytest.mark.network`, skipped by default.
- Never relax a security check (SSRF limits, freshness, test-key rejection, HMAC rejection) to
  make a feature work. `dev_mode` exists only for local demos.
- Do not log request bodies, IP addresses, cookies, or user identifiers. Operator URL and
  keyid are fine.
- One milestone per commit (or small PR), message format `M<n>: <summary>`.
- Python 3.11+, type hints on public functions, `ruff` and `mypy --strict` clean on
  `kya_gateway/` once M0 is done.
- Stop and write REPORT.md if you are blocked for more than one attempt on the same problem.

## 4. Known defects to fix first (M0)

These were found by review of the POC. Each needs a failing test first, then the fix.

| ID | Defect | Where | Fix and acceptance test |
| --- | --- | --- | --- |
| D1 | **Rate-limit bypass.** Unverified requests are bucketed by keyid, so an attacker who rotates keyids is never limited. Confirmed: 5 rotating keyids give 5 `allow`. | `policy.py` bucket key | Bucket unverified and unsigned traffic by a caller-supplied client key (for example a hashed IP prefix passed in by the middleware), never by attacker-chosen values. Test: 5 requests with 5 different keyids from one client key, limit 2, expect the 3rd to 5th to be `rate_limit`. |
| D2 | **Admin endpoints are public.** `/_kya/*` exposes the audit log and dashboard to anyone. | `middleware.py` `_admin` | Require a bearer token from config (`KYA_ADMIN_TOKEN`); 404 when unset, 401 on a wrong token. Tests for all three cases. |
| D3 | **Blocking I/O in the event loop.** Directory fetch uses sync `httpx.Client`; audit writes use sync SQLite inside `async dispatch`. | `keys.py`, `middleware.py` | Make key resolution async (`httpx.AsyncClient`) and run SQLite writes in a thread pool. Test: 50 concurrent requests while one directory fetch sleeps 2 s; others must not wait for it. |
| D4 | **DNS rebinding (TOCTOU) in the SSRF guard.** Host is resolved and checked, then httpx resolves it again. | `keys.py` `_check_host`, `_fetch` | Resolve once, check the IP, then connect to that exact IP with the original Host header and SNI. Test with a resolver stub that returns a public IP first and 127.0.0.1 second. |
| D5 | **No cap on signature labels.** A request with thousands of labels makes the verifier loop over all of them. | `verifier.py` `verify` | Process at most 3 labels (configurable); return `invalid` with reason `too many signatures` beyond that. Test with 1,000 labels, must finish under 50 ms. |
| D6 | **No fetch coalescing.** Many requests naming the same uncached directory each trigger a fetch (draft A.3). | `keys.py` | One in-flight fetch per directory URL, shared by waiters; per-host concurrency limit. Test: 100 concurrent requests, directory server sees 1 fetch. |
| D7 | **Audit race across processes.** The lock is per process; two workers can write the same `prev_hash`. | `audit.py` `append` | Use `BEGIN IMMEDIATE` so read-prev and insert are one transaction. Test: 4 processes x 200 appends, `verify_chain()` stays intact. |
| D9 | **Cache headers not honored.** Only `max-age` is read; ChatGPT's live directory sends `Cache-Control: no-store` and its keys expire after about 7 days, but we cache for 300 s anyway. | `keys.py` `_fetch` | Honor `no-store` and `no-cache` (draft A.4). Tests for no-store, no-cache, max-age, and missing header. |
| D8 | **@authority behind a proxy.** Uses the Host header; a reverse proxy may rewrite it. | `sigbase.py` | Config option `trusted_proxy_host_header` (for example `x-forwarded-host`), off by default. Test both modes. |

## 5. Milestones

Do them in order. Each lists what "done" means. Write the tests named in "Tests" before or
with the code.

### M0: Fix defects D1 to D8
Done when all eight tests above exist and pass, plus the original 12.

### M1: Complete the Web Bot Auth verifier
- RSA-PSS-SHA512 support (`alg="rsa-pss-sha512"`), key from RFC 9421 Appendix B.1.2.
- Pass draft Appendix C.1.1, C.1.2, C.1.3 (RSA) in addition to the existing C.2 vectors.
- Load Cloudflare's JSON test vectors from a vendored copy under `tests/vectors/` and run them.
- Enforce `Signature-Agent` type values `directory`, `jwks_uri`, `cimd` (draft 4.5); implement
  `cimd` (fetch the Client ID Metadata Document, then `jwks` or `jwks_uri` from it).
- Honor `Cache-Control`, `ETag`, `Last-Modified` on directory fetches with conditional requests (A.4).
- Respond to missing or bad signatures on protected paths with `Accept-Signature` when policy
  says `challenge` (new action, draft 4.3: 403 for missing, 429 for replayed nonce).

Tests: new vectors, one test per discovery type, cache hit and 304 revalidation, challenge responses.

### M2: Common claim model and adapters
- Introduce `AgentClaim` (operator, keyid, tag, intent, user_ref, scope, proof_type) and an
  `Adapter` interface: `detect(request) -> bool`, `verify(request) -> VerificationResult`.
- Port Web Bot Auth and Visa TAP to adapters. TAP tags: `agent-browser-auth` (browse) and
  `agent-payer-auth` (payment intent); map these to `intent`.
- **Spike, not full build:** KYAPay (signed JWT) and AP2 (user-signed mandate in body). Find the
  public spec, write what verification needs, and implement only if the spec and a public key
  endpoint are openly available without an account. Otherwise document the blocker in REPORT.md.

Tests: adapter registry picks the right adapter; a request with both a TAP signature and an
AP2 mandate yields one claim with both identity and user authorization.

### M3: Policy engine v1
- JSON Schema for `policy.yaml`; reject unknown keys and actions with a clear error at load.
- New match fields: `intent`, `operator_in` (list of directory URLs), `client_key`.
- New actions: `challenge` (from M1) and `require_mandate` (block payment intent without an AP2 mandate).
- Hot reload on file change, keeping the last valid policy if the new one fails validation.
- Pluggable rate-limit and nonce stores: in-memory (default) and Redis (`KYA_REDIS_URL`).

Tests: schema errors, each match field, each action, reload with a broken file, Redis stores
(use `fakeredis`).

### M4: Audit log v1
- Periodic anchor: every N entries or T minutes, write the head hash to an append-only
  anchor file and optionally POST it to a configured URL. `verify_chain()` also checks anchors.
- Retention setting (days) that deletes old rows and records a signed "truncated before" marker
  so the chain still verifies.
- `kya audit export --from --to` CLI producing JSON evidence for a dispute.

Tests: truncation keeps the chain verifiable; editing, deleting, or reordering any row is detected.

### M5: Middleware and deployment modes
- Replace `BaseHTTPMiddleware` with pure ASGI middleware (no body buffering, supports streaming).
- `log_only` stays the default for new installs.
- Standalone reverse-proxy mode: `kya proxy --upstream http://localhost:3000 --listen :8080`.
- Express/Node middleware port is **out of scope**; note API shape needed for it in REPORT.md.

Tests: streaming response passes through untouched; proxy mode end to end with the demo store.

### M6: Dashboard v1
- Behind the admin token (D2). Filters by outcome, decision, operator, time range.
- Counts per operator per day, and verified share of agent traffic.
- Stays a single server-rendered page with no external scripts.

Tests: HTML contains the filtered rows only; no unescaped user-controlled strings (XSS test
with a malicious path and reason).

### M7: Packaging and CI
- `pyproject.toml`, package name `kya-gateway`, console script `kya`.
- GitHub Actions: ruff, mypy, pytest on Python 3.11 and 3.12; network tests only on manual trigger.
- Micro-benchmark script `bench/verify_bench.py`: Ed25519 verify with a cached key, report p50
  and p95. Target: p95 under 1 ms per request on a laptop.

## 6. Test plan summary

| Layer | What | Command |
| --- | --- | --- |
| Spec conformance | IETF Appendix C vectors, RFC 9421 keys, Cloudflare JSON vectors | `pytest tests/test_ietf_vectors.py tests/test_cf_vectors.py` |
| Unit | sigbase, keys, verifier, policy, audit | `pytest -q` |
| Security | D1 to D8, SSRF ranges (IPv4, IPv6, IPv4-mapped IPv6), oversized and redirecting directories, XSS | `pytest -q -m security` |
| Integration | demo scenario must still produce the same 8 outcomes | `python -m demo.run_demo` |
| Interop (optional, network) | Sign with Cloudflare's tooling, verify with ours, and the reverse | `pytest -m network` |
| Performance | verify latency | `python bench/verify_bench.py` |

## 7. Out of scope

Issuing agent identities or running a key directory; payment collection (the `charge` action
only returns 402 with a price); behavioral fraud scoring; Shopify (it verifies Web Bot Auth
itself); WooCommerce plugin (next phase).

## 8. Feedback: write REPORT.md when you stop

Use exactly these sections, short and factual:

1. **Summary**: one paragraph, what works now that did not before.
2. **Milestones**: table with columns `Milestone | Status (done/partial/blocked) | Commit | Notes`.
3. **Test results**: command, passed, failed, skipped, for each layer in section 6. Paste the
   final `pytest` summary line and the demo table.
4. **Benchmark**: p50 and p95 verify latency, machine description.
5. **Spec questions**: every `SPEC-QUESTION`, with the draft or RFC section and the reading you chose.
6. **Security findings**: anything new you found beyond D1 to D8, with severity (high/medium/low)
   and whether you fixed it.
7. **Deviations**: anything implemented differently from this brief, and why.
8. **Feedback on the product**: where the spec or ecosystem makes the product harder or easier
   than the RFD assumes (for example, which proof formats were impossible to verify without an
   account). This goes back into the RFD.
9. **Next steps**: the three most valuable things to do next, in order.
