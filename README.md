# KYA Gateway

**Know Your Agent: middleware that tells a real AI agent from a spoofed one, applies your policy, and keeps proof.**

AI agents now browse, shop and call APIs on behalf of people. A site cannot tell a real
agent from a scraper, because `User-Agent: GPTBot` is just text anyone can type. The
industry answer is cryptographic agent identity: the agent signs every request
([RFC 9421 HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421), profiled by the
IETF [Web Bot Auth draft](https://www.ietf.org/archive/id/draft-meunier-webbotauth-httpsig-protocol-00.html))
and publishes its public keys. As of 22 September 2026, **96 agent operators publish signing
keys and 87 of them verify cleanly in this gateway**, including ChatGPT, Google, AWS Bedrock
AgentCore, Meta and DuckDuckGo.

Cloudflare, Shopify, AWS and Akamai verify those signatures for their own customers.
KYA Gateway is for everyone else: self-hosted stores, APIs and MCP servers. It **verifies**
the agent, **decides** what it may do from a YAML policy, and **proves** what happened in a
hash-chained audit log.

> **Status: proof of concept, hardened, not production ready.** Everything claimed below is
> reproducible with one command and backed by files in [`evidence/`](evidence/). Two things
> are explicitly *not* proven: no genuine request from a real third-party agent has passed
> through it yet (needs a public deployment), and directory fetches still block the event
> loop (see [Known limitations](#known-limitations)).

---

## Contents

- [What it does](#what-it-does)
- [Quick start](#quick-start)
- [Use it in your app](#use-it-in-your-app)
- [Writing policy](#writing-policy)
- [How it works](#how-it-works)
- [Protocol coverage](#protocol-coverage)
- [What is proven, and how to re-prove it](#what-is-proven-and-how-to-re-prove-it)
- [What we learned about the ecosystem](#what-we-learned-about-the-ecosystem)
- [Performance](#performance)
- [Security model](#security-model)
- [Known limitations](#known-limitations)
- [Repository layout](#repository-layout)
- [Documentation map](#documentation-map)
- [Specs this implements](#specs-this-implements)

---

## What it does

Every incoming request gets one of four **outcomes**:

| Outcome | Meaning |
| --- | --- |
| `unsigned` | No signature at all. A human browser, or an old-style bot. |
| `verified` | Signature and key material check out. We know which operator this is. |
| `invalid` | Something failed: bad signature, expired, replayed nonce, forged key id, malformed header. |
| `unverified` | We could not decide: the operator's directory was unreachable, the key is not published, the algorithm is unsupported. |

Your policy turns an outcome (plus tag, operator, path, method, user agent) into one of four
**decisions**:

| Decision | HTTP | Use |
| --- | --- | --- |
| `allow` | passes through | normal traffic |
| `block` | 403 | forged signatures, spoofed AI user agents |
| `rate_limit` | 429 | traffic you cannot verify yet |
| `charge` | 402 + price header | agents hitting an endpoint you want to bill for |

Every decision is appended to a SQLite audit log where each row hashes the previous one, so
any later edit, deletion or reordering is detectable. A built-in dashboard shows the traffic
and the chain status.

## Quick start

Requirements: **Python 3.11+**, **Node 18+** (for the Cloudflare cross-checks), optionally
**Rust/cargo** (for the second cross-check). Tested on macOS with Python 3.14 and Node 24.

```bash
git clone https://github.com/Dizi-dev/KYA-POC.git
cd KYA-POC
scripts/verify.sh              # offline: spec vectors, unit, security, interop, demo, benchmark
scripts/verify.sh --network    # also: live Cloudflare server, real key directories, surveys, drift
```

`verify.sh` creates `.venv`, installs dependencies, runs every layer and writes
[`evidence/SUMMARY.md`](evidence/SUMMARY.md) with a PASS/FAIL per step and sha256 hashes of
every log it produced. A non-zero exit code means something failed.

Three ways to watch it work:

```bash
.venv/bin/python -m demo.run_demo      # scripted end-to-end demo, self-checking
.venv/bin/python -m demo.live          # interactive panel at http://127.0.0.1:8002
.venv/bin/python -m examples.walkthrough   # production mode against live ChatGPT/Google keys
```

The scripted demo prints what the gateway decided for each kind of traffic, then tampers with
its own audit database to show the chain break:

```
 1. Acme agent browses a product (signed)          200  outcome=verified   decision=allow
 2. Acme agent checks out (TAP agent-payer-auth)   200  outcome=verified   decision=allow
 3. Acme agent pulls the price API (signed)        402  outcome=verified   decision=charge
 4. Attacker replays request 1 headers             403  outcome=invalid    decision=block
 5. Attacker forges Acme's identity                403  outcome=invalid    decision=block
 6. Scraper sends 'GPTBot' User-Agent, no signature 403 outcome=unsigned   decision=block
 7. Unknown agent, directory offline (try 3)       429  outcome=unverified decision=rate_limit
 8. Human with a normal browser                    200  outcome=unsigned   decision=allow
 9. Acme rotates: request signed with NEW key      200  outcome=verified   decision=allow
 9. Acme rotates: OLD key still published          200  outcome=verified   decision=allow
 9. OLD key after Acme removed it (cache expired)  429  outcome=unverified decision=rate_limit
Audit chain: 13 entries, chain intact
After editing entry 5 in the database: chain broken at entry 5
```

`demo.live` is the one to show a person: buttons fire real requests at a protected demo shop
while the gateway's dashboard updates beside them.

## Use it in your app

The integration is a few lines on an existing FastAPI or Starlette app. Full example:
[`examples/my_shop.py`](examples/my_shop.py).

```python
from fastapi import FastAPI
from kya_gateway import AuditLog, KeyResolver, PolicyEngine, Verifier
from kya_gateway.middleware import KYAMiddleware

app = FastAPI()

app.add_middleware(
    KYAMiddleware,
    verifier=Verifier(KeyResolver()),              # production mode: HTTPS-only, SSRF rules on
    policy=PolicyEngine.from_yaml("policy.yaml"),
    audit=AuditLog("kya_audit.db"),
    log_only=True,                                 # start here: decide but never block
)
```

**Start in `log_only=True`.** The gateway still verifies, decides and logs, but never blocks
or charges. That is how a site measures its real agent traffic before enforcing anything.

Responses carry `KYA-Outcome`, `KYA-Decision`, and where known `KYA-Operator` and `KYA-Price`.

### Configuration

| Setting | Where | Default | Notes |
| --- | --- | --- | --- |
| `log_only` | middleware arg | `False` | Decide and log, never enforce. |
| `admin_token` | middleware arg or `KYA_ADMIN_TOKEN` | unset | Unset means `/_kya/*` returns 404. |
| `dev_mode` | `KeyResolver(dev_mode=True)` | `False` | Allows http and localhost directories. **Local demos only.** |
| `max_signatures` | `Verifier(max_signatures=N)` | `3` | Cap on signature labels per request. |
| `max_validity_s` | `Verifier(...)` | `86400` | Reject signatures valid for longer. |
| `require_nonce` | `Verifier(...)` | `False` | Require a nonce for replay protection. |
| `allowed_directories` | `KeyResolver(...)` | `None` | Optional allowlist of directory origins (exact match). |
| `default_ttl_s` | `KeyResolver(...)` | `300` | Cache lifetime when a directory sends no `Cache-Control`. |

### Admin endpoints

All under `/_kya/`, all requiring `Authorization: Bearer $KYA_ADMIN_TOKEN`. With no token
configured they return 404, so a fresh install exposes nothing.

| Path | Returns |
| --- | --- |
| `/_kya/dashboard` | Server-rendered HTML: traffic by outcome, decision and operator, plus the chain status |
| `/_kya/audit.json` | The full audit log as JSON |
| `/_kya/verify-chain` | `{"intact": bool, "detail": "..."}` |

## Writing policy

First matching rule wins; `default` applies if nothing matches. See
[`policy.yaml`](policy.yaml) for the shipped demo policy.

```yaml
default: allow
rules:
  - name: block-invalid-signatures
    match: {outcome: invalid}
    action: block
    message: signature failed verification

  - name: block-spoofed-ai-agents
    match: {outcome: unsigned, user_agent_contains: [GPTBot, ClaudeBot, PerplexityBot]}
    action: block

  - name: charge-agents-for-price-api
    match: {outcome: verified, path: "/api/*"}
    action: charge
    price: "0.002 USD"

  - name: limit-unverified
    match: {outcome: unverified}
    action: rate_limit
    limit: 2
    window_s: 60
```

Match fields: `outcome`, `tag`, `operator`, `path` (glob), `method`, `user_agent_contains`.
Each accepts a single value or a list.

**`operator` matches exactly**, by full directory URL, by origin (`https://acme.com`) or by
host (`acme.com`). It is deliberately not a substring match: a directory at
`https://acme.com.attacker.io` must never satisfy a rule meant for `acme.com`.

**Rate limits bucket unproven traffic by client**, never by the agent's own key id, which the
attacker chooses. The middleware derives an opaque client key from a salted hash of the IPv4
/24 or IPv6 /48 prefix; the raw IP never reaches the policy engine or the log. Behind a
reverse proxy you must feed it the real client address, or every visitor shares one bucket.

## How it works

```
request
  │
  ├─ sigbase.py   rebuild the RFC 9421 signature base from the covered components
  ├─ verifier.py  check tag, required params, freshness, label cap, nonce replay
  ├─ keys.py      find the operator's public key: static, or fetch their published directory
  │                 (HTTPS only, public IPs only, no redirects, 64 KB / 32 key caps, 3 s timeout,
  │                  Cache-Control honoured including no-store)
  ├─ verifier.py  Ed25519 verify against the rebuilt base  ──▶ outcome
  ├─ policy.py    first-match YAML rules                    ──▶ decision
  ├─ audit.py     append {outcome, decision, operator, keyid, tag, path, rule} + hash chain
  └─ middleware.py  KYA-* response headers, enforcement, /_kya/* admin
```

| Module | Job |
| --- | --- |
| [`kya_gateway/sigbase.py`](kya_gateway/sigbase.py) | RFC 9421 signature base: `@authority`, `@method`, `@path`, `@target-uri`, `@query`, headers, dictionary members |
| [`kya_gateway/keys.py`](kya_gateway/keys.py) | Key discovery: static JWKs, `Signature-Agent` directories and `jwks_uri`; SSRF guard; cache with real HTTP semantics |
| [`kya_gateway/verifier.py`](kya_gateway/verifier.py) | The four outcomes, freshness window, nonce replay store, label cap, Ed25519 verification |
| [`kya_gateway/policy.py`](kya_gateway/policy.py) | First-match rules; allow / block / rate_limit / charge; rate-limit bucketing |
| [`kya_gateway/audit.py`](kya_gateway/audit.py) | SQLite hash chain, `verify_chain()`, JSON export |
| [`kya_gateway/middleware.py`](kya_gateway/middleware.py) | ASGI glue, response headers, client key derivation, admin endpoints, dashboard |
| [`kya_gateway/signer.py`](kya_gateway/signer.py) | Agent-side signer used by the demo and the interop tests |

Deeper detail, including the threat model and the extension points for new proof types:
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Protocol coverage

| Proof | What it establishes | Status |
| --- | --- | --- |
| **Web Bot Auth** (IETF draft, Ed25519) | Which operator the agent belongs to | **Implemented and tested**, including the draft-00 dictionary `Signature-Agent`, the legacy string form, and no-header requests |
| **Visa Trusted Agent Protocol** | Identity plus browse-vs-pay intent | **Partial**: the `agent-browser-auth` and `agent-payer-auth` tags are accepted and policy can match on them. The shopper-recognition token and RSA-PSS keys are not implemented |
| **Skyfire KYAPay** | Who delegated, and the spend limit | Not implemented. Spec and keys are public, so it is buildable |
| **Google AP2** | The person approved this purchase | Not implemented, and currently not buildable: the spec does not define how a merchant obtains verification keys |

Ed25519 is the only algorithm implemented. That covers the entire observed ecosystem today:
all 100 keys found in the September 2026 survey were Ed25519. RSA-PSS and EC support are
prerequisites for the Visa and Skyfire work.

## What is proven, and how to re-prove it

Run `scripts/verify.sh --network`. Every row below names the command and the file it writes.

| Claim | Command | Evidence |
| --- | --- | --- |
| IETF draft Appendix C.2 vectors pass, plus unit and security regressions | `pytest -m "not interop and not network"` | `evidence/pytest-offline.log` (51 tests) |
| Interoperable with Cloudflare's JavaScript library, both directions, tampering rejected | `pytest -m interop` | `evidence/pytest-interop.log` (7 of 15) |
| Interoperable with Cloudflare's Rust crate `web-bot-auth` 0.7.0, both directions | `pytest -m interop` | `evidence/pytest-interop.log` (8 of 15) |
| Cloudflare's live research server accepts our signatures | `KYA_NETWORK=1 pytest -m network` | `evidence/pytest-network.log` |
| Every decision in the demo is correct; tampering is detected | `python -m demo.run_demo` | `evidence/demo.log`, `evidence/demo.json` |
| Production mode blocks forged ChatGPT and Google agents using their live published keys | `python -m examples.walkthrough` | `evidence/walkthrough.log`, `evidence/walkthrough.json` |
| 87 of 96 registered signing operators load under production rules | `python -m research.survey_directories --dataset` | `evidence/signed_agents_survey.json` |
| Verification cost | `python -m bench.verify_bench` | `evidence/bench.json` |
| The three baseline ecosystem surprises still hold | `python -m research.drift_check` | `evidence/drift.json` |

Baseline results from before the hardening work are kept in
[`evidence/baseline-2026-09-22/`](evidence/baseline-2026-09-22/) for comparison. The full
hardening write-up, including every security finding, is
[`docs/HARDENING_REPORT.md`](docs/HARDENING_REPORT.md).

## What we learned about the ecosystem

Full detail with commands and dates: [`research/FINDINGS.md`](research/FINDINGS.md).

- **96 operators publish key directories; 87 load cleanly here.** The 9 that fail do so
  because they redirect, publish under a sub-path, 404, 403, or fail DNS. The gateway refuses
  redirects on purpose (draft section 5.8).
- **Key directories usually are not on the company's main domain.** Google signs from
  `agent.bot.goog`; AWS Bedrock AgentCore uses one host per region under `*.on.aws`; Manus
  uses `api.manus.im`. Searching apex domains finds almost nothing. Use the `Signature-Agent`
  header or a registry.
- **All 100 published keys are Ed25519.**
- **Caching differs wildly.** Most send `max-age=86400`, but 11 send `no-store`, including
  ChatGPT, whose keys also expire about 7 days out. Honouring `no-store` literally means a
  live fetch per request, measured at a 340–430 ms median.
- **Formats disagree.** Cloudflare's live test server still rejects the draft-00 dictionary
  `Signature-Agent` form and accepts only the older string form. Cloudflare's own directory
  publishes `nbf` in milliseconds. Four operators, Google included, publish a `kid` that is
  not the RFC 7638 thumbprint that verifiers index by.
- **Content negotiation bites.** Klaviyo's directory returns 406 unless you send the
  directory media type in `Accept`. That bug made one real operator unverifiable until fixed.

## Performance

10,000 verifications with a cached key, Apple M4 Pro, Python 3.14.7
([`evidence/bench.json`](evidence/bench.json)):

| Metric | Value |
| --- | --- |
| p50 | 0.171 ms |
| p95 | 0.201 ms |
| Throughput, single core | ~5,700 verifications/second |

That is the cached path. An uncached directory fetch costs 340–430 ms median against
ChatGPT, and today it blocks the event loop. See [Known limitations](#known-limitations).

## Security model

Enforced today, with tests:

- **SSRF**: directories must be HTTPS and resolve to public addresses; private, loopback,
  link-local, reserved and multicast ranges are refused; no redirects are followed; 3 s
  timeout; 64 KB body cap; 32 key cap.
- **Replay**: nonces are remembered until the signature expires; signatures older than 24 h
  by default are rejected; clock skew tolerance is 60 s.
- **Work limits**: at most 3 signature labels per request, checked before parsing or any key
  lookup, so a request cannot trigger unbounded fetches.
- **Identity**: a key is always the pair (directory URL, key), never the key alone. Known RFC
  9421 test keys are refused outside `dev_mode`. HMAC is refused.
- **Admin surface**: `/_kya/*` requires a bearer token and returns 404 when none is set;
  token comparison is constant-time.
- **Privacy**: the audit log records method, path, outcome, reason, operator, key id, tag,
  decision and rule. No bodies, no raw IPs, no cookies, no user identifiers.

`dev_mode=True` disables the transport and SSRF restrictions so the offline demo can talk to
`http://127.0.0.1`. **Never enable it in production.**

Full threat model and the list of fixed and open findings:
[`docs/SECURITY.md`](docs/SECURITY.md).

## Known limitations

Ordered by how much they matter before a pilot.

1. **Directory fetches block the event loop.** `httpx.Client` is synchronous and sits inside
   `async dispatch`. With ChatGPT's `no-store` directory that is a ~400 ms stall on every
   ChatGPT request, during which nothing else is served. Fixing this is the top item in
   [`DEVELOPERS.md`](DEVELOPERS.md).
2. **No fetch coalescing.** Many simultaneous requests naming the same uncached directory
   each trigger their own fetch.
3. **Single process only.** The nonce store and the rate limiter are in-memory, and the audit
   log's ordering lock is per process. Multiple workers need shared stores and
   `BEGIN IMMEDIATE`.
4. **No RSA-PSS or EC keys**, so Visa TAP's and Skyfire's key material cannot be read.
5. **DNS rebinding window** between the SSRF check and the connection.
6. **`@authority` comes from the Host header**, which a reverse proxy may rewrite.
7. **`charge` returns 402 with a price**, it does not collect payment.
8. **The audit log detects edits but cannot stop file deletion.** External anchoring of the
   head hash is the next step.
9. **No genuine third-party agent request has been observed end to end.**

## Repository layout

```
kya_gateway/     the middleware itself (about 900 lines)
demo/            scripted demo, interactive panel, demo agent directory and store
examples/        production-mode integration example and a live-internet walkthrough
tests/           spec vectors, security regressions, interop with JS and Rust
interop/js/      Cloudflare's web-bot-auth 0.2.0, used as a reference implementation
interop/rust/    CLI around Cloudflare's web-bot-auth 0.7.0 crate, same purpose
research/        directory surveys, ecosystem drift checks, findings write-up
bench/           verifier latency benchmark
scripts/         verify.sh, the one command that proves everything
evidence/        machine-written proof: logs, JSON, JUnit XML, sha256 hashes
docs/            architecture, security, roadmap, context, reports
```

## Documentation map

| File | Read it when |
| --- | --- |
| [`DEVELOPERS.md`](DEVELOPERS.md) | You are picking this up: setup, every test layer, living checks, next steps |
| [`AGENTS.md`](AGENTS.md) | You are a coding agent working in this repo |
| [`DEMO.md`](DEMO.md) | You are showing it to someone in three minutes |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | You need the request lifecycle and module internals |
| [`docs/SECURITY.md`](docs/SECURITY.md) | You need the threat model and finding history |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | You need what is next and why, in order |
| [`docs/CONTEXT.md`](docs/CONTEXT.md) | You need the product and market context |
| [`docs/HARDENING_REPORT.md`](docs/HARDENING_REPORT.md) | You want the proof table and what changed on 22 Sep 2026 |
| [`docs/BASELINE_FINDINGS.md`](docs/BASELINE_FINDINGS.md) | You want the pre-hardening baseline |
| [`research/FINDINGS.md`](research/FINDINGS.md) | You want the ecosystem research with commands and dates |

## Specs this implements

| Spec | Used for |
| --- | --- |
| [draft-meunier-webbotauth-httpsig-protocol-00](https://www.ietf.org/archive/id/draft-meunier-webbotauth-httpsig-protocol-00.html) | Required parameters, `Signature-Agent`, discovery types, SSRF rules (5.8), outcomes (A.1), caching (A.4, A.5), test vectors (Appendix C) |
| [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421) | Signature base (2.5), components (2.1, 2.2), verification (3.2), test keys (Appendix B.1) |
| [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638) and [RFC 8037 A.3](https://www.rfc-editor.org/rfc/rfc8037#appendix-A.3) | `keyid` as the JWK SHA-256 thumbprint |
| [RFC 9111](https://www.rfc-editor.org/rfc/rfc9111) section 5.2.2 | `Cache-Control` handling on directory fetches |
| [Visa Trusted Agent Protocol](https://developer.visa.com/capabilities/trusted-agent-protocol) | Tag values for browse and pay intent |
| [Cloudflare web-bot-auth](https://github.com/cloudflare/web-bot-auth) | Reference implementations used for interop |

Ambiguities are marked `SPEC-QUESTION:` in the code and listed in
[`docs/HARDENING_REPORT.md`](docs/HARDENING_REPORT.md).

---

**License:** not yet chosen. See [`DEVELOPERS.md`](DEVELOPERS.md) for the open decision.
