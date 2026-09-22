# KYA Gateway, proof of concept

Coding agents: start with CLAUDE.md.

Middleware that tells a real AI agent from a spoofed one, applies a per-agent policy, and
keeps an audit log nobody can quietly edit. Built for RFD 1 (KYA Gateway).

## Prove it works (one command)

```bash
scripts/verify.sh            # offline: IETF vectors, unit, Cloudflare interop, self-checking demo
scripts/verify.sh --network  # also: Cloudflare's live test server, real key directories, survey
```

Needs Python 3.11+ and Node 18+ (Node is for the Cloudflare cross-check). Results land in
`evidence/`; `evidence/SUMMARY.md` says PASS or FAIL per step with sha256 hashes of every log.
Baseline results from 22 Sep 2026 are in `evidence/baseline-2026-09-22/` and explained in
`docs/BASELINE_FINDINGS.md`.

## Run pieces by hand

```bash
pip install -r requirements.txt
python -m pytest -q          # IETF Ed25519 test vectors, unit tests, interop (if node_modules present)
python -m demo.run_demo      # end-to-end demo; exits non-zero if any decision is wrong
```

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

Production-mode example against the live ChatGPT and Google key directories (needs internet):
`python -m examples.walkthrough`. The integration itself is `examples/my_shop.py`.

Admin endpoints (`/_kya/dashboard`, `/_kya/audit.json`, `/_kya/verify-chain`) need
`Authorization: Bearer $KYA_ADMIN_TOKEN`. If `KYA_ADMIN_TOKEN` is unset they return 404.
To browse the dashboard:
`KYA_ADMIN_TOKEN=change-me uvicorn demo.store:app --port 8000`, send some traffic, then
`curl -H "Authorization: Bearer change-me" http://127.0.0.1:8000/_kya/dashboard > d.html`.
The demo also writes `dashboard_snapshot.html`.

## Use it in your own FastAPI app

```python
from kya_gateway import AuditLog, KeyResolver, PolicyEngine, Verifier
from kya_gateway.middleware import KYAMiddleware

app.add_middleware(KYAMiddleware,
                   verifier=Verifier(KeyResolver()),
                   policy=PolicyEngine.from_yaml("policy.yaml"),
                   audit=AuditLog("kya_audit.db"),
                   log_only=True)   # start in log-only mode with design partners
# set KYA_ADMIN_TOKEN to enable /_kya/*
```

## How it works

| Module | Job |
| --- | --- |
| `sigbase.py` | Rebuilds the RFC 9421 signature base (`@authority`, `@method`, `@path`, `@target-uri`, headers, dictionary members) |
| `keys.py` | Finds the agent's public key: static keys, or the `Signature-Agent` directory (`directory` and `jwks_uri` types) |
| `verifier.py` | Checks tag, required params, freshness (24h cap), nonce replay, Ed25519 signature; returns unsigned / verified / invalid / unverified |
| `policy.py` | First-match YAML rules: allow, block, rate_limit, charge (HTTP 402) |
| `audit.py` | SQLite log where each row hashes the previous one; `verify_chain()` finds edits |
| `middleware.py` | FastAPI/Starlette glue, `KYA-*` response headers, `/_kya/dashboard`, `/_kya/audit.json`, `/_kya/verify-chain` |
| `signer.py` | Agent-side signer (`agent_format` dict, legacy, or none) used by the demo and interop tests |

| Folder | Job |
| --- | --- |
| `tests/` | `test_ietf_vectors.py` (spec + security), `test_interop.py` (Cloudflare library, live server, real directories) |
| `interop/js/` | Cloudflare's `web-bot-auth` 0.2.0 signer and verifier, used as the reference implementation |
| `interop/rust/` | Cross-check CLI around Cloudflare's Rust crate `web-bot-auth` 0.7.0 (tests skip without cargo) |
| `research/` | `survey_directories.py` (who publishes key directories, `--dataset` for every Radar-registered signer), `drift_check.py`, `FINDINGS.md` |
| `bench/` | `verify_bench.py`: verifier latency, writes `evidence/bench.json` |
| `examples/` | `my_shop.py` (production integration), `walkthrough.py` (live-directory walkthrough) |
| `scripts/verify.sh` | Runs everything and writes `evidence/` |
| `docs/` | Context, baseline findings, longer roadmap |

Safety rules from draft-meunier-webbotauth-httpsig-protocol-00 that are implemented:
HTTPS-only directories, no fetches to private, loopback or link-local addresses, no
redirects, 64 KB and 32-key caps, 3 s timeout, negative cache capped at 5 minutes,
HMAC rejected, the RFC 9421 test key rejected outside `dev_mode`.

## Not in the POC yet

- RSA-PSS keys (Ed25519 only), the `cimd` discovery type, signed directory responses
- KYAPay JWT and AP2 mandate adapters
- Nonce store and rate limiter are in-memory, so single process only (use Redis in production)
- Directory fetches are synchronous and block the event loop (D3); with ChatGPT's `no-store`
  directory that is a live fetch (medians of 340 to 430 ms measured) on every ChatGPT request. Fix before production.
- Behind a reverse proxy, pass the real client address: rate limits key on `request.client`
- The `charge` action returns 402 with a price; it does not collect payment
- Audit log proves edits happened; it does not stop someone deleting the whole file
  (next step: periodically publish the latest hash somewhere external)

`dev_mode=True` in `demo/store.py` allows plain http and localhost directories so the demo
runs offline. Never enable it in production.
