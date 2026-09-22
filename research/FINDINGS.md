# Research findings (22 September 2026)

Every finding can be reproduced with `scripts/verify.sh --network` (last run 2026-09-22T13:06Z,
commit 5ff70ab, `evidence/SUMMARY.md` = PASS) or with the single command listed.

## R1: who signs today

**Command:** `python -m research.survey_directories --dataset --out evidence/signed_agents_survey.json`
**Evidence:** `evidence/signed_agents_survey.json`, `evidence/signed_agents_survey.log` (checked 2026-09-22T13:05Z)

- The Cloudflare Radar mirror lists **705 bots; 96 name a Web Bot Auth key directory**.
- **87 of those 96 load cleanly in the gateway under production rules** (HTTPS, public IPs,
  no redirects, size caps). Together they publish **100 usable keys**. The 87 cover 66
  distinct operator names.
- **Every one of the 100 published keys is Ed25519.** The POC supports only Ed25519, and
  today that covers the whole observed ecosystem. RSA-PSS support (ROADMAP M1) is not urgent.
- Categories of the 87 that load: AI assistants 30, monitoring 12, AI crawlers 7, security 7,
  search crawlers 6, SEO 5, AI search 5, aggregators 5, other 10.
- **Why the other 9 fail:**
  - 3 publish somewhere other than the origin root, or behind a redirect: Cledara (308),
    PureConsent (302), WindowsForum (`.../index.json`, 403).
  - 2 return 404: Cloudflare Radar URL Scanner, Novellum.
  - 1 returns 403: Hark.
  - 3 fail DNS or time out: Quartr, sourcedash, Twin.
  - The gateway refuses redirects on purpose (draft 5.8), so the redirect cases stay
    unverifiable unless those operators fix their setup.
- **Google:** `https://agent.bot.goog` serves 5 Ed25519 keys and loads fine
  (`evidence/directory_survey.json`). Google is **not** in the Radar mirror.
- **Amazon Bedrock AgentCore:** one directory per AWS region on
  `*.keydirectory.signer.<region>.on.aws`. Both regions probed load, with 1 key each.
- **Key directories are rarely on the company's main domain.** Examples: agent.bot.goog,
  *.on.aws, api.manus.im, api.anchorbrowser.io, nekuda-agent-registry.onrender.com. That is
  why the baseline found nothing at google.com, amazon.com or manus.im. You find operators
  through the `Signature-Agent` header or a registry like Radar, not by guessing hostnames.
- **Caching:** most directories send `max-age=86400` (31) or `max-age=3600` (10). 11 send
  `no-store`, including ChatGPT agent and Link CLI. 7 send no Cache-Control header.
- **Key IDs:** 4 operators publish a `kid` that is not the RFC 7638 thumbprint: Google (all 5
  keys, e.g. `mhxuPw`), Nekuda, Platebreaker and Pricey. The gateway, like Cloudflare's Rust
  crate (`keyring.rs` `try_import_jwk`), indexes keys by thumbprint. If one of these agents
  sends its `kid` as `keyid`, both verifiers return "key not published". **Unknown:** which
  value Google puts in `keyid`. Only a real signed Google request answers that.
- **Accept header bug found by the survey:** Klaviyo's directory answers **406** to
  `Accept: application/json`, which is what the gateway sent. Fixed in commit 05b386e with
  test `test_e4_directory_fetch_accepts_draft_media_type`. After the fix, Klaviyo loads.

## R2: interop matrix

**Command:** `python -m pytest -q -m interop`
**Evidence:** `evidence/pytest-interop.log` (15 passed)

| Other implementation | They sign → we verify | We sign → they verify | Tampered signature rejected |
| --- | --- | --- | --- |
| Cloudflare `web-bot-auth` 0.2.0 (npm) | pass | pass (dict, dict+@method @path, legacy, none) | pass |
| Cloudflare `web-bot-auth` 0.7.0 (Rust crate, `interop/rust/`) | pass (2 URLs) | pass (same 4 forms) | pass; a swapped Signature-Agent is also caught on our side |

The Rust crate only accepts `tag="web-bot-auth"`. It rejects Visa TAP's `agent-browser-auth`
and `agent-payer-auth` ("No matching label"). Found with a manual check. Our gateway accepts
all three tags.

## R3: drift check

**Command:** `python -m research.drift_check --out evidence/drift.json`
**Evidence:** `evidence/drift.json` (checked 2026-09-22T13:06Z) and `evidence/drift.log`

| Baseline surprise | Still holds? | Observed |
| --- | --- | --- |
| Cloudflare's live server rejects the dictionary Signature-Agent form | yes | none: accepted, legacy: accepted, dict: rejected |
| Cloudflare's research directory publishes `nbf` in milliseconds | yes | `nbf=1743465600000` |
| ChatGPT's keys expire about 7 days out, with `no-store` | yes | `no-store, no-transform`, exp in 7.0 days |

Also seen: 3 keys in the wider survey publish `nbf`/`exp` in milliseconds (Flowpane, Nostra),
so the milliseconds heuristic in `keys.py` matters beyond Cloudflare's test server.

## R4: verifier cost

**Command:** `python -m bench.verify_bench --out evidence/bench.json`
**Evidence:** `evidence/bench.json` (measured 2026-09-22T13:04Z, Apple M4 Pro, Python 3.14.7)

- 10,000 verifications with a cached key: **p50 0.171 ms, p95 0.201 ms**, about 5,700 per
  second on one core. Meets the ROADMAP target of p95 < 1 ms.
- **Before fix E5**, latency grew with the number of stored nonces: 0.20 ms → 0.97 ms after
  20,000 requests. The replay store rescanned itself on every request; it is now a heap.
- **Uncached cost is far higher and dominates in practice.** A live fetch of ChatGPT's
  directory through the gateway's code path took **median 431 ms, max 1,035 ms** (10 samples,
  `evidence/drift.json` → `chatgpt_directory_fetch`, 2026-09-22T13:06Z; earlier runs gave
  medians of 339 ms and 403 ms). ChatGPT sends `no-store`, so every ChatGPT request pays this. The POC
  fetches synchronously inside the event loop (D3), so it stalls all other requests during
  that time.

## Unknowns (not measurable from a public endpoint)

- How much signed agent traffic actually reaches a small store or API. Nothing public gives
  this, and Cloudflare publishes no count of signed requests.
- What `keyid` value Google-Agent sends (thumbprint or the short `kid`).
- Whether any real agent signs with the draft-00 dictionary form in production, or still with
  the legacy string form. Cloudflare's live server accepts only the legacy form.
- Whether a genuine signed request from ChatGPT, Google or AgentCore verifies end to end in
  this gateway. That needs a publicly reachable deployment and a real agent visiting it; see
  REPORT.md next steps.
