# KYA Gateway: report (22 September 2026)

> **Point-in-time record, 22 September 2026** (previously `REPORT.md` at the repository root).
> It reports the hardening pass that fixed D1, D2, D5, D9 and findings E1–E5, with the proof
> table for every claim. Later changes are not reflected here; current state lives in
> [`../README.md`](../README.md), [`SECURITY.md`](SECURITY.md) and [`ROADMAP.md`](ROADMAP.md).

## 1. Verdict

**It works, with one production blocker.** `scripts/verify.sh --network` ends with
`Overall: PASS` (`evidence/SUMMARY.md`, run 2026-09-22T13:06Z at commit 5ff70ab, macOS arm64,
Python 3.14.7, Node 24). That covers:
- the IETF test vectors;
- two-way interop with Cloudflare's JavaScript and Rust libraries;
- Cloudflare's live test server;
- the self-checking demo, including key rotation;
- a production-mode walkthrough that fetches ChatGPT's and Google's real public keys and
  blocks forgeries of both.

87 of the 96 agent operators registered with Cloudflare publish keys that the gateway loads
today.

**Not yet proven:** that a *genuine* signed request from a real agent verifies end to end. That
needs a public deployment.

**Production blocker:** directory fetches block the server. ChatGPT's keys are `no-store`, so
each ChatGPT request costs a live fetch of 340 to 430 ms (median, measured) during which
nothing else is served (D3, section 8).

## 2. What changed

| Commit | Change |
| --- | --- |
| 16ee01b | baseline: POC as received |
| 8841115 | M0: baseline verified (`verify.sh --network` PASS before any change) |
| c1f0b55 | M1-D1: rate-limit unproven traffic by a salted hash of the client's /24 or /48, not by the attacker-chosen keyid |
| 20bbc52 | M1-D2: `/_kya/*` needs `Authorization: Bearer $KYA_ADMIN_TOKEN` (404 when unset, 401 when wrong) |
| ee518ed | M1-D5: cap signature labels (default 3, configurable), checked before parsing or any key lookup |
| f90326d | M1-D9: honour `Cache-Control` no-store / no-cache / max-age on directory fetches |
| 59fd4f7 | M1-E1..E3: exact operator and allowlist matching; malformed signature params give `invalid`, not a crash |
| 3c37fec | M1-S9: demo scenario 9, key rotation |
| 05b386e | M1-E4: ask for the directory media type (Klaviyo's live directory returned 406); survey extended |
| 3711e1b | M1-E5 + R4: replay store no longer rescans every nonce per request; benchmark added to `verify.sh` |
| 32bbe22 | R3: live drift check |
| 2174b1e | R2: interop with Cloudflare's Rust crate `web-bot-auth` 0.7.0 |
| dfdd059 | `examples/`: production-mode shop and a walkthrough against live directories |
| 5ff70ab | Docs: FINDINGS, candidates, DEMO.md, README |
| (last) | This report, the no-store SPEC-QUESTION note, final evidence |

Deviation from the brief: all defect tests live in one new file, `tests/test_defects.py`,
written before the fixes (they failed at collection, then one group was fixed per commit).
Each commit ran the full pytest suite and the demo. The full `verify.sh --network` ran at M0,
after the fixes (dfdd059) and at the end, not after every single commit.

## 3. Proof table

| Claim | Command | Evidence file | Result |
| --- | --- | --- | --- |
| IETF draft Appendix C.2 vectors and the original security tests pass | `pytest -m "not interop and not network"` | `evidence/pytest-offline.log` | 51 passed (12 original + 39 new) |
| Cloudflare JS library ↔ us, both directions, tampering rejected | `pytest -m interop` | `evidence/pytest-interop.log` | 7 JS tests passed |
| Cloudflare Rust crate 0.7.0 ↔ us, both directions, tampering rejected | `pytest -m interop` | `evidence/pytest-interop.log` | 8 Rust tests passed (15 interop total) |
| Cloudflare's live server accepts our none/legacy forms; rejects the dict form | `KYA_NETWORK=1 pytest -m network`; `python -m research.drift_check` | `evidence/pytest-network.log`, `evidence/drift.json` | 4 passed, 1 expected skip; dict rejected (unchanged) |
| Demo decisions are all correct and tampering is detected | `python -m demo.run_demo --evidence evidence/demo.json` | `evidence/demo.log`, `evidence/demo.json` | `DEMO CHECK: PASS`, chain broken at entry 5 |
| D1: 5 keyids from one client, limit 2 → requests 3 to 5 get `rate_limit`; no raw IP stored | `pytest tests/test_defects.py -k d1` | `evidence/pytest-offline.log` | pass (4 tests) |
| D2: token unset 404, wrong 401, right 200; demo uses a token | `pytest tests/test_defects.py -k d2` | `evidence/pytest-offline.log`, `evidence/demo.log` | pass (10 tests) |
| D5: 1,000 labels → `invalid` / "too many signatures" in under 50 ms; default 3 | `pytest tests/test_defects.py -k d5` | `evidence/pytest-offline.log` | pass (3 tests) |
| D9: no-store/no-cache fetch every time, max-age=60 once per 60 s, missing header → default TTL | `pytest tests/test_defects.py -k d9` | `evidence/pytest-offline.log` | pass (7 tests, local directory server) |
| Key rotation: new key verified, old key verified while published, old key `unverified` after removal | `python -m demo.run_demo` | `evidence/demo.json` (scenario 9) | pass |
| Production mode blocks forged ChatGPT and Google signatures using their live keys | `python -m examples.walkthrough` | `evidence/walkthrough.log`, `evidence/walkthrough.json` | `WALKTHROUGH CHECK: PASS` |
| Verifier cost with a cached key | `python -m bench.verify_bench` | `evidence/bench.json` | p50 0.171 ms, p95 0.201 ms, about 5,700/s per core |
| 87 of 96 registered signers' directories load under production rules | `python -m research.survey_directories --dataset` | `evidence/signed_agents_survey.log` / `.json` | 87/96, 100 keys, all Ed25519 |
| Genuine signed ChatGPT, Google or AgentCore request verifies | none possible locally | none | **unproven** |

## 4. Research findings

Details in [../research/FINDINGS.md](../research/FINDINGS.md); sources in [../research/candidates.md](../research/candidates.md).

- **R1:** Google publishes at `https://agent.bot.goog` (5 keys) and AWS AgentCore at one
  `*.keydirectory.signer.<region>.on.aws` host per region. Both load. The Cloudflare Radar
  mirror lists 96 signers, of which 87 load and 9 fail (redirects, sub-paths, 404/403, DNS).
  Key directories usually live off the company's main domain.
- **R2:** the JS and Rust reference libraries both interoperate with us in both directions.
  The Rust crate rejects Visa TAP tags; we accept them.
- **R3:** all three baseline surprises still hold.
- **R4:** 0.17 ms per verification with a cached key. An uncached ChatGPT fetch costs a
  median of 340 to 430 ms across runs, up to about 1 s.

## 5. Spec questions

| Where | Section | Reading chosen |
| --- | --- | --- |
| `keys.py` `_seconds` | protocol draft 4.5 (directory JWK `nbf`/`exp`) | The unit isn't stated. Values above 1e11 are treated as milliseconds, which Cloudflare's research server, Flowpane and Nostra publish. |
| `verifier.py` `max_signatures` | RFC 9421 7.2.6 and 1.4; the draft gives no number | Cap at 3 labels (stricter). Over the cap → `invalid`, checked before any fetch. |
| `keys.py` `directory_ttl` | draft A.4 ("normal HTTP caching semantics"), RFC 9111 5.2.2 | `no-store` and `no-cache` → fetch again every time (no ETag revalidation yet). This is correct, but costly with ChatGPT; a short floor would be a deliberate deviation. |

## 6. Security findings

Found in review or by the survey, beyond D1 to D9. All are fixed, each with tests in
`tests/test_defects.py`, except where noted.

| ID | Finding | Severity | Status |
| --- | --- | --- | --- |
| E1 | A policy `operator: acme.com` was a substring match, so a directory at `https://acme.com.attacker.io` satisfied it. An attacker's own key would get "Acme" treatment | High (whenever operator rules are used) | fixed: exact URL, origin or host match |
| E2 | `allowed_directories` was a prefix match (`https://acme.com` admitted `acme.com.attacker.io`) | Medium | fixed: exact origin |
| E3 | Wrong-typed params (`created="abc"`, `alg=5`) raised an exception: 500 response, no audit row | Medium | fixed: `invalid` |
| E4 | Gateway sent `Accept: application/json`; Klaviyo's live directory answers 406, so KlaviyoAIBot could never verify | Medium (interop) | fixed |
| E5 | The replay store rebuilt itself on every request, so latency grew linearly with live nonces (0.2 → 1 ms after 20k). Anyone signing valid long-lived requests from their own directory could drive it up | Medium | fixed: heap eviction; 50k nonces in under 1 s |
| D5+ | Each signature label could trigger its own directory fetch, not just CPU work | High | fixed by the D5 cap, which runs before any lookup |
| E6 | Synchronous directory fetch in the event loop: one slow or `no-store` directory stalls every request (the D3 impact) | **High** | **open** (ROADMAP D3/D6) |
| E7 | Signatures without a nonce can be replayed until expiry (`require_nonce=False` by default) | Low | open, documented |
| E8 | Rate-limit and directory-cache tables grow without bound as attackers invent keys or URLs | Low | open |
| E9 | Behind a reverse proxy, every client shares the proxy's address and therefore one rate-limit bucket | Medium (deployment) | documented in `client_key`; needs trusted-proxy config |

## 7. Product feedback for the RFD

- **The ecosystem is real and growing:** 96 registered signers, 87 of them usable today,
  across AI assistants, crawlers, monitoring, security, SEO and agentic commerce (Rye, Nekuda,
  Firmly, Strivve). Google, AWS, Meta, DuckDuckGo, Manus and ChatGPT all sign. That is more
  than the baseline's 2 real directories.
- **Only Ed25519 matters today** (100 of 100 keys). RSA-PSS can wait.
- **Formats in the wild disagree:** the draft-00 dictionary form vs. the legacy form
  (Cloudflare's live server accepts only legacy); `kid` sometimes isn't the thumbprint
  (Google, Nekuda); `nbf`/`exp` sometimes in milliseconds; directories behind redirects or
  sub-paths; strict content negotiation (Klaviyo). **Tolerating this mess is real product
  value**, and the survey is a ready-made regression suite for it.
- **Signing is partial and opt-in.** Google signs only "a subset" of Google-Agent requests
  and tells sites to keep IP and reverse-DNS checks. AgentCore signing is off by default. The
  policy must treat unsigned traffic from known agents as normal for now, not as an attack.
  The shipped rule that blocks unsigned "GPTBot" User-Agents may block real Googlebot or
  GPTBot traffic that is not signed yet.
- **Verification is commoditised.** Cloudflare's JS and Rust libraries and OpenBotAuth are
  free, and Cloudflare, AWS WAF, Akamai, HUMAN and DataDome verify at the edge (third-party
  reports, see FINDINGS). This confirms the RFD: the product is policy, the audit log and the
  dashboard for sites outside those platforms, not verification itself.
- **Biggest unknown, unchanged:** how much signed traffic a small site actually receives.
  `log_only=True` with design partners is still the right first measurement.

## 8. Unknowns and next steps

1. **Deploy `examples/my_shop.py` on a public HTTPS address in `log_only` mode, then point a
   real agent at it.** Candidates: ChatGPT agent mode, an AgentCore Browser session with
   signing enabled, a Browserbase session. This turns "unproven" into proven, and answers
   which `keyid` and Signature-Agent form real agents send.
2. **Fix D3 and D6 (async fetch, one in-flight fetch per directory, connection reuse), and
   decide the `no-store` policy.** Without this, ChatGPT traffic makes every request slow.
   It is the only thing between this POC and a design-partner pilot.
3. **Run 2 to 3 design partners in `log_only` for two weeks** and count signed vs. unsigned
   agent traffic per operator. That is the go/no-go number for the RFD's success gate; nothing
   public provides it.
