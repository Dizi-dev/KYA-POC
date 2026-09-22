# Baseline findings (22 September 2026)

Produced by `scripts/verify.sh --network` before handing the repo to a coding agent.
Raw outputs are in `evidence/baseline-2026-09-22/`. Re-run the same command to check
whether anything below has changed; differences are findings, not failures.

## 1. Spec conformance

- The verifier passes the three Ed25519 test vectors in Appendix C.2 of
  draft-meunier-webbotauth-httpsig-protocol-00 (no Signature-Agent, dictionary
  Signature-Agent, legacy string Signature-Agent).
- keyid computation matches: RFC 9421 test key thumbprint is
  `poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U`, same as the draft.

## 2. Interoperability with Cloudflare's reference library (web-bot-auth 0.2.0, npm)

| Direction | Formats tested | Result |
| --- | --- | --- |
| Cloudflare library signs, our verifier checks | dictionary Signature-Agent with `type=directory`, two URLs | verified |
| Our signer signs, Cloudflare `verify()` checks | dictionary, dictionary + `@method @path`, legacy, none | all accepted |
| Our signer with a corrupted signature, Cloudflare `verify()` | dictionary | rejected (correct) |

## 3. Cloudflare's live research server

`https://http-message-signatures-example.research.cloudflare.com/` verifies requests signed
with the RFC 9421 test key.

| Signature form | Result |
| --- | --- |
| `@authority` only, no Signature-Agent | accepted |
| Legacy string Signature-Agent (older architecture draft) | accepted |
| Dictionary Signature-Agent (June 2026 draft-00), from our signer | **rejected** |
| Dictionary Signature-Agent, from Cloudflare's own library | **rejected** |

Interpretation: the live server lags the current draft; both reference libraries agree with
each other. Our signer therefore supports `agent_format="dict" | "legacy" | "none"`.
Product implication: in the wild, verifiers will see both forms for a while, so ours must
accept both (it does).

## 4. Who publishes key directories (15 origins probed, production SSRF rules)

| Origin | Directory | Notes |
| --- | --- | --- |
| chatgpt.com | yes, 1 Ed25519 key | `purpose: ai`; `Cache-Control: no-store`; key `exp` about 7 days out, so keys rotate weekly |
| www.browserbase.com | yes, 2 Ed25519 keys | `purpose: rag`; `max-age=3600`; bare browserbase.com redirects (the gateway does not follow redirects) |
| Cloudflare research server | yes, 1 key | the RFC 9421 **test key**; `nbf` published in **milliseconds** |
| openai.com, anthropic.com, claude.ai, perplexity.ai, google.com, bing.com, amazon.com, cloudflare.com, browser-use.com, manus.im, skyfire.xyz, visa.com | no directory at the apex or its redirect target | Google reportedly signs crawlers since June 2026, so its keys live elsewhere: open research item |

## 5. Bugs and gaps these findings exposed

- **Fixed before hand-off:** `nbf`/`exp` in milliseconds made the Cloudflare key look "not yet
  valid". Now treated as milliseconds above 1e11, marked `SPEC-QUESTION` in `keys.py`.
- **Open (D9 in ROADMAP):** `Cache-Control: no-store` is ignored; we cache 300 s. With weekly
  key rotation at ChatGPT, this matters.
- **Open (D1):** the unverified-traffic rate limit is keyed on attacker-chosen keyids and can be
  bypassed by rotating them (confirmed: 5 rotating keyids, limit 2, all allowed).

## 6. Test-suite lesson

A first version of the "tampered signature" interop test was flaky: changing one base64
character right before the `==` padding only touches padding bits, so the signature decodes to
identical bytes and correctly still verifies. The test now flips a bit in the decoded bytes and
passed 10 of 10 runs. Anything keyed on the raw `Signature` header text (for example a replay
cache) must decode first, because two different header strings can carry the same signature.
