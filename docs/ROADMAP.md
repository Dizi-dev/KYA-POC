# Roadmap

Where this goes, in order, with the reason each item is where it is. Acceptance tests for the
near-term items are in [`../DEVELOPERS.md`](../DEVELOPERS.md#next-steps-in-order). The
original pre-hardening plan is kept at
[`archive/ORIGINAL_ROADMAP.md`](archive/ORIGINAL_ROADMAP.md).

Sequenced by what the ecosystem has settled, not by what is most fun to build: agent identity
is settled, payment intent is settling now, user-approval mandates are not settled at all.

## Now: working and proven

| Capability | State |
| --- | --- |
| Web Bot Auth verification (Ed25519), all three `Signature-Agent` forms | Done, spec vectors and two independent implementations agree |
| Key discovery: static keys, `directory`, `jwks_uri`; SSRF rules; HTTP-correct caching | Done |
| Four outcomes, freshness, nonce replay, label cap | Done |
| Visa TAP intent tags (`agent-browser-auth`, `agent-payer-auth`) readable by policy | Done |
| Policy engine: allow, block, rate_limit, charge | Done |
| Hash-chained audit log, chain verification, JSON export | Done |
| Dashboard and admin endpoints behind a bearer token | Done |
| One-command evidence (`scripts/verify.sh`) | Done |

## Next: before anyone runs this in front of real traffic

1. **Async key resolution and non-blocking audit writes (D3).** Today a single slow
   directory stalls the whole process, and ChatGPT's `no-store` policy makes that the common
   case rather than the rare one.
2. **Fetch coalescing and per-host limits (D6).** One in-flight fetch per directory.
3. **A decided, documented `no-store` policy.** Spec-literal behaviour costs 340–430 ms per
   ChatGPT request. Choose a floor, background refresh, or stale-while-revalidate, and write
   the deviation down.
4. **Shared state (D7 and multi-worker).** Redis-backed nonce and rate-limit stores;
   `BEGIN IMMEDIATE` for audit appends.
5. **Proxy-aware deployment (D8, E9).** Trusted host header, and a real client address for
   rate-limit bucketing.
6. **DNS rebinding fix (D4).** Resolve once, connect to that address.

## Then: make the pitch true

7. **Public pilot.** Deploy the example shop in `log_only` mode and get a genuine third-party
   agent to visit it. This answers the two open ecosystem questions (which `keyid` form real
   operators send, and whether anything verifies end to end) and produces the first real
   number for how much signed traffic a small site sees.
8. **RSA-PSS and EC key support.** Prerequisite for both payment proofs; also unlocks the
   draft's Appendix C.1 vectors.
9. **Visa Trusted Agent Protocol, fully.** The shopper-recognition token alongside the
   signature, not just the intent tag.
10. **Skyfire KYAPay.** A signed JWT with delegation and spend limits; spec and keys are
    public, so verification is buildable without an account (collecting the money is not).
11. **The common claim and adapter interface.** `operator, keyid, tag, intent, user_ref,
    scope, proof_type`, with each protocol as an adapter. Policy gains `intent`, `user_ref`
    and `scope` matching plus an action that requires a payment proof. Audit, dashboard and
    middleware stay unchanged.

## Later: product surface

12. **Packaging.** `pyproject.toml`, a `kya` console script, published to PyPI.
13. **Pure ASGI middleware**, so streaming responses pass through untouched.
14. **Dashboard v1.** Filters by outcome, decision, operator and time; per-operator daily
    counts; verified share of agent traffic.
15. **Audit log v1.** External anchoring of the head hash, a retention policy with a signed
    "truncated before" marker, and `kya audit export --from --to` for disputes.
16. **Reverse-proxy mode.** `kya proxy --upstream http://localhost:3000`, for the many sites
    that cannot add Python middleware.
17. **Real charging.** Today `charge` returns 402 with a price. Collecting requires picking a
    settlement path (Skyfire, x402, or a card rail).

## Watching, not building

- **Google AP2.** The specification does not define how a merchant obtains the keys needed to
  verify a mandate, and the project's own issue about it is unresolved. Re-check quarterly.
  Building on it now would mean inventing a key-distribution scheme nobody else implements.
- **IETF working group adoption.** The Web Bot Auth draft is still individual-submission.
  When a working-group draft lands, re-read every `SPEC-QUESTION:` comment in the code.
- **Platform commoditisation.** If Cloudflare or Vercel ship free policy plus audit tooling
  for non-customers, the wedge narrows sharply. That is the main strategic risk.

## Explicitly out of scope

Issuing agent identities or running a key directory; behavioural fraud scoring; Shopify
(it verifies Web Bot Auth at its own edge); anything requiring a commercial partnership
before a single line of verification code can run.
