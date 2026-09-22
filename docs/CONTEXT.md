# Product context (condensed from RFD 1 and the pre-build research)

Full docs: RFD 1: KYA Gateway (https://claude.ai/code/artifact/56219d5a-dcfc-4a83-8d0a-f95fcc7cdf9a)
and KYA Gateway: Pre-build Research (https://claude.ai/code/artifact/7c1a1cfb-6385-4ecc-ab26-8226078c3962).

## The idea in one paragraph

AI agents now browse, shop, and call APIs for people. Sites cannot tell a real agent from a
scraper using its User-Agent string. The emerging answer is cryptographic agent identity
("Know Your Agent"): the agent signs each request (RFC 9421 HTTP Message Signatures, profiled
by the IETF Web Bot Auth draft) and publishes its public keys. Big platforms verify this for
their own customers (Cloudflare, Shopify, DataDome, HUMAN). KYA Gateway is middleware for
everyone else: self-hosted stores, small APIs, MCP servers. It verifies agents, applies a
per-agent policy (allow, block, rate-limit, charge), and keeps a tamper-evident audit log.

## Protocols that matter

| Standard | What it proves | Where the proof is | In POC |
| --- | --- | --- | --- |
| Web Bot Auth (IETF draft, June 2026) | Agent operator identity | Signed HTTP headers | Yes |
| Visa Trusted Agent Protocol | Identity plus browse vs pay intent (`agent-browser-auth`, `agent-payer-auth` tags) | Signed HTTP headers, built on Web Bot Auth | Tags accepted |
| Skyfire KYAPay | Operator, user delegation, spend scope | Signed JWT | No (roadmap spike) |
| Google AP2 | The user approved this spend | Signed mandate in body | No (roadmap spike) |
| Mastercard Agent Pay | Identity inside the card token | Payment rail, invisible to merchant | Out of scope |

## Competition and positioning

- Shopify verifies Web Bot Auth at its edge (May 2026), so Shopify stores are not a market.
- Cloudflare counts signed agents as verified bots (July 2026); DataDome, HUMAN, CHEQ sell to mid-market and enterprise.
- An open-source Python verifier (OpenBotAuth, v0.1.0) exists, so verification alone is free.
  We charge for policy, audit log, and dashboard.

## Ground rules of the venture that constrain scope

Bootstrapped, three people, no military or gambling, geography-independent. Success gate:
1,000 paying users or 2 paying B2B clients. Demo week: one person builds a working demo in 7 days.

## Biggest unknown

How much signed agent traffic actually reaches a small store or API today. The gateway's
`log_only=True` mode exists to measure this with design partners.
