# Security model

What this gateway defends against, what it does not, and the full finding history. Code-level
detail is in [`ARCHITECTURE.md`](ARCHITECTURE.md); the hardening narrative is in
[`HARDENING_REPORT.md`](HARDENING_REPORT.md).

## What it is trying to prevent

| Attack | Defence | Test |
| --- | --- | --- |
| Pretending to be a known agent by setting a `User-Agent` | Policy can block `unsigned` requests claiming known AI user agents | demo scenario 6 |
| Forging another operator's identity | Signature must verify against the key published at that operator's own directory | `test_swapped_signature_agent_is_invalid`, walkthrough steps 3 and 7 |
| Replaying a captured signed request | Nonce store, plus `created`/`expires` freshness with a 24 h cap | `test_replayed_nonce_is_invalid`, demo scenario 4 |
| Using the published RFC 9421 test key | Refused outside `dev_mode` | `test_test_key_rejected_outside_dev_mode` |
| Downgrading to a shared secret | HMAC algorithms refused | `test_hmac_rejected` |
| Making the gateway fetch internal services (SSRF) | HTTPS only, public addresses only, no redirects, timeouts and size caps | `test_ssrf_guard_blocks_private_directory` |
| Exhausting the verifier with many signatures | Label cap (default 3) checked before parsing or key lookup | `test_d5_*` |
| Bypassing rate limits by rotating key ids | Unproven traffic is bucketed by an opaque client key | `test_d1_*` |
| Reading or quietly editing the audit log | Bearer-token admin surface; hash-chained rows | `test_d2_*`, demo tamper step |
| Impersonating an operator with a lookalike domain | Exact operator and allowlist matching | `test_e1_*`, `test_e2_*` |

## What it does not defend against

- **Deletion of the audit database.** The chain proves edits, not existence. External
  anchoring of the head hash is on the roadmap.
- **A compromised operator.** If ChatGPT's signing key leaks, anything signed with it
  verifies. That is the trust model of the standard, not a gateway bug.
- **Unsigned abuse.** Scrapers that simply do not sign are outside this system; it tells you
  who *is* real, it does not stop who is not.
- **Application-layer attacks.** This is an identity and policy layer, not a WAF.
- **Traffic analysis or behavioural fraud.** Explicitly out of scope.

## Privacy stance

The audit log stores `ts, method, path, outcome, reason, operator, keyid, tag, decision,
rule`. It deliberately does not store request bodies, raw IP addresses, cookies, query
strings or user identifiers. Rate limiting uses a per-process salted hash of the IPv4 /24 or
IPv6 /48 prefix, so buckets cannot be reversed into addresses and do not survive a restart.
A regression test asserts that no raw IP reaches the log.

Paths can still contain identifiers in some applications (`/orders/12345`). If that matters
for a deployment, hash or truncate the path before it reaches `AuditLog.append`.

## Finding history

All findings below were discovered during the September 2026 review and hardening pass.
"Fixed" means a regression test exists and runs in the default suite.

### Fixed

| ID | Finding | Severity | Fix |
| --- | --- | --- | --- |
| D1 | Rate limits keyed on the attacker-chosen `keyid`; rotating it bypassed the limit entirely | High | Bucket unproven traffic by a salted hash of the client address prefix |
| D2 | `/_kya/*` exposed the audit log and dashboard to anyone | High | Bearer token required; 404 when unset, 401 when wrong, constant-time compare |
| D5 | No cap on signature labels; each label could also trigger its own directory fetch | High | Cap of 3 (configurable), checked before parsing or key lookup |
| D9 | `Cache-Control: no-store` / `no-cache` ignored; stale keys served after rotation | Medium | Full `Cache-Control` handling, `max-age` capped at 24 h |
| E1 | Policy `operator` matched substrings, so `https://acme.com.attacker.io` satisfied a rule for `acme.com` | High | Exact URL, origin or host matching |
| E2 | `allowed_directories` matched prefixes, with the same lookalike problem | Medium | Exact origin or full-URL comparison |
| E3 | Wrong-typed signature parameters (`created="abc"`, `alg=5`) raised exceptions: HTTP 500 and no audit row | Medium | Types validated per RFC 9421 §2.3; malformed input is `invalid` |
| E4 | The gateway sent `Accept: application/json`; Klaviyo's live directory answers 406, making a real operator permanently unverifiable | Medium | Ask for the directory media type, JSON as fallback |
| E5 | The nonce store rescanned itself on every request: latency grew linearly with live nonces (0.2 ms → 1 ms after 20k) and could be driven up deliberately | Medium | Heap-based eviction; 50k nonces in well under a second |

### Open

| ID | Finding | Severity | Notes |
| --- | --- | --- | --- |
| D3 | Directory fetches and audit writes block the event loop; one slow or `no-store` directory stalls every request | High | Top of the next-steps list in [`../DEVELOPERS.md`](../DEVELOPERS.md) |
| D6 | No fetch coalescing: many requests for the same uncached directory each fetch | Medium | Same work item as D3 |
| D4 | DNS rebinding window between the SSRF check and the connection | Medium | Resolve once, connect to that IP with the original Host and SNI |
| D7 | Audit appends are serialised per process, so two workers can write the same `prev_hash` | Medium | `BEGIN IMMEDIATE` around read-prev and insert |
| D8 | `@authority` comes from the `Host` header, which a reverse proxy may rewrite | Medium | Needs a `trusted_proxy_host_header` option |
| E7 | Signatures without a nonce can be replayed until they expire; `require_nonce` is off by default | Low | Turn it on where operators reliably send nonces |
| E8 | Rate-limit and directory-cache tables grow without bound under adversarial input | Low | Bound them, or move to a store with TTLs |
| E9 | Behind a reverse proxy, every client shares one rate-limit bucket | Medium (deployment) | Configure the real client address; documented in `client_key` |

## Operational guidance

- **Run new installs with `log_only=True`.** Enforcement mistakes on a design partner are
  expensive and avoidable.
- **Set `KYA_ADMIN_TOKEN` to a long random value** and rotate it periodically. It is the only
  thing standing between the internet and the audit log.
- **Never enable `dev_mode` outside a local demo.** It allows plain HTTP and localhost
  directories, which disables the SSRF protections by design.
- **Back up the audit database.** The chain detects edits; it cannot survive `rm`.
- **Verify the chain on a schedule** (`/_kya/verify-chain` or `AuditLog.verify_chain()`), not
  only when you suspect something.
- **Watch the outcome mix.** A sudden rise in `unverified` usually means an operator's
  directory changed or broke, not that you are under attack.

## Reporting a vulnerability

This is a proof of concept without a published disclosure process yet. Until one exists,
report privately to the repository owner rather than opening a public issue, and include the
request that triggered it (headers only, no bodies).
