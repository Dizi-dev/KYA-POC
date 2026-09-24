# Architecture

How a request flows, what each module guarantees, and where to extend it. Companion to
[`../README.md`](../README.md) (what it is) and [`SECURITY.md`](SECURITY.md) (threat model).

## Request lifecycle

```
                    ┌────────────────────────────────────────────────┐
  HTTP request ───▶ │ KYAMiddleware.dispatch (middleware.py)         │
                    │  · /_kya/* → admin, bearer token, never logged │
                    │  · client_key = salted hash of IP /24 or /48   │
                    └───────────────┬────────────────────────────────┘
                                    ▼
                    ┌────────────────────────────────────────────────┐
                    │ Verifier.verify (verifier.py)                  │
                    │  1. no Signature headers        → unsigned     │
                    │  2. label count > max_signatures → invalid     │
                    │  3. per label:                                 │
                    │     tag accepted? params typed? fresh?         │
                    │     covers @authority or @target-uri?          │
                    │     Signature-Agent covered and parsed?        │
                    └───────────────┬────────────────────────────────┘
                                    ▼
                    ┌────────────────────────────────────────────────┐
                    │ KeyResolver.resolve (keys.py)                  │
                    │  static key?  →  else fetch the directory:     │
                    │  SSRF guard · no redirects · 64 KB · 32 keys   │
                    │  cache per Cache-Control (no-store honoured)   │
                    │  key nbf/exp checked (ms tolerated)            │
                    └───────────────┬────────────────────────────────┘
                                    ▼
                    ┌────────────────────────────────────────────────┐
                    │ build_signature_base (sigbase.py) + Ed25519    │
                    │ verify, then nonce replay check                │
                    │      → verified | invalid | unverified         │
                    └───────────────┬────────────────────────────────┘
                                    ▼
                    ┌────────────────────────────────────────────────┐
                    │ PolicyEngine.decide (policy.py)                │
                    │ first match on outcome/tag/operator/path/      │
                    │ method/user_agent_contains                     │
                    │      → allow | block | rate_limit | charge     │
                    └───────────────┬────────────────────────────────┘
                                    ▼
                    ┌────────────────────────────────────────────────┐
                    │ AuditLog.append (audit.py)  hash-chained row   │
                    │ then enforce (or not, if log_only) and set     │
                    │ KYA-Outcome / KYA-Decision / KYA-Operator      │
                    └────────────────────────────────────────────────┘
```

## Modules

### `sigbase.py` — RFC 9421 signature base

Rebuilds the exact byte string the agent signed, from the components its `Signature-Input`
claims to cover. Supports `@authority`, `@method`, `@path`, `@query`, `@target-uri`, plain
headers, and dictionary members (`"signature-agent";key="agent1"`, RFC 9421 §2.1.2).
Duplicate components are rejected; a missing covered header is an error, not a skip.

`@authority` comes from the `Host` header. Behind a reverse proxy that rewrites it, this
breaks verification (open defect D8).

### `keys.py` — key discovery and caching

Two sources: statically registered JWKs (`add_static_jwk`, used by tests and for
out-of-band agreements) and the operator's published directory, discovered from the
`Signature-Agent` header.

Discovery types: `directory` (origin + `/.well-known/http-message-signatures-directory`) and
`jwks_uri` (the URL as given). `cimd` is not implemented.

Fetch rules, all from draft section 5.8 unless noted:

| Rule | Value |
| --- | --- |
| Scheme | HTTPS only (`dev_mode` allows http) |
| Address | public only: private, loopback, link-local, reserved, multicast and unspecified are refused |
| Redirects | never followed |
| Timeout | 3 s |
| Body cap | 64 KB, enforced while streaming |
| Key cap | 32 per directory |
| `Accept` | `application/http-message-signatures-directory+json, application/json;q=0.9` |
| Positive cache | per `Cache-Control`: `no-store`/`no-cache` → no reuse, `max-age` → capped at 24 h, absent → `default_ttl_s` (300 s) |
| Negative cache | capped at 5 minutes (draft A.5) |

Keys are indexed by RFC 7638 thumbprint (RFC 8037 A.3 member set for OKP), which is what the
draft says `keyid` is and what Cloudflare's libraries do. `nbf`/`exp` are checked; values
above 1e11 are treated as milliseconds, because Cloudflare's own directory publishes them
that way (`SPEC-QUESTION` in the source).

**Identity is the pair (directory URL, key), never the key alone.** `ResolvedKey.source`
carries the directory URL and becomes the `operator` in policy and the audit log.

### `verifier.py` — outcomes

The four outcomes exist so policy can treat "we know this is a forgery" differently from "we
could not find out". Mapping:

| Situation | Outcome |
| --- | --- |
| No `Signature`/`Signature-Input` at all | `unsigned` |
| Signature and key material check out | `verified` |
| Bad signature, expired, replayed nonce, malformed headers or params, missing required component, HMAC, published test key, more than `max_signatures` labels | `invalid` |
| Directory unreachable, key id not published, unknown tag, unsupported algorithm | `unverified` |

Other guarantees: at most `max_signatures` (default 3) labels are examined, and that cap is
applied **before** parsing or any key lookup, so one request cannot trigger many fetches;
signature validity longer than `max_validity_s` (default 24 h) is rejected; the nonce store
evicts by expiry in O(log n) via a heap.

### `policy.py` — decisions

First match wins, `default` otherwise. Match fields: `outcome`, `tag`, `operator`, `path`
(glob), `method`, `user_agent_contains`; each takes a value or a list.

`operator` matching is exact: full URL, origin, or host. Substring matching was a real
vulnerability (finding E1) because `https://acme.com.attacker.io` satisfied `acme.com`.

Rate-limit bucketing:

| Traffic | Bucket key |
| --- | --- |
| `verified` with a known operator | the operator's directory URL |
| everything else | the middleware's opaque client key |

The agent's `keyid` is never a bucket key: the attacker picks it, and rotating it bypassed
the limit entirely (defect D1).

### `audit.py` — tamper-evident log

One SQLite table. Each row stores the previous row's SHA-256 over a canonical JSON of its
fields, so editing, deleting or reordering any row breaks the chain from that point on.
`verify_chain()` walks it and names the first broken entry.

Fields: `ts, method, path, outcome, reason, operator, keyid, tag, decision, rule`, plus
`prev_hash` and `hash`. Deliberately absent: bodies, IPs, cookies, user identifiers, query
strings.

Limits: appends are serialised by an in-process lock, so two workers can currently race
(D7, fix with `BEGIN IMMEDIATE`). The chain proves edits; it cannot stop someone deleting the
file, which is why external anchoring of the head hash is on the roadmap.

### `middleware.py` — glue and admin

Derives the client key: parse the address, take the IPv4 /24 or IPv6 /48 prefix, hash it with
a per-process salt, keep 16 hex characters. IPv4-mapped IPv6 is normalised first. A raw
address is never stored or logged.

Admin endpoints live under `/_kya/` and are handled before verification, so they never appear
in the audit log. They require `Authorization: Bearer $KYA_ADMIN_TOKEN`, compared with
`hmac.compare_digest`; with no token configured they 404 rather than advertising themselves.

The dashboard is one server-rendered page with no external scripts; every user-controlled
string is escaped.

## Data flow of an identity

```
Signature-Input keyid  ──┐
                         ├─▶ KeyResolver ──▶ ResolvedKey(keyid, public_key, source)
Signature-Agent URL   ───┘                              │
                                                        ▼
                                          operator = source (directory URL)
                                                        │
                            policy match ◀───────────────┤
                            audit row     ◀──────────────┘
```

## Extending it: new proof types

The roadmap's aggregator direction (Visa TAP payment proofs, Skyfire KYAPay, eventually
Google AP2) is deliberately a small change to this shape:

1. A common claim: `operator, keyid, tag, intent, user_ref, scope, proof_type`.
2. An adapter interface: `detect(request) -> bool`, `verify(request) -> VerificationResult`.
3. Web Bot Auth becomes the first adapter; Visa TAP extends it with the payment-side checks;
   KYAPay is a JWT check rather than an HTTP-signature check.
4. `policy.py` gains match fields (`intent`, `user_ref`, `scope`) and an action that requires
   a payment proof. `audit.py`, the dashboard and the middleware do not change.

The point of the design is that everything after verification reads one normalised answer,
not a protocol.

## Deployment shapes

| Shape | Status |
| --- | --- |
| FastAPI/Starlette middleware, single worker | works today |
| Multiple workers | needs shared nonce, rate-limit and audit stores |
| Reverse proxy in front of any app | roadmap |
| Node/Express port | out of scope for now; the API shape it needs is the adapter interface above |

## Performance characteristics

| Path | Cost |
| --- | --- |
| Verification with a cached key | p50 0.171 ms, p95 0.201 ms (Apple M4 Pro, Python 3.14) |
| Verification with an uncached directory | 340–430 ms median, dominated by the HTTPS fetch |
| Audit append | one SQLite insert, synchronous |

Both the fetch and the audit write currently happen on the event loop (D3). That is the
single biggest gap between this and something you would put in front of real traffic.
