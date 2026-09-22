"""R4: verifier cost. 10,000 Web Bot Auth verifications with a cached Ed25519 key.

    python -m bench.verify_bench [--n 10000] [--out evidence/bench.json]

Signing happens up front (not timed); each timed call is one full Verifier.verify():
header parsing, freshness, key lookup (cache hit), signature base, Ed25519 verify, nonce check.
"""
import argparse
import json
import platform
import statistics
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from kya_gateway import KeyResolver, Verifier
from kya_gateway.sigbase import Request
from kya_gateway.signer import public_jwk, sign_request
from kya_gateway.verifier import Outcome


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=10_000)
    ap.add_argument("--out", default="evidence/bench.json")
    args = ap.parse_args()

    key = Ed25519PrivateKey.generate()
    resolver = KeyResolver()
    resolver.add_static_jwk(public_jwk(key), "bench")     # cached key: no network
    verifier = Verifier(resolver)
    url = "https://shop.example/products/42"
    reqs = []
    for _ in range(args.n):
        h = {k.lower(): v for k, v in sign_request("GET", url, key, "https://agent.example",
                                                   agent_format="none").items()}
        h["host"] = "shop.example"
        reqs.append(Request("GET", url, h))

    for r in reqs[:200]:                      # warm-up on throwaway copies (nonces would replay)
        Verifier(resolver).verify(r)
    lat = []
    for r in reqs:
        t0 = time.perf_counter_ns()
        res = verifier.verify(r)
        lat.append((time.perf_counter_ns() - t0) / 1e6)
        if res.outcome != Outcome.VERIFIED:
            raise SystemExit(f"benchmark request not verified: {res.reason}")
    lat.sort()
    q = statistics.quantiles(lat, n=100)
    out = {"n": args.n, "p50_ms": round(q[49], 4), "p95_ms": round(q[94], 4),
           "p99_ms": round(q[98], 4), "max_ms": round(lat[-1], 4),
           "mean_ms": round(statistics.fmean(lat), 4),
           "verifications_per_s_single_core": round(1000 / statistics.fmean(lat)),
           "target": "p95 < 1 ms (ROADMAP M7)", "meets_target": q[94] < 1.0,
           "machine": f"{platform.machine()} {platform.system()} {platform.release()}",
           "python": platform.python_version(),
           "measured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    with open(args.out, "w") as f:
        json.dump(out, f, indent=2)
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
