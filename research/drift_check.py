"""R3: re-test the three surprises from docs/BASELINE_FINDINGS.md against live endpoints.

    python -m research.drift_check --out evidence/drift.json

1. Cloudflare's live research server rejects the draft-00 dictionary Signature-Agent form.
2. Cloudflare's research directory publishes nbf in milliseconds.
3. ChatGPT's directory sends Cache-Control: no-store and its key expires about 7 days out.
"""
import argparse
import base64
import datetime as dt
import json
import time

import httpx
from cryptography.hazmat.primitives.serialization import load_der_private_key

from kya_gateway.keys import DIRECTORY_ACCEPT, WELL_KNOWN
from kya_gateway.signer import sign_request

CF_SERVER = "https://http-message-signatures-example.research.cloudflare.com"
# RFC 9421 Appendix B.1.4 test key: public test material, the server under test expects it.
TEST_PRIV = load_der_private_key(base64.b64decode(
    "MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF"), None)


def live_verdict(fmt: str) -> str:
    h = sign_request("GET", CF_SERVER + "/", TEST_PRIV, CF_SERVER, agent_format=fmt, extra_components=())
    text = httpx.get(CF_SERVER + "/", headers=h, timeout=20).text
    return "accepted" if "You successfully authenticated" in text else \
        "rejected" if "does not validate" in text else "no-verdict"


def directory(origin: str) -> tuple[dict, str]:
    r = httpx.get(origin + WELL_KNOWN, headers={"accept": DIRECTORY_ACCEPT}, timeout=15)
    return r.json(), r.headers.get("cache-control", "")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="evidence/drift.json")
    args = ap.parse_args()
    now = time.time()
    checks = []

    verdicts = {f: live_verdict(f) for f in ("none", "legacy", "dict")}
    checks.append({"id": 1, "claim": "live Cloudflare server rejects the dictionary Signature-Agent form",
                   "observed": verdicts, "still_holds": verdicts["dict"] == "rejected"})

    cf, _ = directory(CF_SERVER)
    nbf = [k.get("nbf") for k in cf.get("keys", [])]
    checks.append({"id": 2, "claim": "Cloudflare research directory publishes nbf in milliseconds",
                   "observed": {"nbf": nbf}, "still_holds": any(v and v > 1e11 for v in nbf)})

    gpt, cc = directory("https://chatgpt.com")
    days = [round((k["exp"] - now) / 86400, 2) for k in gpt.get("keys", []) if "exp" in k]
    checks.append({"id": 3, "claim": "ChatGPT directory is no-store and its key expires ~7 days out",
                   "observed": {"cache_control": cc, "days_until_exp": days,
                                "kids": [k.get("kid") for k in gpt.get("keys", [])]},
                   "still_holds": "no-store" in cc and any(5 <= d <= 8 for d in days)})

    # Not a baseline surprise, but it drives the D3 priority: with no-store, every ChatGPT
    # request needs this fetch (gateway code path, fresh connection each time as in the POC).
    from kya_gateway.keys import KeyResolver
    r = KeyResolver()
    url = r._fetch_url("https://chatgpt.com", "directory")
    lat = []
    for _ in range(10):
        t0 = time.perf_counter()
        r._fetch(url)
        lat.append(round((time.perf_counter() - t0) * 1000))
    lat.sort()
    fetch = {"url": url, "samples_ms": lat, "median_ms": lat[len(lat) // 2], "max_ms": lat[-1]}
    print(f"ChatGPT directory fetch latency: median {fetch['median_ms']} ms, max {fetch['max_ms']} ms")

    out = {"checked_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), "checks": checks,
           "chatgpt_directory_fetch": fetch}
    with open(args.out, "w") as f:
        json.dump(out, f, indent=2)
    for c in checks:
        print(f"{c['id']}. {'STILL HOLDS' if c['still_holds'] else 'CHANGED    '} {c['claim']}: {c['observed']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
