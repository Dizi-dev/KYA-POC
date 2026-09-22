"""Survey which agent operators publish a Web Bot Auth key directory, and whether it is usable.

    python -m research.survey_directories --out evidence/directory_survey.json
    python -m research.survey_directories --dataset --out evidence/signed_agents_survey.json

For each candidate origin it fetches /.well-known/http-message-signatures-directory with the
gateway's production rules (HTTPS only, public IPs only, size and key caps, no redirects) and
records what a verifier would see. Add origins to CANDIDATES as you find more.
"""
import argparse
import datetime as dt
import json
import time

import httpx

from kya_gateway.keys import DIRECTORY_ACCEPT, KNOWN_TEST_KEYIDS, WELL_KNOWN, KeyResolver, jwk_thumbprint

CANDIDATES = [
    "https://chatgpt.com", "https://openai.com", "https://anthropic.com", "https://claude.ai",
    "https://perplexity.ai", "https://google.com", "https://bing.com", "https://amazon.com",
    "https://cloudflare.com", "https://browserbase.com", "https://browser-use.com",
    "https://manus.im", "https://skyfire.xyz", "https://visa.com",
    "https://http-message-signatures-example.research.cloudflare.com",
    # R1 additions (22 Sep 2026); sources in research/candidates.md
    "https://agent.bot.goog",                                       # Google-Agent
    "https://xhah6q48pbxb4.keydirectory.signer.us-east-1.on.aws",  # AWS Bedrock AgentCore Browser
    "https://c3drvlj8gw240.keydirectory.signer.eu-west-1.on.aws",  # AgentCore, eu-west-1
    "https://api.anchorbrowser.io", "https://www.kernel.sh", "https://api.manus.im",
    "https://api.apify.com", "https://api.link.com", "https://nekuda-agent-registry.onrender.com",
    "https://www.meta.com", "https://assistbot.duckduckgo.com", "https://you.com",
    "https://www.klaviyo.com", "https://rye.xyz", "https://signatures.cardsavr.io",
    "https://payroll-bot.adp.com", "https://www.browserless.io", "https://www.shopify.com",
    "https://steel.dev", "https://hyperbrowser.ai", "https://stripe.com", "https://coinbase.com",
]
DATASET_URL = ("https://raw.githubusercontent.com/microlinkhq/cloudflare-bot-directory/"
               "master/src/index.json")   # community mirror of Cloudflare Radar's bot directory


def survey(origin: str) -> dict:
    # Dataset entries give the full directory URL, sometimes under a sub-path.
    url = origin if WELL_KNOWN in origin else origin.rstrip("/") + WELL_KNOWN
    row = {"origin": origin, "url": url, "at_origin_root": url.split("/", 3)[-1] == WELL_KNOWN.lstrip("/"), "checked_at": dt.datetime.now(dt.timezone.utc).isoformat()}
    try:
        r = httpx.get(url, timeout=10, follow_redirects=False, headers={"accept": DIRECTORY_ACCEPT})
        row.update(status=r.status_code, content_type=r.headers.get("content-type", ""),
                   cache_control=r.headers.get("cache-control", ""))
        if r.status_code != 200:
            return row
        data = r.json()
        if not isinstance(data, dict):
            raise ValueError("directory is not a JSON object")
    except Exception as exc:  # noqa: BLE001
        row["error"] = f"{type(exc).__name__}: {exc}"[:200]
        return row
    keys = data.get("keys", [])
    now = time.time()
    rows = []
    for jwk in keys:
        k = {"kty": jwk.get("kty"), "crv": jwk.get("crv"), "kid": jwk.get("kid")}
        try:
            tp = jwk_thumbprint(jwk)
            k["thumbprint"] = tp
            k["kid_matches_thumbprint"] = (jwk.get("kid") == tp) if "kid" in jwk else None
            k["is_rfc9421_test_key"] = tp in KNOWN_TEST_KEYIDS
        except (ValueError, KeyError):
            k["thumbprint"] = None
        for f in ("nbf", "exp"):
            if f in jwk:
                v = jwk[f]
                k[f] = v
                k[f + "_unit"] = "milliseconds?" if v > 1e11 else "seconds"
        if "exp" in jwk:
            exp_s = jwk["exp"] / 1000 if jwk["exp"] > 1e11 else jwk["exp"]
            k["days_until_exp"] = round((exp_s - now) / 86400, 1)
        rows.append(k)
    entry = KeyResolver(dev_mode=False)._fetch(url)   # same code path the gateway uses
    row.update(key_count=len(keys), keys=rows, purpose=data.get("purpose"),
               signature_agent=data.get("signature_agent"),
               gateway_can_load=entry.error is None, gateway_error=entry.error,
               gateway_usable_keys=len(entry.keys))
    return row


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="evidence/directory_survey.json")
    ap.add_argument("--dataset", action="store_true",
                    help="survey every signatureAgentUrl in the Cloudflare Radar mirror")
    ap.add_argument("origins", nargs="*")
    args = ap.parse_args()
    results = []
    targets = args.origins or CANDIDATES
    meta = {}
    if args.dataset:
        entries = httpx.get(DATASET_URL, timeout=30).json()
        signed = [e for e in entries if e.get("signatureAgentUrl")]
        meta = {e["signatureAgentUrl"]: {"name": e.get("name"), "operator": e.get("operator"),
                                         "category": e.get("category")} for e in signed}
        print(f"dataset: {len(entries)} bots, {len(signed)} with a signatureAgentUrl")
        targets = list(meta)
    for o in targets:
        row = survey(o)
        row.update(meta.get(o, {}))
        results.append(row)
        # The gateway never follows redirects (draft 5.8), but record where a redirect leads
        # so we know whether the operator publishes on another host (e.g. www.).
        if str(row.get("status", "")).startswith("3"):
            loc = httpx.get(row["url"], timeout=10, follow_redirects=False).headers.get("location", "")
            if loc.startswith("https://") and loc.endswith(WELL_KNOWN):
                follow = survey(loc[: -len(WELL_KNOWN)])
                follow["redirected_from"] = o
                results.append(follow)
    with open(args.out, "w") as f:
        json.dump(results, f, indent=2)
    print(f"{'origin':<66} {'status':>6} keys gateway")
    for r in results:
        name = r["origin"] + ("  (redirect target)" if "redirected_from" in r else "")
        print(f"{name:<66} {str(r.get('status', 'err')):>6} {r.get('key_count', '-'):>4} "
              f"{'ok' if r.get('gateway_can_load') else '-'}")
    loaded = [r for r in results if r.get("gateway_can_load")]
    print(f"\n{len(loaded)} of {len(results)} directories load under production rules; "
          f"{sum(r.get('gateway_usable_keys', 0) for r in loaded)} usable Ed25519 keys")
    print(f"written to {args.out}")


if __name__ == "__main__":
    main()
