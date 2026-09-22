"""Walkthrough against the production-mode example shop, using real public key directories.

    python -m examples.walkthrough [--evidence evidence/walkthrough.json]

Starts examples/my_shop.py on 127.0.0.1:8080 and sends what a real site would see. Needs
internet: the gateway fetches ChatGPT's and Google's live key directories over HTTPS.
"""
import json
import os
import sys
import threading
import time

import httpx
import uvicorn
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from kya_gateway.keys import DIRECTORY_ACCEPT, WELL_KNOWN
from kya_gateway.signer import sign_request

SHOP = "http://127.0.0.1:8080"
TOKEN = "walkthrough-admin-token"
DB = "walkthrough_audit.db"
STEPS = []

EXPECTED = [
    ("human", 200, "unsigned", "allow"),
    ("fake-gptbot-ua", 403, "unsigned", "block"),
    ("forged-chatgpt", 403, "invalid", "block"),
    ("unknown-key-at-chatgpt-1", 200, "unverified", "allow"),
    ("unknown-key-at-chatgpt-2", 200, "unverified", "allow"),
    ("unknown-key-at-chatgpt-3-rotated", 429, "unverified", "rate_limit"),
    ("forged-google-agent", 403, "invalid", "block"),
]


def step(sid, label, r):
    body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
    row = {"id": sid, "label": label, "status": r.status_code, "outcome": r.headers.get("KYA-Outcome"),
           "decision": r.headers.get("KYA-Decision"), "reason": body.get("reason")}
    STEPS.append(row)
    print(f"  {label:<58} {r.status_code}  {row['outcome']:<10} {row['decision']:<10} {row['reason'] or ''}")


def main():
    if os.path.exists(DB):
        os.remove(DB)
    os.environ.update(KYA_ADMIN_TOKEN=TOKEN, KYA_AUDIT_DB=DB)
    from examples.my_shop import app
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=8080, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    for _ in range(50):
        try:
            httpx.get(SHOP + "/_kya/verify-chain", timeout=0.2)
            break
        except httpx.HTTPError:
            time.sleep(0.1)
    c = httpx.Client(base_url=SHOP, timeout=15)
    u = SHOP + "/products/1"

    print("\nWhat the shop sees                                          HTTP outcome    decision   reason")
    step("human", "A person with Firefox", c.get("/products/1", headers={"User-Agent": "Mozilla/5.0 Firefox/131.0"}))
    step("fake-gptbot-ua", "Scraper claims to be GPTBot in User-Agent only",
         c.get("/products/1", headers={"User-Agent": "Mozilla/5.0 (compatible; GPTBot/1.3)"}))

    # Real ChatGPT keyid from the live directory; the attacker signs with their own key.
    gpt = httpx.get("https://chatgpt.com" + WELL_KNOWN, headers={"accept": DIRECTORY_ACCEPT}, timeout=15).json()
    gpt_kid = gpt["keys"][0]["kid"]
    attacker = Ed25519PrivateKey.generate()
    h = sign_request("GET", u, attacker, "https://chatgpt.com")
    own_kid = h["Signature-Input"].split('keyid="')[1].split('"')[0]
    h["Signature-Input"] = h["Signature-Input"].replace(own_kid, gpt_kid)
    step("forged-chatgpt", "Attacker signs as ChatGPT (real ChatGPT keyid, wrong key)", c.get("/products/1", headers=h))

    for i in range(3):   # new keyid each time: the D1 bypass attempt
        k = Ed25519PrivateKey.generate()
        sid = f"unknown-key-at-chatgpt-{i + 1}" + ("-rotated" if i == 2 else "")
        step(sid, f"Unknown key pointing at chatgpt.com directory (try {i + 1})",
             c.get("/products/1", headers=sign_request("GET", u, k, "https://chatgpt.com")))

    g = httpx.get("https://agent.bot.goog" + WELL_KNOWN, headers={"accept": DIRECTORY_ACCEPT}, timeout=15).json()
    from kya_gateway.keys import jwk_thumbprint
    g_kid = jwk_thumbprint(g["keys"][0])
    h = sign_request("GET", u, attacker, "https://agent.bot.goog")
    h["Signature-Input"] = h["Signature-Input"].replace(
        h["Signature-Input"].split('keyid="')[1].split('"')[0], g_kid)
    step("forged-google-agent", "Attacker signs as Google-Agent (real Google keyid)", c.get("/products/1", headers=h))

    print("\nAdmin endpoints")
    a1 = c.get("/_kya/audit.json").status_code
    a2 = c.get("/_kya/audit.json", headers={"Authorization": "Bearer wrong"}).status_code
    audit = c.get("/_kya/audit.json", headers={"Authorization": f"Bearer {TOKEN}"})
    chain = c.get("/_kya/verify-chain", headers={"Authorization": f"Bearer {TOKEN}"}).json()
    print(f"  no token -> {a1}, wrong token -> {a2}, right token -> {audit.status_code}; chain: {chain['detail']}")
    rows = audit.json()
    print(f"  audit row example: {json.dumps({k: rows[2][k] for k in ('path', 'outcome', 'reason', 'operator', 'decision')})}")

    got = [(s["id"], s["status"], s["outcome"], s["decision"]) for s in STEPS]
    failures = [f"{e[0]}: got {g[1:]}, expected {e[1:]}" for g, e in zip(got, EXPECTED) if g != e]
    if (a1, a2, audit.status_code) != (401, 401, 200):
        failures.append(f"admin auth statuses {(a1, a2, audit.status_code)}")
    if not chain["intact"]:
        failures.append("audit chain not intact")
    if "--evidence" in sys.argv:
        with open(sys.argv[sys.argv.index("--evidence") + 1], "w") as f:
            json.dump({"passed": not failures, "failures": failures, "steps": STEPS,
                       "admin": [a1, a2, audit.status_code], "chain": chain}, f, indent=2)
    print("\nWALKTHROUGH CHECK:", "PASS" if not failures else "FAIL")
    for x in failures:
        print("  -", x)
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
