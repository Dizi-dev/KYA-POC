"""End-to-end demo: starts the key directory and the protected store, then sends
eight kinds of traffic and shows what the gateway decided for each.

    python -m demo.run_demo [--evidence evidence/demo.json]
Exits non-zero if any gateway decision differs from EXPECTED or tampering goes undetected.
Dashboard afterwards: KYA_ADMIN_TOKEN=... python -m uvicorn demo.store:app --port 8000, then
GET /_kya/dashboard with "Authorization: Bearer <token>"
"""
import json
import os
import sys
import sqlite3
import threading
import time

import httpx
import uvicorn
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from demo import agent_directory
from demo.store import build_app
from kya_gateway.middleware import render_dashboard
from kya_gateway.signer import sign_request

STORE = "http://127.0.0.1:8000"
ACME_DIR = "http://127.0.0.1:8001"       # dev mode: plain http on localhost
DB = "demo_audit.db"
ADMIN_TOKEN = "demo-admin-token"          # /_kya/* needs a bearer token (D2)
ADMIN = {"Authorization": f"Bearer {ADMIN_TOKEN}"}


def serve(app, port, probe="/openapi.json"):
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    for _ in range(50):
        try:
            httpx.get(f"http://127.0.0.1:{port}{probe}", timeout=0.2)
            return
        except httpx.HTTPError:
            time.sleep(0.1)


RESULTS = []

# What a correct gateway must produce for each scenario (status, outcome, decision).
EXPECTED = [
    (200, "verified", "allow"), (200, "verified", "allow"), (402, "verified", "charge"),
    (403, "invalid", "block"), (403, "invalid", "block"), (403, "unsigned", "block"),
    (200, "unverified", "allow"), (200, "unverified", "allow"), (429, "unverified", "rate_limit"),
    (200, "unsigned", "allow"),
]


def show(n, label, r):
    RESULTS.append({"scenario": n, "label": label, "status": r.status_code,
                    "outcome": r.headers.get("KYA-Outcome"), "decision": r.headers.get("KYA-Decision")})
    print(f"{n:>2}. {label:<46} {r.status_code}  outcome={r.headers.get('KYA-Outcome', '-'):<10} "
          f"decision={r.headers.get('KYA-Decision', '-')}")


def main():
    if os.path.exists(DB):
        os.remove(DB)
    store_app = build_app(db_path=DB, admin_token=ADMIN_TOKEN)
    serve(agent_directory.app, 8001)
    serve(store_app, 8000, probe="/_kya/verify-chain")   # admin paths are not logged
    acme = agent_directory.ACME_KEY
    c = httpx.Client(base_url=STORE)
    print("\nRequest                                          HTTP  gateway result\n" + "-" * 96)

    u = f"{STORE}/products/42"
    h1 = sign_request("GET", u, acme, ACME_DIR)
    show(1, "Acme agent browses a product (signed)", c.get("/products/42", headers=h1))

    u = f"{STORE}/checkout"
    show(2, "Acme agent checks out (TAP agent-payer-auth)",
         c.post("/checkout", headers=sign_request("POST", u, acme, ACME_DIR, tag="agent-payer-auth")))

    u = f"{STORE}/api/prices"
    show(3, "Acme agent pulls the price API (signed)", c.get("/api/prices", headers=sign_request("GET", u, acme, ACME_DIR)))

    show(4, "Attacker replays request 1 headers", c.get("/products/42", headers=h1))

    attacker = Ed25519PrivateKey.generate()
    forged = sign_request("GET", f"{STORE}/products/42", attacker, ACME_DIR)
    acme_kid = h1["Signature-Input"].split('keyid="')[1].split('"')[0]
    atk_kid = forged["Signature-Input"].split('keyid="')[1].split('"')[0]
    forged["Signature-Input"] = forged["Signature-Input"].replace(atk_kid, acme_kid)
    show(5, "Attacker forges Acme's identity", c.get("/products/42", headers=forged))

    show(6, "Scraper sends 'GPTBot' User-Agent, no signature",
         c.get("/products/42", headers={"User-Agent": "Mozilla/5.0 (compatible; GPTBot/1.3)"}))

    stranger = Ed25519PrivateKey.generate()
    for i in range(3):
        u = f"{STORE}/products/{7 + i}"
        r = c.get(f"/products/{7 + i}", headers=sign_request("GET", u, stranger, "http://127.0.0.1:8999"))
        show(7, f"Unknown agent, directory offline (try {i + 1})", r)

    show(8, "Human with a normal browser", c.get("/products/42", headers={"User-Agent": "Mozilla/5.0 Firefox/131.0"}))

    before = c.get("/_kya/verify-chain", headers=ADMIN).json()
    print("\nAudit chain:", before["detail"])
    db = sqlite3.connect(DB)
    db.execute("UPDATE audit SET decision='allow' WHERE id=5")   # try to hide the forgery
    db.commit()
    after = c.get("/_kya/verify-chain", headers=ADMIN).json()
    print("After editing entry 5 in the database:", after["detail"])

    from kya_gateway.audit import AuditLog
    with open("dashboard_snapshot.html", "w") as f:
        f.write(render_dashboard(AuditLog(DB)))
    print("Dashboard snapshot written to dashboard_snapshot.html\n")

    failures = []
    got = [(r["status"], r["outcome"], r["decision"]) for r in RESULTS]
    if got != EXPECTED:
        for i, (g, e) in enumerate(zip(got, EXPECTED), 1):
            if g != e:
                failures.append(f"request {i}: got {g}, expected {e}")
        if len(got) != len(EXPECTED):
            failures.append(f"got {len(got)} results, expected {len(EXPECTED)}")
    if not before["intact"]:
        failures.append("audit chain broken before tampering")
    if after["intact"] or "entry 5" not in after["detail"]:
        failures.append("tampering with entry 5 was not detected")
    report = {"passed": not failures, "failures": failures, "results": RESULTS,
              "chain_before": before, "chain_after_tamper": after}
    if "--evidence" in sys.argv:
        out = sys.argv[sys.argv.index("--evidence") + 1]
        with open(out, "w") as f:
            json.dump(report, f, indent=2)
    print("DEMO CHECK:", "PASS" if not failures else "FAIL")
    for f_ in failures:
        print("  -", f_)
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
