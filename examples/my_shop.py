"""What a store owner adds to an existing FastAPI app. Production settings: HTTPS-only public
key directories, full SSRF rules, the RFC 9421 test key rejected. Run it with:

    KYA_ADMIN_TOKEN=change-me uvicorn examples.my_shop:app --port 8080
"""
import os

from fastapi import FastAPI

from kya_gateway import AuditLog, KeyResolver, PolicyEngine, Verifier
from kya_gateway.middleware import KYAMiddleware

app = FastAPI(title="My shop")


@app.get("/products/{pid}")
def product(pid: int):
    return {"id": pid, "name": f"Product {pid}", "price_eur": 19.9}


@app.get("/api/prices")
def prices():
    return {"prices": [{"id": 1, "eur": 19.9}]}


# ---- the KYA Gateway integration: these lines are all a store owner writes ----------------
app.add_middleware(
    KYAMiddleware,
    verifier=Verifier(KeyResolver()),                     # production mode (dev_mode=False)
    policy=PolicyEngine.from_yaml(os.environ.get("KYA_POLICY", "policy.yaml")),
    audit=AuditLog(os.environ.get("KYA_AUDIT_DB", "kya_audit.db")),
    log_only=os.environ.get("KYA_LOG_ONLY") == "1",       # start in log-only with a new site
)                                                         # admin token: $KYA_ADMIN_TOKEN
