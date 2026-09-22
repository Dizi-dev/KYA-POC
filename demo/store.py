"""Demo store protected by the KYA Gateway middleware."""
import os

from fastapi import FastAPI

from kya_gateway import AuditLog, KeyResolver, PolicyEngine, Verifier
from kya_gateway.middleware import KYAMiddleware

HERE = os.path.dirname(os.path.abspath(__file__))


def build_app(db_path: str = "kya_audit.db", dev_mode: bool = True, log_only: bool = False) -> FastAPI:
    app = FastAPI(title="Demo store")

    @app.get("/products/{pid}")
    def product(pid: int):
        return {"id": pid, "name": f"Product {pid}", "price_eur": 19.9}

    @app.get("/api/prices")
    def prices():
        return {"prices": [{"id": 1, "eur": 19.9}, {"id": 2, "eur": 4.5}]}

    @app.post("/checkout")
    def checkout():
        return {"order": "A-1001", "status": "confirmed"}

    # dev_mode allows http + localhost directories for the local demo only
    verifier = Verifier(KeyResolver(dev_mode=dev_mode))
    policy = PolicyEngine.from_yaml(os.path.join(HERE, "..", "policy.yaml"))
    app.add_middleware(KYAMiddleware, verifier=verifier, policy=policy,
                       audit=AuditLog(db_path), log_only=log_only)
    return app


app = build_app()
