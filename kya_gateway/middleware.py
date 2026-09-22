"""FastAPI / Starlette middleware: verify -> decide -> log, plus a small dashboard."""
from __future__ import annotations

import hashlib
import html
import ipaddress
import json
import os
from collections import Counter

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest
from starlette.responses import HTMLResponse, JSONResponse, Response

from .audit import AuditLog
from .policy import PolicyEngine
from .sigbase import Request
from .verifier import Verifier

PREFIX = "/_kya"
# Per-process salt so client keys cannot be reversed to an IP prefix from the audit log or
# rate-limit state. Buckets reset on restart, which is fine for an in-memory limiter.
_CLIENT_SALT = os.urandom(16)


def client_key(host: str | None) -> str:
    """Opaque rate-limit key for a client: salted hash of the IPv4 /24 or IPv6 /48 prefix.
    Never the raw IP (audit and privacy rule). Behind a reverse proxy, pass the real client
    address here; Starlette's request.client is the proxy's address unless a trusted
    proxy-headers middleware rewrote it."""
    try:
        ip = ipaddress.ip_address(host or "")
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        prefix = 24 if ip.version == 4 else 48
        material = str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
    except ValueError:
        material = f"host:{host or 'unknown'}"
    return hashlib.sha256(_CLIENT_SALT + material.encode()).hexdigest()[:16]


class KYAMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, *, verifier: Verifier, policy: PolicyEngine, audit: AuditLog,
                 log_only: bool = False):
        super().__init__(app)
        self.verifier, self.policy, self.audit, self.log_only = verifier, policy, audit, log_only

    async def dispatch(self, request: StarletteRequest, call_next):
        if request.url.path.startswith(PREFIX):
            return self._admin(request)

        headers = {k.lower(): v for k, v in request.headers.items()}
        res = self.verifier.verify(Request(request.method, str(request.url), headers))
        ck = client_key(request.client.host if request.client else None)
        decision = self.policy.decide(res, request.method, request.url.path, headers.get("user-agent", ""),
                                      client_key=ck)
        self.audit.append(method=request.method, path=request.url.path, outcome=res.outcome.value,
                          reason=res.reason, operator=res.operator, keyid=res.keyid, tag=res.tag,
                          decision=("log-only:" if self.log_only else "") + decision.action,
                          rule=decision.rule)
        kya_headers = {"KYA-Outcome": res.outcome.value, "KYA-Decision": decision.action}
        if res.operator:
            kya_headers["KYA-Operator"] = res.operator

        if decision.action == "allow" or self.log_only:
            response = await call_next(request)
            response.headers.update(kya_headers)
            return response
        body = {"decision": decision.action, "outcome": res.outcome.value, "reason": res.reason,
                "detail": decision.detail}
        if decision.price:
            body["price"] = decision.price
            kya_headers["KYA-Price"] = decision.price
        return JSONResponse(body, status_code=decision.status, headers=kya_headers)

    # -- admin endpoints -------------------------------------------------------
    def _admin(self, request: StarletteRequest) -> Response:
        path = request.url.path
        if path == f"{PREFIX}/audit.json":
            return Response(self.audit.export_json(), media_type="application/json")
        if path == f"{PREFIX}/verify-chain":
            ok, msg = self.audit.verify_chain()
            return JSONResponse({"intact": ok, "detail": msg})
        if path == f"{PREFIX}/dashboard":
            return HTMLResponse(render_dashboard(self.audit))
        return JSONResponse({"error": "not found"}, status_code=404)


def render_dashboard(audit: AuditLog) -> str:
    rows = audit.rows(limit=500)
    ok, chain_msg = audit.verify_chain()
    outcomes = Counter(r["outcome"] for r in rows)
    decisions = Counter(r["decision"] for r in rows)
    operators = Counter(r["operator"] or "(none)" for r in rows)

    def chips(c: Counter) -> str:
        return "".join(f'<span class="chip"><b>{html.escape(str(k))}</b> {v}</span>' for k, v in c.most_common())

    trs = "".join(
        f'<tr class="{html.escape(r["outcome"])}"><td>{r["id"]}</td><td>{html.escape(r["method"])} {html.escape(r["path"])}</td>'
        f'<td>{html.escape(r["outcome"])}</td><td>{html.escape(r["decision"])}</td>'
        f'<td>{html.escape(r["operator"] or "")}</td><td>{html.escape(r["tag"] or "")}</td>'
        f'<td>{html.escape(r["reason"] or "")}</td><td><code>{r["hash"][:10]}</code></td></tr>'
        for r in rows)
    return f"""<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="refresh" content="3">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>KYA Gateway</title>
<style>
:root{{--bg:#fafaf7;--fg:#1c1c1a;--muted:#6b6b66;--line:#e4e2dc;--ok:#1f7a4d;--bad:#b3261e;--warn:#9a6700}}
@media (prefers-color-scheme:dark){{:root{{--bg:#151513;--fg:#ecebe6;--muted:#9c9b94;--line:#2c2b27;--ok:#5ccf95;--bad:#ff8a80;--warn:#e3b341}}}}
body{{font:14px/1.45 ui-sans-serif,system-ui,sans-serif;background:var(--bg);color:var(--fg);margin:0;padding:24px;max-width:1200px}}
h1{{font-size:20px;margin:0 0 4px}} .muted{{color:var(--muted)}} .chip{{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:2px 10px;margin:2px 6px 2px 0}}
.wrap{{overflow-x:auto;margin-top:16px}} table{{border-collapse:collapse;width:100%}} td,th{{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;white-space:nowrap}}
tr.verified td:nth-child(3){{color:var(--ok)}} tr.invalid td:nth-child(3){{color:var(--bad)}} tr.unverified td:nth-child(3){{color:var(--warn)}}
.chain{{font-weight:600;color:{'var(--ok)' if ok else 'var(--bad)'}}}
</style></head><body>
<h1>KYA Gateway</h1><div class="muted">Audit chain: <span class="chain">{html.escape(chain_msg)}</span></div>
<p>Outcomes {chips(outcomes)}</p><p>Decisions {chips(decisions)}</p><p>Operators {chips(operators)}</p>
<div class="wrap"><table><tr><th>#</th><th>Request</th><th>Outcome</th><th>Decision</th><th>Operator</th><th>Tag</th><th>Reason</th><th>Hash</th></tr>{trs}</table></div>
</body></html>"""
