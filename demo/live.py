"""Interactive demo: a control panel that sends real traffic to the protected demo store and
shows the gateway's dashboard live next to it.

    python -m demo.live        then open http://127.0.0.1:8002

Starts the Acme key directory (8001), the protected store (8000, dev mode, admin token set)
and this panel (8002). Every button makes a real HTTP request through the KYA middleware.
"""
import html
import os
import sqlite3
import threading
import time

import httpx
import uvicorn
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse

from demo import agent_directory
from demo.store import build_app
from kya_gateway.signer import sign_request

STORE = "http://127.0.0.1:8000"
ACME_DIR = "http://127.0.0.1:8001"
DB = "live_audit.db"
TOKEN = "live-demo-token"
ADMIN = {"Authorization": f"Bearer {TOKEN}"}
state = {"last_signed": None}
store = httpx.Client(base_url=STORE, timeout=10)


def _serve(app, port, probe="/openapi.json"):   # probe paths the gateway does not log
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    for _ in range(50):
        try:
            httpx.get(f"http://127.0.0.1:{port}{probe}", timeout=0.2)
            return
        except httpx.HTTPError:
            time.sleep(0.1)


def _signed(method, path, key=None, agent=ACME_DIR, tag="web-bot-auth"):
    return sign_request(method, STORE + path, key or agent_directory.ACME_KEY, agent, tag=tag)


def _forged(path):
    """Attacker signs with their own key but claims Acme's keyid and directory."""
    real = _signed("GET", path)
    fake = sign_request("GET", STORE + path, Ed25519PrivateKey.generate(), ACME_DIR)
    kid = lambda h: h["Signature-Input"].split('keyid="')[1].split('"')[0]  # noqa: E731
    fake["Signature-Input"] = fake["Signature-Input"].replace(kid(fake), kid(real))
    return fake


def _send(method, path, headers):
    r = store.request(method, path, headers=headers)
    body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
    return {"status": r.status_code, "outcome": r.headers.get("KYA-Outcome"),
            "decision": r.headers.get("KYA-Decision"), "operator": r.headers.get("KYA-Operator"),
            "reason": body.get("reason") or body.get("detail") or "", "path": f"{method} {path}"}


def act_agent_browse():
    h = _signed("GET", "/products/42")
    state["last_signed"] = h
    return _send("GET", "/products/42", h)


def act_agent_checkout():
    return _send("POST", "/checkout", _signed("POST", "/checkout", tag="agent-payer-auth"))


def act_agent_prices():
    return _send("GET", "/api/prices", _signed("GET", "/api/prices"))


def act_replay():
    h = state["last_signed"] or _signed("GET", "/products/42")
    if state["last_signed"] is None:
        _send("GET", "/products/42", h)
    return _send("GET", "/products/42", h)


def act_forge():
    return _send("GET", "/products/42", _forged("/products/42"))


def act_fake_gptbot():
    return _send("GET", "/products/42", {"User-Agent": "Mozilla/5.0 (compatible; GPTBot/1.3)"})


def act_human():
    return _send("GET", "/products/42", {"User-Agent": "Mozilla/5.0 Firefox/131.0"})


def act_unknown_agent():
    k = Ed25519PrivateKey.generate()   # new identity every click, directory unreachable
    return _send("GET", "/products/7", _signed("GET", "/products/7", key=k, agent="http://127.0.0.1:8999"))


def act_tamper():
    db = sqlite3.connect(DB)
    row = db.execute("SELECT id, decision FROM audit WHERE decision != 'allow' ORDER BY id LIMIT 1").fetchone() \
        or db.execute("SELECT id, decision FROM audit ORDER BY id LIMIT 1").fetchone()
    if not row:
        return {"status": "-", "outcome": "-", "decision": "-", "path": "audit log",
                "reason": "nothing logged yet, send some traffic first"}
    db.execute("UPDATE audit SET decision='allow' WHERE id=?", (row[0],))
    db.commit()
    chain = store.get("/_kya/verify-chain", headers=ADMIN).json()
    return {"status": "DB edit", "outcome": "-", "decision": "-", "path": f"audit entry {row[0]}",
            "reason": f"changed '{row[1]}' to 'allow' directly in SQLite. Gateway says: {chain['detail']}"}


ACTIONS = {
    "agent_browse": ("Real agent browses a product", "Acme's AI agent signs its request.", act_agent_browse, "good"),
    "agent_checkout": ("Real agent checks out", "Signed with Visa's payment-intent tag.", act_agent_checkout, "good"),
    "agent_prices": ("Real agent hits the price API", "Policy says: charge agents here (HTTP 402).", act_agent_prices, "good"),
    "human": ("Normal human visitor", "A browser, no signature.", act_human, "good"),
    "replay": ("Attacker replays a real request", "Copies the agent's last signed headers exactly.", act_replay, "bad"),
    "forge": ("Attacker impersonates Acme", "Claims Acme's key, signs with their own.", act_forge, "bad"),
    "fake_gptbot": ("Scraper pretends to be GPTBot", "Only the User-Agent text, no signature.", act_fake_gptbot, "bad"),
    "unknown_agent": ("Unknown agent (click 3x)", "New identity each time; can't be checked.", act_unknown_agent, "warn"),
    "tamper": ("Tamper with the audit log", "Edit the database to hide a block.", act_tamper, "bad"),
}

panel = FastAPI(title="KYA live demo")


@panel.post("/act/{name}")
def act(name: str):
    if name not in ACTIONS:
        return JSONResponse({"error": "unknown action"}, status_code=404)
    label = ACTIONS[name][0]
    return {"label": label, **ACTIONS[name][2]()}


@panel.get("/dashboard")
def dashboard():
    # The panel holds the admin token server-side, so the browser never needs it.
    r = store.get("/_kya/dashboard", headers=ADMIN)
    return HTMLResponse(r.text, status_code=r.status_code)


@panel.get("/")
def index():
    buttons = "".join(
        f'<button class="act {kind}" data-a="{key}"><b>{html.escape(t)}</b><span>{html.escape(d)}</span></button>'
        for key, (t, d, _, kind) in ACTIONS.items())
    return HTMLResponse(PAGE.replace("{{BUTTONS}}", buttons))


PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>KYA Gateway live demo</title>
<style>
:root{--bg:#fafaf7;--card:#fff;--fg:#1c1c1a;--muted:#6b6b66;--line:#e4e2dc;--ok:#1f7a4d;--bad:#b3261e;--warn:#9a6700}
@media (prefers-color-scheme:dark){:root{--bg:#151513;--card:#1d1d1a;--fg:#ecebe6;--muted:#9c9b94;--line:#2c2b27;--ok:#5ccf95;--bad:#ff8a80;--warn:#e3b341}}
*{box-sizing:border-box}body{margin:0;font:14px/1.45 ui-sans-serif,system-ui,sans-serif;background:var(--bg);color:var(--fg)}
header{padding:18px 20px 6px}h1{font-size:19px;margin:0}p.sub{margin:4px 0 0;color:var(--muted)}
main{display:grid;grid-template-columns:minmax(300px,420px) 1fr;gap:16px;padding:12px 20px 20px}
@media (max-width:900px){main{grid-template-columns:1fr}}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:8px}
button.act{text-align:left;border:1px solid var(--line);background:var(--card);color:var(--fg);border-radius:10px;padding:10px;cursor:pointer;border-left:4px solid var(--line)}
button.act:hover{border-color:var(--muted)}button.act b{display:block;font-size:13px}button.act span{display:block;color:var(--muted);font-size:12px;margin-top:2px}
button.good{border-left-color:var(--ok)}button.bad{border-left-color:var(--bad)}button.warn{border-left-color:var(--warn)}
h2{font-size:13px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);margin:18px 0 8px}
.log{display:flex;flex-direction:column;gap:6px}
.row{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:8px 10px}
.row .top{display:flex;justify-content:space-between;gap:8px}.row .code{font-weight:700;font-variant-numeric:tabular-nums}
.row .meta{color:var(--muted);font-size:12px;margin-top:2px;word-break:break-word}
.pill{display:inline-block;border-radius:999px;padding:0 8px;font-size:12px;border:1px solid var(--line);margin-right:4px}
.o-verified{color:var(--ok)}.o-invalid{color:var(--bad)}.o-unverified{color:var(--warn)}
.d-allow{color:var(--ok)}.d-block,.d-rate_limit{color:var(--bad)}.d-charge{color:var(--warn)}
iframe{width:100%;height:calc(100vh - 110px);min-height:520px;border:1px solid var(--line);border-radius:10px;background:var(--card)}
</style></head><body>
<header><h1>KYA Gateway, live</h1><p class="sub">Each button sends a real HTTP request to a demo shop protected by the gateway. The dashboard on the right is the gateway's own view, refreshing every 3 s.</p></header>
<main><section><div class="grid">{{BUTTONS}}</div><h2>What the gateway decided</h2><div class="log" id="log"></div></section>
<section><iframe id="dash" src="/dashboard" title="Gateway dashboard"></iframe></section></main>
<script>
const log=document.getElementById('log');
document.querySelectorAll('button.act').forEach(b=>b.addEventListener('click',async()=>{
  b.disabled=true;
  try{const r=await (await fetch('/act/'+b.dataset.a,{method:'POST'})).json();
    const d=document.createElement('div');d.className='row';
    const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
    d.innerHTML=`<div class="top"><b>${esc(r.label)}</b><span class="code">${esc(r.status)}</span></div>
      <div class="meta"><span class="pill o-${esc(r.outcome)}">${esc(r.outcome)}</span><span class="pill d-${esc(r.decision)}">${esc(r.decision)}</span>${esc(r.path)}${r.reason?' · '+esc(r.reason):''}</div>`;
    log.prepend(d);document.getElementById('dash').src='/dashboard?'+Date.now();
  }finally{b.disabled=false}
}));
</script></body></html>"""


def main():
    if os.path.exists(DB):
        os.remove(DB)
    agent_directory.CACHE_CONTROL = "max-age=300"
    _serve(agent_directory.app, 8001)
    _serve(build_app(db_path=DB, admin_token=TOKEN), 8000, probe="/_kya/verify-chain")
    print("KYA live demo: open http://127.0.0.1:8002")
    uvicorn.run(panel, host="127.0.0.1", port=8002, log_level="warning")


if __name__ == "__main__":
    main()
