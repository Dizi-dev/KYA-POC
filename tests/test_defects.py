"""Regression tests for the demo-week defects (D1, D2, D5, D9 in docs/ROADMAP.md) and the
review findings E1 to E3 (see REPORT.md). Local servers only, no public internet."""
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from starlette.testclient import TestClient

from kya_gateway import AuditLog, KeyResolver, PolicyEngine, Verifier
from kya_gateway.keys import WELL_KNOWN
from kya_gateway.middleware import KYAMiddleware, client_key
from kya_gateway.sigbase import Request
from kya_gateway.signer import public_jwk, sign_request
from kya_gateway.verifier import Outcome, VerificationResult

UNVERIFIED_LIMIT = [{"name": "limit-unverified", "match": {"outcome": "unverified"},
                     "action": "rate_limit", "limit": 2, "window_s": 60}]


# -- D1: rate limit must not be keyed on attacker-chosen values ---------------------------

def test_d1_rotating_keyids_same_client_are_rate_limited():
    policy = PolicyEngine(UNVERIFIED_LIMIT)
    actions = []
    for i in range(5):
        res = VerificationResult(Outcome.UNVERIFIED, "directory unavailable", keyid=f"kid-{i}")
        actions.append(policy.decide(res, "GET", "/", "", client_key="c1").action)
    assert actions == ["allow", "allow", "rate_limit", "rate_limit", "rate_limit"]


def test_d1_different_clients_have_separate_buckets():
    policy = PolicyEngine(UNVERIFIED_LIMIT)
    res = VerificationResult(Outcome.UNVERIFIED, "x", keyid="same")
    for _ in range(2):
        policy.decide(res, "GET", "/", "", client_key="c1")
    assert policy.decide(res, "GET", "/", "", client_key="c2").action == "allow"


def test_d1_client_key_is_hashed_prefix_never_raw_ip():
    a, b = client_key("203.0.113.7"), client_key("203.0.113.200")
    assert a == b, "same /24 must share a bucket"
    assert client_key("198.51.100.7") != a
    assert "203.0.113" not in a
    v6a, v6b = client_key("2001:db8:1:2::1"), client_key("2001:db8:1:ffff::9")
    assert v6a == v6b, "same /48 must share a bucket"
    assert "2001" not in v6a


def _unverified_app(tmp_path):
    app = FastAPI()

    @app.get("/p")
    def p():
        return {"ok": True}

    app.add_middleware(KYAMiddleware, verifier=Verifier(KeyResolver(dev_mode=True)),
                       policy=PolicyEngine(UNVERIFIED_LIMIT), audit=AuditLog(str(tmp_path / "a.db")))
    return app


def test_d1_middleware_limits_rotating_keyids_from_one_client(tmp_path):
    c = TestClient(_unverified_app(tmp_path), client=("203.0.113.7", 5000))
    statuses = []
    for _ in range(5):
        k = Ed25519PrivateKey.generate()   # new keyid every request, directory offline
        h = sign_request("GET", "http://testserver/p", k, "http://127.0.0.1:1")
        r = c.get("/p", headers=h)
        statuses.append((r.status_code, r.headers["KYA-Decision"]))
    assert statuses[2:] == [(429, "rate_limit")] * 3
    rows = AuditLog(str(tmp_path / "a.db")).export_json()
    assert "203.0.113" not in rows, "raw IP must never reach the audit log"


# -- D2: admin endpoints need a bearer token ----------------------------------------------

def _admin_app(tmp_path, token):
    app = FastAPI()
    app.add_middleware(KYAMiddleware, verifier=Verifier(KeyResolver()), policy=PolicyEngine([]),
                       audit=AuditLog(str(tmp_path / "a.db")), admin_token=token)
    return TestClient(app)


@pytest.mark.parametrize("path", ["/_kya/dashboard", "/_kya/audit.json", "/_kya/verify-chain"])
def test_d2_admin_404_when_token_unset(tmp_path, monkeypatch, path):
    monkeypatch.delenv("KYA_ADMIN_TOKEN", raising=False)
    c = _admin_app(tmp_path, None)
    assert c.get(path).status_code == 404
    assert c.get(path, headers={"Authorization": "Bearer anything"}).status_code == 404


@pytest.mark.parametrize("path", ["/_kya/dashboard", "/_kya/audit.json", "/_kya/verify-chain"])
def test_d2_admin_401_on_wrong_or_missing_token(tmp_path, path):
    c = _admin_app(tmp_path, "s3cret-token")
    assert c.get(path).status_code == 401
    assert c.get(path, headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert c.get(path, headers={"Authorization": "Basic s3cret-token"}).status_code == 401


@pytest.mark.parametrize("path", ["/_kya/dashboard", "/_kya/audit.json", "/_kya/verify-chain"])
def test_d2_admin_200_on_right_token(tmp_path, path):
    c = _admin_app(tmp_path, "s3cret-token")
    assert c.get(path, headers={"Authorization": "Bearer s3cret-token"}).status_code == 200


def test_d2_token_read_from_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("KYA_ADMIN_TOKEN", "from-env")
    app = FastAPI()
    app.add_middleware(KYAMiddleware, verifier=Verifier(KeyResolver()), policy=PolicyEngine([]),
                       audit=AuditLog(str(tmp_path / "a.db")))
    c = TestClient(app)
    assert c.get("/_kya/verify-chain").status_code == 401
    assert c.get("/_kya/verify-chain", headers={"Authorization": "Bearer from-env"}).status_code == 200


# -- D5: cap on signature labels ------------------------------------------------------------

def _many_labels(n):
    one = '("@authority");created=1;expires=2;keyid="k";tag="web-bot-auth"'
    return {"host": "example.com",
            "signature-input": ", ".join(f"s{i}={one}" for i in range(n)),
            "signature": ", ".join(f"s{i}=:AAAA:" for i in range(n))}


def test_d5_thousand_labels_rejected_fast():
    v = Verifier(KeyResolver())
    t0 = time.perf_counter()
    res = v.verify(Request("GET", "https://example.com/", _many_labels(1000)))
    elapsed_ms = (time.perf_counter() - t0) * 1000
    assert res.outcome == Outcome.INVALID and res.reason == "too many signatures"
    assert elapsed_ms < 50, f"took {elapsed_ms:.1f} ms"


def test_d5_cap_is_configurable_and_defaults_to_3():
    assert Verifier(KeyResolver()).max_signatures == 3
    res = Verifier(KeyResolver()).verify(Request("GET", "https://example.com/", _many_labels(4)))
    assert res.reason == "too many signatures"
    res = Verifier(KeyResolver(), max_signatures=5).verify(Request("GET", "https://example.com/", _many_labels(4)))
    assert res.reason != "too many signatures"


def test_d5_no_directory_fetch_happens_for_over_cap_requests(monkeypatch):
    r = KeyResolver(dev_mode=True)
    monkeypatch.setattr(r, "resolve", lambda *a, **k: pytest.fail("resolver must not be called"))
    Verifier(r).verify(Request("GET", "https://example.com/", _many_labels(10)))


# -- D9: honour Cache-Control on directory fetches (draft Appendix A.4) ---------------------

class _Dir:
    """Local key directory server that counts fetches and sends a configurable Cache-Control."""

    def __init__(self, cache_control):
        self.hits, self.cache_control = 0, cache_control
        self.key = Ed25519PrivateKey.generate()
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                outer.hits += 1
                body = json.dumps({"keys": [public_jwk(outer.key)]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/http-message-signatures-directory+json")
                if outer.cache_control is not None:
                    self.send_header("Cache-Control", outer.cache_control)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        self.kid = public_jwk(self.key)["kid"]

    def close(self):
        self.srv.shutdown()


@pytest.fixture
def directory(request):
    d = _Dir(request.param)
    yield d
    d.close()


def _resolve_n(d, n, clock=None):
    r = KeyResolver(dev_mode=True)
    for _ in range(n):
        r.resolve(d.kid, d.url)
    return r


@pytest.mark.parametrize("directory", ["no-store", "no-cache", "private, no-store", "No-Cache"], indirect=True)
def test_d9_no_store_and_no_cache_fetch_every_time(directory):
    _resolve_n(directory, 3)
    assert directory.hits == 3


@pytest.mark.parametrize("directory", ["max-age=60", "public, max-age=60"], indirect=True)
def test_d9_max_age_fetches_once_per_window(directory, monkeypatch):
    import kya_gateway.keys as keys_mod
    t = [1_000_000.0]
    monkeypatch.setattr(keys_mod.time, "time", lambda: t[0])
    r = KeyResolver(dev_mode=True)
    for _ in range(5):
        r.resolve(directory.kid, directory.url)
        t[0] += 10          # 5 fetches spread over 50 s
    assert directory.hits == 1
    t[0] += 20              # now 70 s after the first fetch
    r.resolve(directory.kid, directory.url)
    assert directory.hits == 2


@pytest.mark.parametrize("directory", [None], indirect=True)
def test_d9_missing_header_uses_default_ttl(directory, monkeypatch):
    import kya_gateway.keys as keys_mod
    t = [1_000_000.0]
    monkeypatch.setattr(keys_mod.time, "time", lambda: t[0])
    r = KeyResolver(dev_mode=True, default_ttl_s=300)
    r.resolve(directory.kid, directory.url)
    t[0] += 299
    r.resolve(directory.kid, directory.url)
    assert directory.hits == 1
    t[0] += 2
    r.resolve(directory.kid, directory.url)
    assert directory.hits == 2


# -- E1: operator policy match must not be a substring match --------------------------------

def _verified(operator):
    return VerificationResult(Outcome.VERIFIED, "ok", operator=operator)


@pytest.mark.parametrize("rule_value", ["acme.com", "https://acme.com"])
def test_e1_lookalike_directory_does_not_match_operator_rule(rule_value):
    p = PolicyEngine([{"name": "trust-acme", "match": {"operator": rule_value}, "action": "allow"}], "block")
    evil = "https://acme.com.attacker.io/.well-known/http-message-signatures-directory"
    assert p.decide(_verified(evil), "GET", "/").rule == "default"
    evil2 = "https://attacker.io/acme.com/.well-known/http-message-signatures-directory"
    assert p.decide(_verified(evil2), "GET", "/").rule == "default"
    good = "https://acme.com/.well-known/http-message-signatures-directory"
    assert p.decide(_verified(good), "GET", "/").rule == "trust-acme"


def test_e1_static_operator_matches_exactly():
    p = PolicyEngine([{"name": "s", "match": {"operator": "static:acme"}, "action": "allow"}], "block")
    assert p.decide(_verified("static:acme"), "GET", "/").rule == "s"
    assert p.decide(_verified("static:acme-evil"), "GET", "/").rule == "default"


# -- E2: directory allowlist must not be a prefix match -------------------------------------

def test_e2_allowlist_rejects_lookalike_host():
    from kya_gateway.keys import KeyNotFound
    r = KeyResolver(allowed_directories=["https://acme.com"])
    with pytest.raises(KeyNotFound):
        r._fetch_url("https://acme.com.attacker.io", "directory")
    with pytest.raises(KeyNotFound):
        r._fetch_url("https://acme.com:8443", "directory")
    assert r._fetch_url("https://acme.com", "directory").startswith("https://acme.com/")


# -- E3: malformed parameters must give 'invalid', not an exception -------------------------

@pytest.mark.parametrize("params", [
    'created="abc";expires=2;keyid="k"',
    'created=1;expires="x";keyid="k"',
    'created=1;expires=2;keyid=5',
    'created=1;expires=2;keyid="k";alg=5',
    'created=1;expires=2;keyid="k";nonce=7',
    'created=?1;expires=2;keyid="k"',
    'created=1.5;expires=2;keyid="k"',
])
def test_e3_malformed_params_are_invalid(params):
    tag = ';tag="web-bot-auth"'
    h = {"host": "example.com", "signature-input": f'sig1=("@authority");{params}{tag}',
         "signature": "sig1=:AAAA:"}
    res = Verifier(KeyResolver()).verify(Request("GET", "https://example.com/", h))
    assert res.outcome == Outcome.INVALID


def test_e3_non_string_tag_is_not_a_crash():
    h = {"host": "example.com", "signature-input": 'sig1=("@authority");created=1;expires=2;keyid="k";tag=5',
         "signature": "sig1=:AAAA:"}
    res = Verifier(KeyResolver()).verify(Request("GET", "https://example.com/", h))
    assert res.outcome in (Outcome.INVALID, Outcome.UNVERIFIED)
