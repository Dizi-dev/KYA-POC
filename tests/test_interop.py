"""Interoperability evidence.

interop tests: our signer <-> Cloudflare's reference library (web-bot-auth 0.2.0), offline.
network tests: live endpoints, only with KYA_NETWORK=1.
"""
import base64
import json
import os
import shutil
import subprocess
import time
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives.serialization import load_der_private_key

from kya_gateway import KeyResolver, Verifier
from kya_gateway.sigbase import Request
from kya_gateway.signer import sign_request
from kya_gateway.verifier import Outcome

JS = Path(__file__).resolve().parent.parent / "interop" / "js"
HAVE_JS = shutil.which("node") and (JS / "node_modules" / "web-bot-auth").exists()
NETWORK = os.environ.get("KYA_NETWORK") == "1"

# RFC 9421 Appendix B.1.4 test key (public test material, dev only)
TEST_PRIV = load_der_private_key(base64.b64decode(
    "MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF"), None)
TEST_JWK = {"kty": "OKP", "crv": "Ed25519", "x": "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"}
CF_SERVER = "https://http-message-signatures-example.research.cloudflare.com"


def node(*args: str) -> str:
    return subprocess.run(["node", *args], cwd=JS, capture_output=True, text=True,
                          timeout=30, check=True).stdout.strip()


def our_verifier() -> Verifier:
    r = KeyResolver(dev_mode=True)
    r.add_static_jwk(TEST_JWK, "rfc9421-test")
    return Verifier(r)


@pytest.mark.interop
@pytest.mark.skipif(not HAVE_JS, reason="run: cd interop/js && npm install")
@pytest.mark.parametrize("path", ["/", "/products/42?color=red"])
def test_cloudflare_library_signs_we_verify(path):
    url = "https://shop.example" + path
    h = json.loads(node("sign.mjs", url, f'sig1="{CF_SERVER}";type=directory'))
    res = our_verifier().verify(Request("GET", url, {"host": "shop.example", **{k.lower(): v for k, v in h.items()}}))
    assert res.outcome == Outcome.VERIFIED, res.reason


@pytest.mark.interop
@pytest.mark.skipif(not HAVE_JS, reason="run: cd interop/js && npm install")
@pytest.mark.parametrize("fmt,extra", [("dict", ()), ("dict", ("@method", "@path")), ("legacy", ()), ("none", ())])
def test_we_sign_cloudflare_library_verifies(fmt, extra):
    url = "https://shop.example/products/42"
    h = sign_request("GET", url, TEST_PRIV, CF_SERVER, agent_format=fmt, extra_components=extra)
    assert node("verify.mjs", url, json.dumps(h)) == "CF_VERIFY_OK"


@pytest.mark.interop
@pytest.mark.skipif(not HAVE_JS, reason="run: cd interop/js && npm install")
def test_cloudflare_library_rejects_our_tampered_signature():
    url = "https://shop.example/products/42"
    h = sign_request("GET", url, TEST_PRIV, CF_SERVER)
    # Flip a bit in the decoded signature bytes. (Editing a base64 character is not enough:
    # the last character before "==" carries padding bits, so some edits decode identically.)
    label, b64 = h["Signature"].split("=:", 1)
    raw = bytearray(base64.b64decode(b64.rstrip(":")))
    raw[10] ^= 0x01
    h["Signature"] = f"{label}=:{base64.b64encode(bytes(raw)).decode()}:"
    assert node("verify.mjs", url, json.dumps(h)).startswith("CF_VERIFY_FAIL")


def _live_verdict(headers: dict) -> str:
    text = httpx.get(CF_SERVER + "/", headers=headers, timeout=20).text
    if "You successfully authenticated" in text:
        return "accepted"
    if "does not validate" in text:
        return "rejected"
    return "no-verdict"


@pytest.mark.network
@pytest.mark.skipif(not NETWORK, reason="set KYA_NETWORK=1")
@pytest.mark.parametrize("fmt", ["none", "legacy"])
def test_live_cloudflare_server_accepts_our_signatures(fmt):
    h = sign_request("GET", CF_SERVER + "/", TEST_PRIV, CF_SERVER, agent_format=fmt, extra_components=())
    assert _live_verdict(h) == "accepted"


@pytest.mark.network
@pytest.mark.skipif(not NETWORK, reason="set KYA_NETWORK=1")
def test_live_cloudflare_server_dict_form_status():
    """Known gap on 22 Sep 2026: the live research server rejected the draft-00 dictionary
    form even when produced by Cloudflare's own library. Record, don't assert acceptance."""
    h = sign_request("GET", CF_SERVER + "/", TEST_PRIV, CF_SERVER, agent_format="dict", extra_components=())
    assert _live_verdict(h) in ("accepted", "rejected")


@pytest.mark.network
@pytest.mark.skipif(not NETWORK, reason="set KYA_NETWORK=1")
@pytest.mark.parametrize("operator", [CF_SERVER, "https://chatgpt.com"])
def test_live_directory_discovery_with_production_ssrf_rules(operator):
    """Key discovery against real published directories, dev_mode OFF (full SSRF checks)."""
    r = KeyResolver(dev_mode=False)
    url = r._fetch_url(operator, "directory")
    entry = r._fetch(url)
    assert entry.error is None, entry.error
    assert len(entry.keys) >= 1
    kid = next(iter(entry.keys))
    if kid == "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U":
        pytest.skip("directory only publishes the RFC 9421 test key, which production mode rejects")
    key = r.resolve(kid, operator)
    assert key.source.endswith("/.well-known/http-message-signatures-directory")
