"""R2: interop with Cloudflare's Rust crate web-bot-auth 0.7.0 (interop/rust), both directions.
Skips when cargo is missing. The binary is built once per session (cargo build --release)."""
import copy
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from kya_gateway.sigbase import Request
from kya_gateway.signer import sign_request
from kya_gateway.verifier import Outcome
from tests.test_interop import TEST_PRIV, our_verifier

RUST = Path(__file__).resolve().parent.parent / "interop" / "rust"
BIN = RUST / "target" / "release" / "kya-interop"
pytestmark = [pytest.mark.interop,
              pytest.mark.skipif(not shutil.which("cargo"), reason="cargo not installed")]


@pytest.fixture(scope="session")
def rust():
    subprocess.run(["cargo", "build", "-q", "--release"], cwd=RUST, check=True, timeout=600)

    def run(*args):
        return subprocess.run([str(BIN), *args], capture_output=True, text=True, timeout=30,
                              check=True).stdout.strip()
    return run


@pytest.mark.parametrize("url", ["https://example.com/", "https://shop.example/products/42?c=red"])
def test_rust_crate_signs_we_verify(rust, url):
    h = {k.lower(): v for k, v in json.loads(rust("sign", url, "https://signature-agent.test")).items()}
    h["host"] = url.split("/")[2]
    res = our_verifier().verify(Request("GET", url, h))
    assert res.outcome == Outcome.VERIFIED, res.reason


@pytest.mark.parametrize("fmt,extra", [("dict", ()), ("dict", ("@method", "@path")),
                                        ("legacy", ()), ("none", ())])
def test_we_sign_rust_crate_verifies(rust, fmt, extra):
    url = "https://example.com/products/42"
    h = sign_request("GET", url, TEST_PRIV, "https://signature-agent.test", agent_format=fmt,
                     extra_components=extra)
    assert rust("verify", "GET", url, json.dumps(h)) == "RUST_VERIFY_OK"


def test_rust_crate_rejects_our_tampered_signature(rust):
    import base64
    url = "https://example.com/"
    h = sign_request("GET", url, TEST_PRIV, "https://signature-agent.test")
    raw = bytearray(base64.b64decode(h["Signature"].split(":")[1]))
    raw[0] ^= 0x01
    h["Signature"] = f"sig1=:{base64.b64encode(bytes(raw)).decode()}:"
    assert rust("verify", "GET", url, json.dumps(h)).startswith("RUST_VERIFY_FAIL")


def test_rust_crate_signature_with_swapped_agent_is_invalid_for_us(rust):
    url = "https://example.com/"
    h = {k.lower(): v for k, v in json.loads(rust("sign", url, "https://signature-agent.test")).items()}
    h["host"] = "example.com"
    bad = copy.deepcopy(h)
    bad["signature-agent"] = 'agent1="https://attacker.test"'
    assert our_verifier().verify(Request("GET", url, bad)).outcome == Outcome.INVALID
