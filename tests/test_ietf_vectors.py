"""Checks the verifier against the Ed25519 test vectors in Appendix C.2 of
draft-meunier-webbotauth-httpsig-protocol-00 (key from RFC 9421 Appendix B.1.4)."""
import copy

import pytest

from kya_gateway.keys import KeyResolver
from kya_gateway.sigbase import Request
from kya_gateway.verifier import Outcome, Verifier

TEST_JWK = {"kty": "OKP", "crv": "Ed25519", "x": "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"}
KEYID = "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U"

C21 = {  # Signature-Agent absent
    "host": "example.com",
    "signature-input": 'sig1=("@authority");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=4889289600;nonce="zIW8+cdmA3vdYagbxojpONwa/l0EKJ/O3/wD486VvsQjO/RxPaSt6ZxvQaMcQzNnqKN/mQ6hpGiFro2L2qkz5A==";tag="web-bot-auth"',
    "signature": "sig1=:QKN4fTdIYfh82fvoZCQiQA1weuozfCS/Led2zTMbewMMqH8PI2Wsy/5c4ao6B6D09nraNQdBNOADg8aM1MqfCg==:",
}
C22 = {  # Signature-Agent dictionary member covered
    "host": "example.com",
    "signature-agent": 'agent2="https://signature-agent.test"',
    "signature-input": 'sig2=("@authority" "signature-agent";key="agent2");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=4889289600;nonce="n9p433xm+NJ3ph3upfBIGmsuwHw387YV7Q/F+6BSpGCVjYCqQw6rznNA8PVVLySrAWsv0hQtFioQb6E1YsauiA==";tag="web-bot-auth"',
    "signature": "sig2=:RdNFx5Bj6au3YgAMQL/RzmUlZE8QZLIaXGRpw985hWnwPfMxT228NMk6ehRS1PSl4e8PhbNZACSanGdhEwYCCg==:",
}
C23 = {  # legacy sf-string Signature-Agent
    "host": "example.com",
    "signature-agent": '"https://signature-agent.test"',
    "signature-input": 'sig2=("@authority" "signature-agent");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=1735693200;nonce="e8N7S2MFd/qrd6T2R3tdfAuuANngKI7LFtKYI/vowzk4lAZYadIX6wW25MwG7DCT9RUKAJ0qVkU0mEeLElW1qg==";tag="web-bot-auth"',
    "signature": "sig2=:jdq0SqOwHdyHr9+r5jw3iYZH6aNGKijYp/EstF4RQTQdi5N5YYKrD+mCT1HA1nZDsi6nJKuHxUi/5Syp3rLWBA==:",
}


def make_verifier(dev_mode=True):
    r = KeyResolver(dev_mode=dev_mode)
    assert r.add_static_jwk(TEST_JWK, "rfc9421-test") == KEYID
    # vectors use century-long validity; relax the 24h cap and pin the clock
    return Verifier(r, max_validity_s=10**10, now=lambda: 1735690000)


def req(headers):
    return Request("GET", "https://example.com/", headers)


@pytest.mark.parametrize("vector", [C21, C22, C23], ids=["C.2.1", "C.2.2", "C.2.3-legacy"])
def test_vectors_verify(vector):
    res = make_verifier().verify(req(vector))
    assert res.outcome == Outcome.VERIFIED, res.reason


def test_tampered_authority_is_invalid():
    h = dict(C22, host="evil.example")
    assert make_verifier().verify(req(h)).outcome == Outcome.INVALID


def test_swapped_signature_agent_is_invalid():
    h = dict(C22, **{"signature-agent": 'agent2="https://attacker.test"'})
    assert make_verifier().verify(req(h)).outcome == Outcome.INVALID


def test_test_key_rejected_outside_dev_mode():
    res = make_verifier(dev_mode=False).verify(req(C21))
    assert res.outcome == Outcome.INVALID and "test key" in res.reason


def test_replayed_nonce_is_invalid():
    v = make_verifier()
    assert v.verify(req(C21)).outcome == Outcome.VERIFIED
    assert v.verify(req(copy.deepcopy(C21))).outcome == Outcome.INVALID


def test_default_24h_cap_rejects_long_lived_signature():
    r = KeyResolver(dev_mode=True)
    r.add_static_jwk(TEST_JWK, "t")
    res = Verifier(r, now=lambda: 1735690000).verify(req(C21))
    assert res.outcome == Outcome.INVALID and "too long" in res.reason


def test_unsigned_request():
    assert make_verifier().verify(req({"host": "example.com"})).outcome == Outcome.UNSIGNED


def test_unknown_key_without_directory_is_unverified():
    v = Verifier(KeyResolver(dev_mode=True), max_validity_s=10**10, now=lambda: 1735690000)
    assert v.verify(req(C21)).outcome == Outcome.UNVERIFIED


def test_hmac_rejected():
    h = dict(C21, **{"signature-input": C21["signature-input"].replace('alg="ed25519"', 'alg="hmac-sha256"')})
    assert make_verifier().verify(req(h)).outcome == Outcome.INVALID


def test_ssrf_guard_blocks_private_directory():
    from kya_gateway.keys import KeyNotFound
    r = KeyResolver(dev_mode=False)
    for url in ["https://127.0.0.1", "https://10.0.0.5", "https://169.254.169.254", "http://example.com"]:
        with pytest.raises(KeyNotFound):
            r.resolve("some-keyid", url)
