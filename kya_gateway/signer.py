"""Agent-side signer, used by the demo agent and tests. Produces Web Bot Auth headers."""
from __future__ import annotations

import base64
import os
import time
from urllib.parse import urlsplit

import http_sfv
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .keys import b64url_encode, jwk_thumbprint
from .sigbase import Request, build_signature_base


def public_jwk(private_key: Ed25519PrivateKey) -> dict:
    from cryptography.hazmat.primitives import serialization
    raw = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64url_encode(raw)}
    jwk["kid"] = jwk_thumbprint(jwk)
    return jwk


def sign_request(method: str, url: str, private_key: Ed25519PrivateKey, agent_url: str, *,
                 tag: str = "web-bot-auth", label: str = "sig1", ttl_s: int = 60,
                 extra_components: tuple[str, ...] = ("@method", "@path"),
                 agent_format: str = "dict") -> dict[str, str]:
    """agent_format: "dict" = label="url" member, as in draft-meunier-webbotauth-httpsig-protocol-00;
    "legacy" = bare sf-string, older architecture draft; "none" = no Signature-Agent header."""
    host = urlsplit(url).netloc
    keyid = jwk_thumbprint(public_jwk(private_key))
    now = int(time.time())
    nonce = base64.b64encode(os.urandom(64)).decode()
    if agent_format not in ("dict", "legacy", "none"):
        raise ValueError("agent_format must be dict, legacy or none")
    comps = " ".join(f'"{c}"' for c in ("@authority",) + extra_components)
    if agent_format == "dict":
        sig_agent, sa_comp = f'{label}="{agent_url}"', f' "signature-agent";key="{label}"'
    elif agent_format == "legacy":
        sig_agent, sa_comp = f'"{agent_url}"', ' "signature-agent"'
    else:
        sig_agent, sa_comp = None, ""
    inner_txt = (f'({comps}{sa_comp});created={now};expires={now + ttl_s};'
                 f'keyid="{keyid}";alg="ed25519";nonce="{nonce}";tag="{tag}"')
    d = http_sfv.Dictionary()
    d.parse(f"{label}={inner_txt}".encode())
    headers = {"host": host}
    if sig_agent:
        headers["signature-agent"] = sig_agent
    base = build_signature_base(Request(method, url, headers), d[label])
    signature = base64.b64encode(private_key.sign(base)).decode()
    out = {"Signature-Input": f"{label}={d[label]}", "Signature": f"{label}=:{signature}:"}
    if sig_agent:
        out["Signature-Agent"] = sig_agent
    return out
