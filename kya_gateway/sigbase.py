"""RFC 9421 signature base construction (the subset Web Bot Auth needs)."""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

import http_sfv


class SignatureBaseError(ValueError):
    pass


@dataclass
class Request:
    method: str
    url: str                      # full URL as the server saw it
    headers: dict[str, str]       # lower-cased header names

    @property
    def authority(self) -> str:
        host = self.headers.get("host") or urlsplit(self.url).netloc
        return host.strip().lower()

    @property
    def path(self) -> str:
        return urlsplit(self.url).path or "/"

    @property
    def query(self) -> str:
        return "?" + urlsplit(self.url).query


def _component_value(req: Request, name: str, params: dict) -> str:
    if name == "@authority":
        return req.authority
    if name == "@method":
        return req.method.upper()
    if name == "@path":
        return req.path
    if name == "@query":
        return req.query
    if name == "@target-uri":
        return req.url
    if name.startswith("@"):
        raise SignatureBaseError(f"unsupported derived component {name}")

    raw = req.headers.get(name)
    if raw is None:
        raise SignatureBaseError(f"covered header {name} missing")
    if "key" in params:
        # Dictionary member: serialize just that member (RFC 9421 section 2.1.2)
        d = http_sfv.Dictionary()
        try:
            d.parse(raw.encode())
        except Exception as exc:  # noqa: BLE001
            raise SignatureBaseError(f"{name} is not a structured dictionary") from exc
        if params["key"] not in d:
            raise SignatureBaseError(f"{name} has no member {params['key']}")
        return str(d[params["key"]])
    return raw.strip()


def _component_id(name: str, params: dict) -> str:
    out = f'"{name}"'
    for k, v in params.items():
        if v is True:
            out += f";{k}"
        elif isinstance(v, str):
            out += f';{k}="{v}"'
        else:
            out += f";{k}={v}"
    return out


def build_signature_base(req: Request, inner_list: "http_sfv.InnerList") -> bytes:
    lines, seen = [], set()
    for item in inner_list:
        cid = _component_id(item.value, dict(item.params))
        if cid in seen:
            raise SignatureBaseError(f"duplicate component {cid}")
        seen.add(cid)
        lines.append(f"{cid}: {_component_value(req, item.value, dict(item.params))}")
    lines.append(f'"@signature-params": {inner_list}')
    return "\n".join(lines).encode()
