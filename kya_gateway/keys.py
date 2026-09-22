"""Key discovery for Web Bot Auth: static keys plus Signature-Agent directory fetches,
with the SSRF limits and caching rules from draft-meunier-webbotauth-httpsig-protocol-00."""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import socket
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

WELL_KNOWN = "/.well-known/http-message-signatures-directory"

# Ed25519 test key from RFC 9421 Appendix B.1.4, used by the draft's test vectors.
# The draft says verifiers SHOULD reject known test keys in production.
KNOWN_TEST_KEYIDS = {"poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U"}


class KeyNotFound(Exception):
    """Key material could not be obtained -> outcome 'unverified', not 'invalid'."""


class TestKeyRejected(Exception):
    """A published test key was used outside dev mode -> outcome 'invalid'."""


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def jwk_thumbprint(jwk: dict) -> str:
    """RFC 7638 thumbprint; RFC 8037 A.3 member set for OKP keys."""
    if jwk.get("kty") != "OKP":
        raise ValueError("POC supports OKP (Ed25519) keys only")
    canon = json.dumps({"crv": jwk["crv"], "kty": "OKP", "x": jwk["x"]},
                       separators=(",", ":"), sort_keys=True)
    return b64url_encode(hashlib.sha256(canon.encode()).digest())


def _seconds(ts: float) -> float:
    """JWK nbf/exp should be NumericDate seconds, but Cloudflare's own research directory
    publishes milliseconds (nbf=1743465600000, seen Sept 2026). Values after year 5000 in
    seconds are treated as milliseconds.
    SPEC-QUESTION: the draft does not state the unit for directory nbf/exp."""
    return ts / 1000 if ts > 1e11 else ts


def directory_ttl(cache_control: str, default_ttl_s: int, cap_s: int = 86_400) -> float:
    """Seconds a fetched directory may be reused (draft Appendix A.4: "use normal HTTP caching
    semantics"; RFC 9111 section 5.2.2). no-store and no-cache both mean "do not reuse without
    going back to the origin"; the POC has no conditional requests (ETag) yet, so no-cache is
    treated like no-store, i.e. a fresh fetch per verification (stricter reading).
    max-age wins over the default; a missing header uses the default TTL."""
    directives = {}
    for part in cache_control.lower().split(","):
        name, _, value = part.strip().partition("=")
        if name:
            directives[name] = value.strip().strip('"')
    if "no-store" in directives or "no-cache" in directives:
        return 0.0
    if "max-age" in directives:
        try:
            return float(min(max(int(directives["max-age"]), 0), cap_s))
        except ValueError:
            return 0.0      # RFC 9111 5.2.2.1: invalid max-age -> treat as stale
    return float(default_ttl_s)


def jwk_to_public_key(jwk: dict) -> Ed25519PublicKey:
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise ValueError("unsupported key type")
    return Ed25519PublicKey.from_public_bytes(b64url_decode(jwk["x"]))


@dataclass
class ResolvedKey:
    keyid: str
    public_key: Ed25519PublicKey
    source: str          # directory URL or "static:<label>"


@dataclass
class _CacheEntry:
    expires_at: float
    keys: dict[str, dict] = field(default_factory=dict)   # kid -> jwk
    error: str | None = None


class KeyResolver:
    def __init__(self, *, dev_mode: bool = False, timeout_s: float = 3.0,
                 max_bytes: int = 64_000, max_keys: int = 32,
                 default_ttl_s: int = 300, negative_ttl_s: int = 300,
                 allowed_directories: list[str] | None = None):
        self.dev_mode = dev_mode
        self.timeout_s = timeout_s
        self.max_bytes = max_bytes
        self.max_keys = max_keys
        self.default_ttl_s = default_ttl_s
        self.negative_ttl_s = min(negative_ttl_s, 300)   # draft: no more than 5 minutes
        self.allowed_directories = allowed_directories   # None = any public directory
        self._static: dict[str, ResolvedKey] = {}
        self._cache: dict[str, _CacheEntry] = {}

    # -- static keys (out-of-band registration, draft section 4.5.1) --------------
    def add_static_jwk(self, jwk: dict, label: str) -> str:
        kid = jwk_thumbprint(jwk)
        self._static[kid] = ResolvedKey(kid, jwk_to_public_key(jwk), f"static:{label}")
        return kid

    # -- main entry ---------------------------------------------------------------
    def resolve(self, keyid: str, agent_url: str | None, agent_type: str = "directory") -> ResolvedKey:
        if keyid in KNOWN_TEST_KEYIDS and not self.dev_mode:
            raise TestKeyRejected("known test key used outside dev mode")
        if keyid in self._static:
            return self._static[keyid]
        if not agent_url:
            raise KeyNotFound("unknown keyid and no Signature-Agent to discover it")

        fetch_url = self._fetch_url(agent_url, agent_type)
        entry = self._cache.get(fetch_url)
        if entry is None or entry.expires_at <= time.time():
            entry = self._fetch(fetch_url)
            self._cache[fetch_url] = entry
        if entry.error:
            raise KeyNotFound(f"directory unavailable: {entry.error}")
        jwk = entry.keys.get(keyid)
        if jwk is None:
            raise KeyNotFound("keyid not published in the agent's directory")
        now = time.time()
        if "nbf" in jwk and now < _seconds(jwk["nbf"]):
            raise KeyNotFound("key not yet valid (nbf)")
        if "exp" in jwk and now > _seconds(jwk["exp"]):
            raise KeyNotFound("key expired (exp)")
        # Identity is the (directory URL, key) pair, never the key alone.
        return ResolvedKey(keyid, jwk_to_public_key(jwk), fetch_url)

    # -- helpers ------------------------------------------------------------------
    def _fetch_url(self, agent_url: str, agent_type: str) -> str:
        parts = urlsplit(agent_url)
        if parts.scheme not in ("https", "http") or not parts.hostname:
            raise KeyNotFound("Signature-Agent is not an absolute URL")
        if parts.scheme == "http" and not self.dev_mode:
            raise KeyNotFound("Signature-Agent must use https")
        if agent_type == "jwks_uri":
            url = agent_url
        elif agent_type == "directory":
            url = urlunsplit((parts.scheme, parts.netloc, WELL_KNOWN, "", ""))
        else:
            raise KeyNotFound(f"discovery type {agent_type!r} not supported in POC")
        if self.allowed_directories is not None and not any(
                url.startswith(a) for a in self.allowed_directories):
            raise KeyNotFound("directory not on the allowlist")
        return url

    def _check_host(self, host: str) -> None:
        if self.dev_mode:
            return
        try:
            infos = socket.getaddrinfo(host, None)
        except socket.gaierror as exc:
            raise KeyNotFound(f"DNS failure for {host}") from exc
        for info in infos:
            ip = ipaddress.ip_address(info[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved \
                    or ip.is_multicast or ip.is_unspecified:
                raise KeyNotFound(f"refusing to fetch directory on non-public address {ip}")

    def _fetch(self, url: str) -> _CacheEntry:
        try:
            self._check_host(urlsplit(url).hostname or "")
            with httpx.Client(timeout=self.timeout_s, follow_redirects=False) as client:
                with client.stream("GET", url, headers={"accept": "application/json"}) as r:
                    if r.status_code != 200:
                        raise KeyNotFound(f"HTTP {r.status_code}")
                    body = b""
                    for chunk in r.iter_bytes():
                        body += chunk
                        if len(body) > self.max_bytes:
                            raise KeyNotFound("directory response too large")
                    cache_control = r.headers.get("cache-control", "")
            data = json.loads(body)
            raw_keys = data.get("keys", [])
            if len(raw_keys) > self.max_keys:
                raise KeyNotFound("too many keys in directory")
            keys = {}
            for jwk in raw_keys:
                try:
                    keys[jwk_thumbprint(jwk)] = jwk
                except (ValueError, KeyError):
                    continue   # skip unsupported key types
            ttl = directory_ttl(cache_control, self.default_ttl_s)
            return _CacheEntry(expires_at=time.time() + ttl, keys=keys)
        except (KeyNotFound, httpx.HTTPError, ValueError) as exc:
            return _CacheEntry(expires_at=time.time() + self.negative_ttl_s, error=str(exc))
