"""Web Bot Auth / Visa TAP verifier. Returns one of four outcomes per request:
unsigned, verified, invalid, unverified (draft Appendix A.1 keeps the last three distinct)."""
from __future__ import annotations

import base64
import time
from dataclasses import dataclass
from enum import Enum
from typing import Callable

import http_sfv
from cryptography.exceptions import InvalidSignature

from .keys import KeyNotFound, KeyResolver, TestKeyRejected
from .sigbase import Request, SignatureBaseError, build_signature_base

DEFAULT_TAGS = {"web-bot-auth", "agent-browser-auth", "agent-payer-auth"}  # Web Bot Auth + Visa TAP


class Outcome(str, Enum):
    UNSIGNED = "unsigned"        # no signature at all: ordinary bot-management path
    VERIFIED = "verified"        # signature and key material validate
    INVALID = "invalid"          # signature, components, key or freshness check failed
    UNVERIFIED = "unverified"    # could not get enough information to decide


@dataclass
class VerificationResult:
    outcome: Outcome
    reason: str
    label: str | None = None
    keyid: str | None = None
    operator: str | None = None  # where the key came from (directory URL or static label)
    tag: str | None = None
    covered: list[str] | None = None


class NonceStore:
    """In-memory replay guard. Production would use Redis with TTL = signature lifetime."""

    def __init__(self):
        self._seen: dict[str, float] = {}

    def check_and_add(self, nonce: str, expires: float, now: float) -> bool:
        self._seen = {n: e for n, e in self._seen.items() if e >= now}
        if nonce in self._seen:
            return False
        self._seen[nonce] = expires
        return True


class Verifier:
    def __init__(self, resolver: KeyResolver, *, accepted_tags: set[str] | None = None,
                 max_validity_s: int = 86_400, clock_skew_s: int = 60,
                 require_nonce: bool = False, now: Callable[[], float] = time.time):
        self.resolver = resolver
        self.accepted_tags = accepted_tags or DEFAULT_TAGS
        self.max_validity_s = max_validity_s
        self.clock_skew_s = clock_skew_s
        self.require_nonce = require_nonce
        self.now = now
        self.nonces = NonceStore()

    def verify(self, req: Request) -> VerificationResult:
        sig_input_raw = req.headers.get("signature-input")
        sig_raw = req.headers.get("signature")
        if not sig_input_raw and not sig_raw:
            return VerificationResult(Outcome.UNSIGNED, "no signature headers")
        if not (sig_input_raw and sig_raw):
            return VerificationResult(Outcome.INVALID, "Signature and Signature-Input must both be present")

        inputs, sigs = http_sfv.Dictionary(), http_sfv.Dictionary()
        try:
            inputs.parse(sig_input_raw.encode())
            sigs.parse(sig_raw.encode())
        except Exception:  # noqa: BLE001
            return VerificationResult(Outcome.INVALID, "malformed signature headers")

        best: VerificationResult | None = None
        for label in inputs:
            result = self._verify_label(req, label, inputs[label], sigs)
            if result.outcome == Outcome.VERIFIED:
                return result
            # prefer reporting 'invalid' over 'unverified' over 'skipped'
            if best is None or (best.outcome != Outcome.INVALID and result.outcome == Outcome.INVALID):
                best = result
        return best or VerificationResult(Outcome.INVALID, "no usable signature")

    def _verify_label(self, req: Request, label: str, inner, sigs) -> VerificationResult:
        p = dict(inner.params)
        tag = p.get("tag")
        base = VerificationResult(Outcome.INVALID, "", label=label, keyid=p.get("keyid"), tag=tag,
                                  covered=[i.value for i in inner])

        def fail(outcome: Outcome, reason: str) -> VerificationResult:
            base.outcome, base.reason = outcome, reason
            return base

        if tag not in self.accepted_tags:
            return fail(Outcome.UNVERIFIED, f"tag {tag!r} not accepted")
        for required in ("created", "expires", "keyid"):
            if required not in p:
                return fail(Outcome.INVALID, f"missing {required}")
        alg = p.get("alg", "ed25519")
        if alg != "ed25519":
            # The draft forbids shared-secret HMAC; this POC implements Ed25519 only.
            return fail(Outcome.INVALID if alg.startswith("hmac") else Outcome.UNVERIFIED,
                        f"alg {alg} not accepted")
        names = [i.value for i in inner]
        if "@authority" not in names and "@target-uri" not in names:
            return fail(Outcome.INVALID, "must cover @authority or @target-uri")

        now = self.now()
        created, expires = p["created"], p["expires"]
        if created > now + self.clock_skew_s:
            return fail(Outcome.INVALID, "created is in the future")
        if expires < now - self.clock_skew_s:
            return fail(Outcome.INVALID, "signature expired")
        if expires - created > self.max_validity_s:
            return fail(Outcome.INVALID, "validity window too long")
        nonce = p.get("nonce")
        if self.require_nonce and not nonce:
            return fail(Outcome.INVALID, "nonce required")

        # Signature-Agent: if present, one member must be covered and it points at the key.
        agent_url, agent_type = None, "directory"
        sa_raw = req.headers.get("signature-agent")
        if sa_raw:
            covered_sa = [dict(i.params).get("key") for i in inner if i.value == "signature-agent"]
            if not covered_sa:
                return fail(Outcome.INVALID, "Signature-Agent present but not signed")
            member = covered_sa[0]
            try:
                if member is None:   # legacy sf-string form
                    item = http_sfv.Item()
                    item.parse(sa_raw.encode())
                    agent_url = item.value
                else:
                    d = http_sfv.Dictionary()
                    d.parse(sa_raw.encode())
                    agent_url = d[member].value
                    agent_type = dict(d[member].params).get("type", "directory")
            except Exception:  # noqa: BLE001
                return fail(Outcome.INVALID, "malformed Signature-Agent")

        try:
            key = self.resolver.resolve(p["keyid"], agent_url, agent_type)
        except TestKeyRejected as exc:
            return fail(Outcome.INVALID, str(exc))
        except KeyNotFound as exc:
            return fail(Outcome.UNVERIFIED, str(exc))
        base.operator = key.source

        if label not in sigs:
            return fail(Outcome.INVALID, "no Signature value for this label")
        signature = sigs[label].value
        if not isinstance(signature, (bytes, bytearray)):
            return fail(Outcome.INVALID, "Signature value is not a byte sequence")
        try:
            sig_base = build_signature_base(req, inner)
            key.public_key.verify(bytes(signature), sig_base)
        except SignatureBaseError as exc:
            return fail(Outcome.INVALID, str(exc))
        except InvalidSignature:
            return fail(Outcome.INVALID, "signature does not match")

        if nonce and not self.nonces.check_and_add(nonce, expires, now):
            return fail(Outcome.INVALID, "nonce replayed")
        base.outcome, base.reason = Outcome.VERIFIED, "ok"
        return base
