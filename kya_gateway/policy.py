"""First-match-wins policy rules: map a verification result + request to a decision."""
from __future__ import annotations

import fnmatch
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from urllib.parse import urlsplit

import yaml

from .verifier import Outcome, VerificationResult

ACTIONS = {"allow", "block", "rate_limit", "charge"}


@dataclass
class Decision:
    action: str            # allow | block | rate_limit | charge
    rule: str              # rule name that matched
    status: int            # HTTP status to return if not allowed through
    detail: str = ""
    price: str | None = None


class PolicyEngine:
    def __init__(self, rules: list[dict], default_action: str = "allow"):
        for r in rules:
            if r.get("action") not in ACTIONS:
                raise ValueError(f"rule {r.get('name')} has unknown action {r.get('action')}")
        self.rules = rules
        self.default_action = default_action
        self._hits: dict[str, deque] = defaultdict(deque)

    @classmethod
    def from_yaml(cls, path: str) -> "PolicyEngine":
        with open(path) as f:
            cfg = yaml.safe_load(f)
        return cls(cfg.get("rules", []), cfg.get("default", "allow"))

    def _matches(self, rule: dict, res: VerificationResult, method: str, path: str, user_agent: str) -> bool:
        m = rule.get("match", {})
        if "outcome" in m and res.outcome.value not in _as_list(m["outcome"]):
            return False
        if "tag" in m and res.tag not in _as_list(m["tag"]):
            return False
        if "operator" in m and not any(_operator_matches(o, res.operator) for o in _as_list(m["operator"])):
            return False
        if "path" in m and not any(fnmatch.fnmatch(path, p) for p in _as_list(m["path"])):
            return False
        if "user_agent_contains" in m and not any(
                u.lower() in user_agent.lower() for u in _as_list(m["user_agent_contains"])):
            return False
        if "method" in m and method.upper() not in [x.upper() for x in _as_list(m["method"])]:
            return False
        return True

    def decide(self, res: VerificationResult, method: str, path: str, user_agent: str = "",
               client_key: str | None = None) -> Decision:
        """client_key: opaque per-client value from the middleware (hashed IP prefix). Used to
        bucket rate limits for traffic whose identity is not proven."""
        for rule in self.rules:
            if not self._matches(rule, res, method, path, user_agent):
                continue
            name, action = rule.get("name", "unnamed"), rule["action"]
            if action == "allow":
                return Decision("allow", name, 200)
            if action == "block":
                return Decision("block", name, 403, rule.get("message", "blocked by policy"))
            if action == "charge":
                return Decision("charge", name, 402, "payment required", price=str(rule.get("price", "0.01 USD")))
            if action == "rate_limit":
                limit, window = int(rule.get("limit", 60)), int(rule.get("window_s", 60))
                bucket = f"{name}:{_bucket_id(res, client_key)}"
                now, hits = time.time(), self._hits[bucket]
                while hits and hits[0] < now - window:
                    hits.popleft()
                if len(hits) >= limit:
                    return Decision("rate_limit", name, 429, f"over {limit} requests per {window}s for {bucket}")
                hits.append(now)
                return Decision("allow", name, 200, "within rate limit")
        return Decision(self.default_action, "default", 200 if self.default_action == "allow" else 403)


def _origin(url: str) -> tuple[str, str, int | None] | None:
    try:
        p = urlsplit(url)
        return (p.scheme.lower(), (p.hostname or "").lower(), p.port) if p.hostname else None
    except ValueError:
        return None


def _operator_matches(rule_value: str, operator: str | None) -> bool:
    """Exact matching only. The old substring match let a directory at
    https://acme.com.attacker.io/... satisfy a rule for "acme.com" (review finding E1).
    Accepted rule values: "static:<label>" (exact), a full directory URL (exact), an origin
    "https://acme.com" (same scheme, host and port), or a bare host "acme.com" (same host)."""
    if not operator:
        return False
    if rule_value.startswith("static:") or operator.startswith("static:"):
        return rule_value == operator
    if rule_value == operator:
        return True
    op = _origin(operator)
    if op is None:
        return False
    if "://" in rule_value:
        rv = _origin(rule_value)
        return rv is not None and rv == op
    return rule_value.lower().rstrip(".") == op[1]


def _bucket_id(res: VerificationResult, client_key: str | None) -> str:
    """Only a verified operator is a trustworthy identity. For unsigned, invalid and unverified
    traffic the keyid and Signature-Agent are attacker-chosen (D1: rotating them bypassed the
    limit), so bucket by the client key the middleware derived from the connection."""
    if res.outcome == Outcome.VERIFIED and res.operator:
        return f"op:{res.operator}"
    return f"client:{client_key or 'anonymous'}"


def _as_list(v):
    return v if isinstance(v, list) else [v]
