import hashlib
import json

from app.cache.cache import cache_level_enabled, pdp_cache
from app.core.config import settings
from app.dcs.pdp.policies import decide
from app.dcs.pdp.types import Decision
from app.dcs.pep.mode import allow_without_dcs, dcs_enabled
from app.dcs.pip.types import PolicyInput
from app.observability.perf import perf_span


def evaluate(policy_input: PolicyInput) -> Decision:
    with perf_span("pdp_ms"):
        cacheable = cache_level_enabled(2) and policy_input.action in (
            "film.read",
            "film.update_time",
        )
        cache_key = None
        if cacheable:
            cache_key = _decision_cache_key(policy_input)
            cached = pdp_cache.get(cache_key)
            if cached is not None:
                return cached  # type: ignore[return-value]

        if not dcs_enabled():
            allow = allow_without_dcs(policy_input.action, policy_input.subject.role)
            decision = Decision(allow=allow, field_actions={}, reason="dcs_off")
        else:
            allow, field_actions, reason = decide(policy_input)
            decision = Decision(allow=allow, field_actions=field_actions, reason=reason)

        if cacheable and cache_key is not None:
            pdp_cache.set(cache_key, decision, settings.CACHE_TTL_PDP_SEC)
        return decision


def _decision_cache_key(policy_input: PolicyInput) -> tuple:
    s = policy_input.subject
    r = policy_input.resource
    fields_sig = tuple(sorted((k, v.get("classification", "")) for k, v in r.fields.items()))
    labels_sig = tuple(sorted(r.labels or []))
    return (
        "pdp",
        dcs_enabled(),
        policy_input.action,
        s.tenant_id,
        s.role,
        s.user_id,
        r.type,
        r.owner_id,
        labels_sig,
        fields_sig,
    )


def decision_hash(decision: Decision) -> str:
    payload = {
        "allow": decision.allow,
        "field_actions": decision.field_actions,
        "reason": decision.reason,
    }
    raw = json.dumps(payload, sort_keys=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()
