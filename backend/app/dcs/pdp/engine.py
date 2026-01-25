import hashlib
import json
from app.dcs.pep.mode import allow_without_dcs, dcs_enabled
from app.dcs.pip.types import PolicyInput
from app.dcs.pdp.types import Decision
from app.dcs.pdp.policies import decide
from app.observability.perf import perf_span

def evaluate(policy_input: PolicyInput) -> Decision:
    with perf_span("pdp_ms"):
        if not dcs_enabled():
            allow = allow_without_dcs(policy_input.action, policy_input.subject.role)
            return Decision(allow=allow, field_actions={}, reason="dcs_off")
        allow, field_actions, reason = decide(policy_input)
        return Decision(allow=allow, field_actions=field_actions, reason=reason)

def decision_hash(decision: Decision) -> str:
    payload = {"allow": decision.allow, "field_actions": decision.field_actions, "reason": decision.reason}
    raw = json.dumps(payload, sort_keys=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()
