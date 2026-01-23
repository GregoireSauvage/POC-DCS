import hashlib
import json
from app.dcs.pip.types import PolicyInput
from app.dcs.pdp.types import Decision
from app.dcs.pdp.policies import decide

def evaluate(policy_input: PolicyInput) -> Decision:
    allow, field_actions, reason = decide(policy_input)
    return Decision(allow=allow, field_actions=field_actions, reason=reason)

def decision_hash(decision: Decision) -> str:
    payload = {"allow": decision.allow, "field_actions": decision.field_actions, "reason": decision.reason}
    raw = json.dumps(payload, sort_keys=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()
