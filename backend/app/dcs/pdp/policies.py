from app.core.dcs_config import get_dcs_config
from app.dcs.pip.types import PolicyInput


def decide(policy_input: PolicyInput) -> tuple[bool, dict[str, str], str]:
    """
    Return: (allow, field_actions, reason)

    The PDP does not see PII plaintext. It decides using:
      - subject attributes (role, tenant)
      - resource metadata (owner_id, labels)
      - field classification (PUBLIC/INTERNAL/PII/SENSITIVE)
    """
    s = policy_input.subject
    r = policy_input.resource
    action = policy_input.action

    # Default deny
    allow = False
    reason = "default_deny"
    field_actions: dict[str, str] = {}

    # Tenant isolation (explicit)
    if s.tenant_id != r.tenant_id:
        return False, {}, "tenant_mismatch"

    cfg = get_dcs_config()
    pdp_cfg = cfg.get("pdp", {})
    role_matrix = pdp_cfg.get("role_classification_actions", {})
    default_classification = pdp_cfg.get("default_classification", "INTERNAL")

    def action_for_classification(classification: str) -> str:
        role_actions = role_matrix.get(s.role, {})
        return role_actions.get(classification, "deny")

    # Coarse authorization per action
    if action in pdp_cfg.get("read_actions", []):
        allow = True
        reason = "read_allowed"
    elif action in pdp_cfg.get("write_actions", []):
        allow = s.role in ("agent", "admin")
        reason = "write_allowed" if allow else "write_forbidden"
    elif action in pdp_cfg.get("bootstrap_actions", []):
        allow = s.role == "admin"
        reason = "bootstrap_allowed" if allow else "bootstrap_forbidden"
    elif action in pdp_cfg.get("audit_actions", []):
        allow = s.role == "admin"
        reason = "audit_admin_only" if not allow else "audit_allowed"
    else:
        return False, {}, "unknown_action"

    if not allow:
        return False, {}, reason

    for field_name, meta in r.fields.items():
        cls = meta.get("classification", default_classification)
        field_actions[field_name] = action_for_classification(cls)

    # Hardening: agent should never see spectator PII in clear even if misclassified
    if r.type == "spectator" and s.role == "agent":
        for fn in pdp_cfg.get("spectator_agent_hardening_fields", []):
            if fn in field_actions:
                field_actions[fn] = "mask_after_decrypt"

    return True, field_actions, reason
