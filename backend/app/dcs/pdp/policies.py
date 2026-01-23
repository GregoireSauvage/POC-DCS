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

    def action_for_classification(classification: str) -> str:
        if s.role == "admin":
            return "decrypt" if classification in ("PII", "SENSITIVE") else "allow"

        if s.role == "agent":
            if classification in ("PUBLIC", "INTERNAL"):
                return "allow"
            if classification == "SENSITIVE":
                return "decrypt"
            if classification == "PII":
                return "mask_after_decrypt"
            return "deny"

        if s.role == "developer":
            if classification == "PUBLIC":
                return "allow"
            if classification in ("INTERNAL", "PII", "SENSITIVE"):
                return "mask_after_decrypt"
            return "deny"

        return "deny"

    # Coarse authorization per action
    if action in ("film.read", "hall.read", "spectator.read", "search.spectator"):
        allow = True
        reason = "read_allowed"
    elif action in ("film.create", "hall.create", "spectator.create", "film.update_time"):
        allow = s.role in ("agent", "admin")
        reason = "write_allowed" if allow else "write_forbidden"
    elif action == "bootstrap":
        allow = s.role == "admin"
        reason = "bootstrap_allowed" if allow else "bootstrap_forbidden"
    elif action == "audit.read":
        allow = s.role == "admin"
        reason = "audit_admin_only" if not allow else "audit_allowed"
    else:
        return False, {}, "unknown_action"

    if not allow:
        return False, {}, reason

    for field_name, meta in r.fields.items():
        cls = meta.get("classification", "INTERNAL")
        field_actions[field_name] = action_for_classification(cls)

    # Hardening: agent should never see spectator PII in clear even if misclassified
    if r.type == "spectator" and s.role == "agent":
        for fn in ("name", "external_id"):
            if fn in field_actions:
                field_actions[fn] = "mask_after_decrypt"

    return True, field_actions, reason
