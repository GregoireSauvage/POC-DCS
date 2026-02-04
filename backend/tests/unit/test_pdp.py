"""Unit tests for the Policy Decision Point (PDP) engine."""

from app.dcs.pdp.engine import evaluate
from app.dcs.pip.types import Context, PolicyInput, Resource, Subject


def mk_input(role: str) -> PolicyInput:
    """Create a PolicyInput for testing with the given role."""
    return PolicyInput(
        subject=Subject(user_id="u1", tenant_id="t1", role=role, username=role),
        action="spectator.read",
        resource=Resource(
            type="spectator",
            id="s1",
            owner_id="u2",
            tenant_id="t1",
            labels=[],
            fields={
                "name": {"classification": "PII"},
                "age": {"classification": "SENSITIVE"},
                "external_id": {"classification": "PII"},
            },
        ),
        context=Context(
            env="dev",
            channel="web",
            purpose="cinema_ops",
            client_ip=None,
            device_trust=0.8,
            request_id="r",
        ),
    )


def test_admin_decrypts():
    """Admin role should decrypt all fields."""
    decision = evaluate(mk_input("admin"))
    assert decision.allow is True
    assert decision.field_actions["name"] == "decrypt"


def test_agent_masks_pii():
    """Agent role should mask PII fields after decryption."""
    decision = evaluate(mk_input("agent"))
    assert decision.allow is True
    assert decision.field_actions["name"] == "mask_after_decrypt"


def test_developer_masks_sensitive():
    """Developer role should see masked values for sensitive fields."""
    decision = evaluate(mk_input("developer"))
    assert decision.allow is True
    assert decision.field_actions["age"] == "mask"
