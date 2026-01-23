from app.dcs.pdp.engine import evaluate
from app.dcs.pip.types import PolicyInput, Subject, Context, Resource

def mk_input(role: str):
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
        context=Context(env="dev", channel="web", purpose="cinema_ops", client_ip=None, device_trust=0.8, request_id="r"),
    )

def test_admin_decrypts():
    d = evaluate(mk_input("admin"))
    assert d.allow is True
    assert d.field_actions["name"] == "decrypt"

def test_agent_masks_pii():
    d = evaluate(mk_input("agent"))
    assert d.allow is True
    assert d.field_actions["name"] == "mask_after_decrypt"
