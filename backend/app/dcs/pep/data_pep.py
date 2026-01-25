from dataclasses import dataclass
from typing import Any
from app.dcs.kms.vault_transit import VaultClient
from app.dcs.pdp.types import Decision
from app.dcs.pep.mode import dcs_enabled

vault = VaultClient()


def mask_string(s: str) -> str:
    s = "" if s is None else str(s)
    if len(s) <= 2:
        return "*" * len(s)
    return s[0] + "***"


def mask_uuid(s: str) -> str:
    s = "" if s is None else str(s)
    if len(s) <= 8:
        return "****"
    return s[:4] + "…"


def mask_age(age: Any) -> str:
    try:
        a = int(age)
    except Exception:
        return "***"
    if a < 18:
        return "-18"
    return "+18"


@dataclass
class ApplyResult:
    payload: dict[str, Any]
    decrypted: list[str]
    masked: list[str]
    denied: list[str]


def apply_decision(
    *,
    decision: Decision,
    ciphertext_row: dict[str, Any],
    field_to_ciphertext: dict[str, str],
) -> ApplyResult:
    out: dict[str, Any] = {}
    decrypted: list[str] = []
    masked: list[str] = []
    denied: list[str] = []

    if not decision.allow:
        return ApplyResult(
            payload={},
            decrypted=[],
            masked=[],
            denied=list(decision.field_actions.keys()),
        )

    if not dcs_enabled():
        out: dict[str, Any] = {}
        ct_values = set(field_to_ciphertext.values())
        for key, val in ciphertext_row.items():
            if key not in ct_values:
                out[key] = val
        for field, ct_key in field_to_ciphertext.items():
            out[field] = ciphertext_row.get(ct_key)
        return ApplyResult(payload=out, decrypted=[], masked=[], denied=[])

    for field, action in decision.field_actions.items():
        if action == "deny":
            denied.append(field)
            continue

        if field not in field_to_ciphertext:
            val = ciphertext_row.get(field)
            if action == "allow":
                out[field] = val
            elif action == "mask_after_decrypt":
                if val is None:
                    out[field] = None
                elif isinstance(val, int):
                    out[field] = mask_age(val)
                else:
                    out[field] = mask_string(val)
                masked.append(field)
            else:
                out[field] = val
            continue

        ct_key = field_to_ciphertext[field]
        ct = ciphertext_row.get(ct_key)
        if ct is None:
            out[field] = None
            continue

        plain = vault.decrypt(ct)

        if action == "decrypt":
            if field in ("age", "time_elapsed"):
                try:
                    out[field] = int(plain)
                except Exception:
                    out[field] = plain
            else:
                out[field] = plain
            decrypted.append(field)
        elif action == "mask_after_decrypt":
            if field == "age":
                out[field] = mask_age(plain)
            elif field.endswith("_id"):
                out[field] = mask_uuid(plain)
            else:
                out[field] = mask_string(plain)
            masked.append(field)
        else:
            denied.append(field)
            out[field] = None

    return ApplyResult(payload=out, decrypted=decrypted, masked=masked, denied=denied)
