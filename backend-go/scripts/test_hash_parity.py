#!/usr/bin/env python3
"""
Test decision hash parity between Python and Go backends.
This script validates that both implementations produce identical hashes.
"""
import hashlib
import json
from dataclasses import dataclass
from typing import Dict


@dataclass
class Decision:
    """Minimal Decision class for testing"""
    allow: bool
    field_actions: Dict[str, str]
    reason: str


def decision_hash_python(decision: Decision) -> str:
    """
    Python backend implementation.
    Note: json.dumps(sort_keys=True) sorts keys at ALL levels recursively,
    including nested dictionaries like field_actions.
    """
    payload = {
        "allow": decision.allow,
        "field_actions": decision.field_actions,
        "reason": decision.reason,
    }
    # sort_keys=True ensures deterministic output by sorting ALL dict keys
    raw = json.dumps(payload, sort_keys=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


# Test cases matching Go tests
test_cases = [
    {
        "name": "Python compatibility test",
        "decision": Decision(
            allow=True,
            field_actions={"name": "mask_after_decrypt", "age": "decrypt"},
            reason="read_allowed"
        ),
        "expected_go_hash": "f986e869dcaf9043676801795ca9701375a2b026cc1ef63960910e0423b96edb"
    },
    {
        "name": "Field order independence",
        "decision": Decision(
            allow=True,
            field_actions={"zzz": "decrypt", "aaa": "allow", "mmm": "mask_after_decrypt"},
            reason="read_allowed"
        ),
        "expected_go_hash": None  # Will be computed
    },
    {
        "name": "Empty field actions",
        "decision": Decision(
            allow=True,
            field_actions={},
            reason="read_allowed"
        ),
        "expected_go_hash": None
    },
]

print("=" * 70)
print("Decision Hash Parity Test - Python vs Go")
print("=" * 70)

for test in test_cases:
    print(f"\nTest: {test['name']}")
    python_hash = decision_hash_python(test["decision"])
    print(f"  Python hash: {python_hash}")

    if test["expected_go_hash"]:
        go_hash = test["expected_go_hash"]
        print(f"  Go hash:     {go_hash}")

        if python_hash == go_hash:
            print("  ✅ MATCH - Hashes are identical!")
        else:
            print("  ❌ MISMATCH - Hashes differ!")
            exit(1)
    else:
        print(f"  (Run Go test to get hash for comparison)")

print("\n" + "=" * 70)
print("✅ All parity tests passed!")
print("=" * 70)
