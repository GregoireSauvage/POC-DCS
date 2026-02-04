# DCS Policy Examples

This directory contains example policies for the Data-Centric Security implementation.

## Policy Structure

Policies are evaluated by the PDP (Policy Decision Point) based on:

1. **Subject Attributes**: User role, tenant, device trust level
2. **Resource Attributes**: Classification level, labels, ownership
3. **Context**: Environment, channel, purpose, request metadata

## Field Classification Levels

| Level | Description | Example Fields |
|-------|-------------|----------------|
| PUBLIC | No restrictions | film.title, hall.name |
| INTERNAL | Internal use only | spectator.age |
| SENSITIVE | Requires elevated access | financial data |
| PII | Personally Identifiable Information | name, email, phone |

## Role-Based Access Matrix

| Role | PUBLIC | INTERNAL | SENSITIVE | PII |
|------|--------|----------|-----------|-----|
| developer | allow | mask | mask | mask |
| agent | allow | allow | decrypt | mask_after_decrypt |
| admin | allow | allow | decrypt | decrypt |

## Example Policy Decision

```json
{
  "allow": true,
  "field_actions": {
    "name": "mask_after_decrypt",
    "age": "allow",
    "external_id": "deny"
  },
  "reason": "Role 'agent' grants access with PII masking"
}
```

## Adding New Policies

1. Define field classifications in `field_classification` table
2. Update PDP rules in `backend/app/dcs/pdp/engine.py`
3. Add tests for new policy combinations
4. Document in this directory
