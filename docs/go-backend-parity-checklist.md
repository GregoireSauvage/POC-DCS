# Go backend migration - parity checklist (Python -> Go)

This checklist is the baseline gate before routing production traffic from Python to Go.

## 1) Contract parity (HTTP)

- [ ] `POST /auth/login` returns same fields (`access_token`, `role`, `tenant_id`, `user_id`, `username`).
- [ ] `GET /films` returns same schema and DCS-shaped values by role.
- [ ] `POST /films` returns response shaped under `film.read` policy.
- [ ] `PATCH /films/{film_id}/time` enforces write policy then read policy.
- [ ] `GET /halls`, `POST /halls` preserve masking/deny behavior.
- [ ] `POST /spectators`, `GET /spectators/search` preserve decrypt/mask + lookup behavior.
- [ ] `GET /audit` admin-only behavior unchanged.
- [ ] `GET /perf`, `GET /perf/summary` admin-only behavior unchanged.
- [ ] `GET/PATCH /admin/settings` preserve runtime DCS/cache toggles.

## 2) DCS behavior parity

- [ ] `DCS_MODE=on`: same `allow/decrypt/mask/deny` decisions for `developer`, `agent`, `admin`.
- [ ] `DCS_MODE=off`: same coarse authorization and ciphertext passthrough behavior.
- [ ] PIP payload equivalence for `film.read` and `film.update_time`.
- [ ] PDP decision hash equivalence for same policy input.
- [ ] PEP output equivalence (including `mask_age`, `mask_uuid`, string masking semantics).
- [ ] Spectator hardening rule for `agent` (`name`, `external_id`) still enforced.

## 3) Data and crypto parity

- [ ] Same DB schema and constraints used by both services.
- [ ] Vault Transit encrypt/decrypt payload formats unchanged.
- [ ] `external_id_lookup` generation matches Python (`normalize + HMAC SHA-256`).
- [ ] No plaintext sensitive fields are persisted in DB.

## 4) Cache/runtime parity

- [ ] Runtime overrides for `dcs_mode` and `cache_level` behave the same.
- [ ] Cache semantics preserved:
  - [ ] L1 classification + pepper
  - [ ] L2 PDP for cacheable actions
  - [ ] L3 KMS decrypt
- [ ] Cache clear on runtime settings change works.

## 5) Audit and perf parity

- [ ] `audit_logs` rows are written with same `action`, `outcome`, and field lists.
- [ ] `perf_logs` rows include same dimensions (`action`, `resource_type`, `dcs_enabled`, `cache_level`).
- [ ] Timings are present for `pip_ms`, `pdp_ms`, `kms_ms`, `db_ms`, `total_ms`.
- [ ] `x-request-id` propagation and persistence are equivalent.

## 6) Rollout safety gates

- [ ] Shadow tests: same request replayed to Python and Go with diff report = no blocking drift.
- [ ] Canary route for Films endpoints passes parity gates.
- [ ] Canary route for Halls/Spectators passes parity gates.
- [ ] Error rate and p95 latency within agreed budget during canary.
- [ ] Rollback path to Python-only routing validated.

## 7) Done criteria for cutover

- [ ] All checklist items completed.
- [ ] CI includes Go tests, proto lint, and parity tests.
- [ ] Runbook updated for routing switch and rollback.
