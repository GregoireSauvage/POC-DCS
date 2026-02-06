# Go backend migration - parity checklist (Python -> Go)

**Last updated**: 2026-02-06
**Status**: 🔴 **28% Complete (12/34 items)** - Foundation phase

This checklist is the baseline gate before routing production traffic from Python to Go.

## Progress Summary

| Category | Status | Complete | Notes |
|----------|--------|----------|-------|
| 1. HTTP Contract | 🔴 30% | 3/10 | Films partial, auth/halls/spectators missing |
| 2. DCS Behavior | 🟡 67% | 4/6 | Core logic ✅, hardening/hash fixes needed |
| 3. Data & Crypto | 🔴 0% | 0/4 | **BLOCKER**: No real DB/Vault |
| 4. Cache/Runtime | ✅ 100% | 4/4 | Fully implemented |
| 5. Audit & Perf | 🔴 33% | 1/3 | Tracking exists, no persistence |
| 6. Rollout Safety | ❌ 0% | 0/4 | Not started (expected) |
| 7. Done Criteria | ❌ 0% | 0/3 | Not started (expected) |

**Legend**: ✅ Complete | 🟡 Partial | ⚠️ Minor issues | ❌ Not implemented | 🔴 Blocker

## 1) Contract parity (HTTP)

- [ ] ❌ `POST /auth/login` returns same fields (`access_token`, `role`, `tenant_id`, `user_id`, `username`).
  - **Status**: Not implemented
  - **Gap**: No JWT issuer, no user auth, headers currently mocked (X-Role, X-User-ID)
  - **Needs**: golang-jwt/jwt library, User repository, bcrypt password validation

- [ ] ⚠️ `GET /films` returns same schema and DCS-shaped values by role.
  - **Status**: Partial - logic complete, infrastructure missing
  - **Go**: PIP→PDP→PEP workflow implemented, perf tracking works
  - **Gap**: No audit logging, no perf log persistence, KMS is mock base64, in-memory DB
  - **Location**: `internal/service/film_workflow.go`, `internal/transport/http/server.go`

- [ ] ❌ `POST /films` returns response shaped under `film.read` policy.
  - **Status**: Not implemented
  - **Gap**: No Create endpoint, proto defines CreateFilm RPC but no service
  - **Needs**: FilmService.Create(), HTTP POST handler, write policy enforcement

- [ ] ⚠️ `PATCH /films/{film_id}/time` enforces write policy then read policy.
  - **Status**: Logic complete, infrastructure missing
  - **Go**: FilmService.UpdateTime() implemented with auth + policy enforcement
  - **Gap**: Same as GET (no audit log, mock KMS, in-memory DB)

- [ ] ❌ `GET /halls`, `POST /halls` preserve masking/deny behavior.
  - **Status**: Not implemented
  - **Gap**: No HallService, no endpoints, HallRepository interface defined but empty
  - **Needs**: HallService.List/Create, HTTP handlers, DCS workflow integration

- [ ] ❌ `POST /spectators`, `GET /spectators/search` preserve decrypt/mask + lookup behavior.
  - **Status**: Not implemented
  - **Gap**: No SpectatorService, no HMAC lookup implementation, no endpoints
  - **Needs**: crypto/lookup.go (HMAC-SHA256), SpectatorService, external_id_lookup logic

- [ ] ❌ `GET /audit` admin-only behavior unchanged.
  - **Status**: Not implemented
  - **Gap**: No AuditLog model, no audit_logs table, no service
  - **Needs**: AuditLog domain + repository, AuditService.List(), admin-only middleware

- [ ] ❌ `GET /perf`, `GET /perf/summary` admin-only behavior unchanged.
  - **Status**: Tracking exists, no persistence/endpoints
  - **Go**: observability/perf tracks metrics in-memory
  - **Gap**: No PerfLog model, no perf_logs table, no query endpoints
  - **Needs**: PerfLog domain + repository, PerfService.List/Summary()

- [ ] ✅ `GET/PATCH /admin/settings` preserve runtime DCS/cache toggles.
  - **Status**: ✅ Complete
  - **Go**: Fully implemented with cache clear on change
  - **Location**: `internal/dcs/runtime/settings.go`, HTTP handlers working

## 2) DCS behavior parity

- [x] ✅ `DCS_MODE=on`: same `allow/decrypt/mask/deny` decisions for `developer`, `agent`, `admin`.
  - **Status**: ✅ Complete - identical role×classification matrix
  - **Go**: Developer masks SENSITIVE+PII, Agent decrypts SENSITIVE/masks PII, Admin decrypts all
  - **Location**: `internal/dcs/pdp/engine.go` fieldActionForRole()

- [x] ✅ `DCS_MODE=off`: same coarse authorization and ciphertext passthrough behavior.
  - **Status**: ✅ Complete
  - **Go**: defaultDecisionNoDCS() implements same read/write/audit role checks
  - **Location**: `internal/dcs/pdp/engine.go`

- [ ] ⚠️ PIP payload equivalence for `film.read` and `film.update_time`.
  - **Status**: Structure identical, minor fields missing
  - **Go**: PolicyInput has all main fields (Subject, Action, Resource, Context)
  - **Gap**: Context.DeviceTrust not populated, Context.ClientIP not extracted, Action.Scopes not propagated
  - **Fix**: Extract X-Real-IP in PIP provider, add device trust field, propagate JWT scopes

- [ ] ⚠️ PDP decision hash equivalence for same policy input.
  - **Status**: Algorithm implemented but non-deterministic
  - **Go**: Uses SHA256(allow + field_actions + reason) like Python
  - **Gap**: 🔴 **CRITICAL BUG** - Go map iteration is non-deterministic → hash varies for same input
  - **Fix**: Sort field_actions keys before hashing (required for audit compliance)
  - **Location**: `internal/dcs/pdp/engine.go` hashDecision()

- [ ] ⚠️ PEP output equivalence (including `mask_age`, `mask_uuid`, string masking semantics).
  - **Status**: Partial - string masking ✅, uuid/age missing
  - **Go**: maskValue() implements first_char + "***" correctly
  - **Gap**: mask_uuid (should use "…" suffix), mask_age (should categorize as "-18"/"+18")
  - **Fix**: Add type-aware masking functions
  - **Location**: `internal/dcs/pep/film.go`

- [ ] ❌ Spectator hardening rule for `agent` (`name`, `external_id`) still enforced.
  - **Status**: Not implemented
  - **Python**: Agents always mask spectator name+external_id regardless of classification
  - **Gap**: 🔴 **SECURITY BLOCKER** - Go PDP follows standard matrix only, no hardening override
  - **Fix**: Add spectator_agent_hardening_fields config, enforce in PDP.decide()
  - **Location**: Need to update `internal/dcs/pdp/engine.go`

## 3) Data and crypto parity

- [ ] ❌ Same DB schema and constraints used by both services.
  - **Status**: 🔴 **BLOCKER** - No real database
  - **Python**: PostgreSQL with composite PKs (tenant_id, id), FK constraints, JSONB labels, BYTEA lookups
  - **Go**: In-memory repository only (`internal/repository/memory/film_repo.go`)
  - **Needs**:
    - PostgreSQL driver (lib/pq or pgx)
    - Migration tool (goose, sqlc, or GORM automigrate)
    - Share same schema as Python (or sync migrations)
  - **Priority**: P0 - blocks all persistence

- [ ] ❌ Vault Transit encrypt/decrypt payload formats unchanged.
  - **Status**: 🔴 **SECURITY BLOCKER** - Mock KMS only
  - **Python**: Real Vault Transit API (POST /v1/transit/encrypt/dcs-key)
  - **Go**: LocalKMS = "vault:v1:" + base64(plaintext) - **NOT REAL ENCRYPTION**
  - **Gap**: No Vault client, no auth, no error handling (sealed vault, timeouts)
  - **Needs**:
    - github.com/hashicorp/vault/api library
    - VaultClient implementation replacing LocalKMS
    - Batch encrypt/decrypt for performance
  - **Location**: Replace `internal/dcs/kms/local.go`
  - **Priority**: P0 - security critical

- [ ] ❌ `external_id_lookup` generation matches Python (`normalize + HMAC SHA-256`).
  - **Status**: Not implemented
  - **Python**: normalize (strip+uppercase) + HMAC-SHA256(pepper, value) → BYTEA
  - **Go**: Domain.Spectator.ExternalIDLookup field exists but never populated
  - **Needs**:
    - `internal/dcs/crypto/lookup.go`: NormalizeExternalID(), HMACLookup()
    - Fetch pepper from Vault KV (cache level 1)
    - Use crypto/hmac standard library
  - **Priority**: P1 - required for spectator search

- [ ] ⚠️ No plaintext sensitive fields are persisted in DB.
  - **Status**: Models correct, DB not verifiable
  - **Go**: Domain models use *CT fields correctly (time_elapsed_ct, name_ct, age_ct, external_id_ct)
  - **Gap**: No DB to verify, risk of accidental plaintext if migrations incorrect
  - **Needs**: DB schema validation tests, migration review checklist

## 4) Cache/runtime parity

- [x] ✅ Runtime overrides for `dcs_mode` and `cache_level` behave the same.
  - **Status**: ✅ Complete - identical behavior
  - **Go**: Thread-safe RWMutex, get/set with overrides
  - **Location**: `internal/dcs/runtime/settings.go`

- [x] ✅ Cache semantics preserved:
  - [x] ✅ L1 classification + pepper
  - [x] ✅ L2 PDP for cacheable actions
  - [x] ✅ L3 KMS decrypt (implemented but unused due to mock KMS)
  - **Status**: ✅ Complete - same 4-level cache strategy
  - **Go**: CacheManager with TTL caches, configurable max entries per cache
  - **Note**: Go allows per-cache max_entries (Python has global max), slightly more flexible
  - **Location**: `internal/dcs/cache/manager.go`, `internal/dcs/cache/ttl.go`

- [x] ✅ Cache clear on runtime settings change works.
  - **Status**: ✅ Complete
  - **Go**: SetDCSMode/SetCacheLevel automatically call ClearAll()
  - **Location**: `internal/dcs/runtime/settings.go`

## 5) Audit and perf parity

- [ ] ❌ `audit_logs` rows are written with same `action`, `outcome`, and field lists.
  - **Status**: 🔴 **COMPLIANCE BLOCKER** - No audit persistence
  - **Python**: Writes to audit_logs table after every PEP enforcement (request_id, decision_hash, fields_decrypted/masked/denied)
  - **Go**: No AuditLog model, no repository, no service
  - **Needs**:
    - Create AuditLog domain model matching Python schema
    - AuditLogRepository.Create()
    - AuditService.WriteAudit() called after PEP.Apply()
    - Integrate in FilmService workflow
  - **Priority**: P0 - compliance requirement

- [ ] ❌ `perf_logs` rows include same dimensions (`action`, `resource_type`, `dcs_enabled`, `cache_level`).
  - **Status**: Tracking exists, no persistence
  - **Python**: Writes to perf_logs table at end of request
  - **Go**: PerfContext collects metrics in-memory, not persisted
  - **Gap**: No PerfLog model, no repository, no auto-logging
  - **Needs**:
    - Create PerfLog domain model
    - PerfLogRepository.Create()
    - HTTP middleware to auto-log at request end
  - **Location**: Use existing `internal/observability/perf/context.go`
  - **Priority**: P1 - observability

- [x] ⚠️ Timings are present for `pip_ms`, `pdp_ms`, `kms_ms`, `db_ms`, `total_ms`.
  - **Status**: Partial - tracking works, not persisted
  - **Go**: PerfContext.StartSpan/EndSpan track all component timings
  - **Gap**: Only exposed in HTTP headers (x-perf-*), not in DB
  - **Note**: Will be ✅ once perf_logs persistence implemented

- [x] ✅ `x-request-id` propagation and persistence are equivalent.
  - **Status**: ✅ Complete
  - **Go**: requestIDMiddleware generates or extracts X-Request-ID, stores in context, propagates through spans
  - **Location**: `internal/transport/http/server.go`

## 6) Rollout safety gates

**Status**: ❌ Not started (expected at this early phase)

- [ ] ❌ Shadow tests: same request replayed to Python and Go with diff report = no blocking drift.
  - **Needs**: Test infrastructure to replay production requests, diff comparison tool
  - **Priority**: P2 - after functional parity

- [ ] ❌ Canary route for Films endpoints passes parity gates.
  - **Needs**: Nginx config for % traffic split, monitoring dashboards
  - **Priority**: P2 - after Films fully implemented

- [ ] ❌ Canary route for Halls/Spectators passes parity gates.
  - **Needs**: Same as above for other endpoints
  - **Priority**: P2 - after all endpoints implemented

- [ ] ❌ Error rate and p95 latency within agreed budget during canary.
  - **Needs**: Prometheus + Grafana, SLO definitions, alerting
  - **Priority**: P2 - production readiness

- [ ] ❌ Rollback path to Python-only routing validated.
  - **Needs**: Nginx rollback procedure, validation checklist
  - **Priority**: P2 - before first canary

## 7) Done criteria for cutover

**Status**: ❌ Not started

- [ ] ❌ All checklist items completed.
  - **Current**: 12/34 items (28%)
  - **Target**: 100%

- [ ] ⚠️ CI includes Go tests, proto lint, and parity tests.
  - **Status**: Partial - local Makefile exists
  - **Has**: `make test`, `make lint`, `make proto-lint`
  - **Missing**: GitHub Actions/GitLab CI pipeline, automated parity tests
  - **Priority**: P1 - quality gate

- [ ] ❌ Runbook updated for routing switch and rollback.
  - **Status**: Minimal README (29 lines)
  - **Needs**: Deployment runbook, troubleshooting guide, rollback procedure
  - **Priority**: P2 - before production

---

## Implementation Priorities

### 🔴 P0 - Critical Blockers (Must do first)

These block all functional endpoints and security compliance:

1. **PostgreSQL Integration** 🔴
   - Impact: Blocks all persistence (films, halls, spectators, audit, perf)
   - Effort: Medium (2-3 days)
   - Approach: Use pgx driver + goose migrations, share schema with Python
   - Files: `internal/repository/postgres/`, `migrations/`

2. **Vault Transit Integration** 🔴
   - Impact: Security critical - currently NO real encryption
   - Effort: Medium (2 days)
   - Approach: Replace `internal/dcs/kms/local.go` with hashicorp/vault/api client
   - Includes: Error handling (sealed vault, timeouts), batch operations

3. **Audit Logging Persistence** 🔴
   - Impact: Compliance requirement - can't route traffic without audit trail
   - Effort: Small (1 day)
   - Approach: AuditLog model + repository, integrate in FilmService workflow
   - Files: `internal/domain/audit_log.go`, `internal/repository/audit_repository.go`

4. **JWT Authentication** 🔴
   - Impact: Security baseline - currently headers are mocked
   - Effort: Medium (2 days)
   - Approach: POST /auth/login endpoint, JWT middleware for Bearer token validation
   - Files: `internal/transport/http/auth.go`, use golang-jwt/jwt library

**Total P0 effort**: ~7-10 days

### 🟡 P1 - High Priority (Functional completeness)

Required for full API parity:

5. **Spectator Service + HMAC Lookup** (3 days)
   - crypto/lookup.go (HMAC-SHA256)
   - Agent hardening rule enforcement
   - POST /spectators, GET /spectators/search endpoints

6. **Hall Service** (2 days)
   - HallService.Create(), List()
   - GET/POST /halls endpoints

7. **Performance Logging Persistence** (1 day)
   - PerfLog model + repository
   - GET /perf, /perf/summary endpoints

8. **PDP Decision Hash Fix** (0.5 day)
   - Sort field_actions keys before hashing (critical for audit)

9. **POST /films Endpoint** (1 day)
   - FilmService.Create() implementation

**Total P1 effort**: ~7.5 days

### 🟢 P2 - Nice to Have (Quality & Future)

10. **gRPC Service Implementations** (3 days)
    - buf generate proto code
    - Implement CinemaService RPCs

11. **PEP Masking Completeness** (0.5 day)
    - mask_uuid with "…" suffix
    - mask_age categorization

12. **Parity Tests** (3 days)
    - Shadow testing infrastructure
    - Contract tests Python↔Go

13. **CI/CD Pipeline** (1 day)
    - GitHub Actions workflow
    - Automated proto lint, Go lint, tests

**Total P2 effort**: ~7.5 days

---

## Recommended Next Step

### ✅ **NEXT: PostgreSQL Integration (P0-1)**

**Why this first?**
- Unblocks all other work (services can't persist without DB)
- Films endpoint already has logic but uses in-memory repo
- Audit/perf logging needs DB
- One-time infrastructure setup

**Implementation Plan** (2-3 days):

1. **Day 1 Morning**: Setup PostgreSQL driver + connection
   - Install: `go get github.com/jackc/pgx/v5`
   - Create: `internal/repository/postgres/connection.go`
   - Config: Add DATABASE_URL to `internal/config/config.go`
   - Test connection in `cmd/server/main.go`

2. **Day 1 Afternoon**: Migration strategy
   - Option A: Use existing Python Alembic migrations (share schema)
   - Option B: Port migrations to goose (Go-native)
   - Recommendation: **Option A** - less duplication, single source of truth
   - Setup: Script to run Alembic migrations from Go service on startup

3. **Day 2**: Implement FilmRepository (PostgreSQL)
   - Create: `internal/repository/postgres/film_repository.go`
   - Implement: ListByTenant(), GetByID(), Create(), UpdateTimeCiphertext()
   - Use: pgx connection pool
   - Test: Integration test with testcontainers

4. **Day 3**: Integrate + validate
   - Wire FilmRepository into FilmService
   - Test GET/PATCH /films endpoints against real DB
   - Verify encryption: time_elapsed_ct column has ciphertext
   - Smoke test: All roles (developer, agent, admin) see correct masking

**Deliverable**: Films endpoints using real PostgreSQL ✅

**After this**: Can immediately tackle Vault (P0-2) then Audit (P0-3) to complete critical path.

---

## Timeline Estimate

**Aggressive (1 FTE)**: 4 weeks to full parity
- Week 1: P0 blockers (DB + Vault + Audit + JWT)
- Week 2: P1 services (Spectators + Halls + Perf)
- Week 3: P1 fixes + P2 gRPC
- Week 4: P2 tests + CI + canary prep

**Realistic (1 FTE)**: 6 weeks to full parity
- Weeks 1-2: P0 (with buffer for debugging)
- Weeks 3-4: P1
- Weeks 5-6: P2 + production hardening

**With 2 FTEs**: 3-4 weeks (parallel work on services after P0 infrastructure)
