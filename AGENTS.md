
## Project Overview

Cinema DCS PoC demonstrating **Data-Centric Security (DCS)** with **Zero Trust** principles. The system enforces field-level access control (allow/decrypt/mask/deny) using ABAC, with encryption via HashiCorp Vault and comprehensive audit logging.

**Domain**: Cinema projection tracking with Films, Halls, and Spectators.

**User roles**:
- `developer`: sees public data, sensitive fields masked
- `agent`: sees SENSITIVE decrypted, PII masked
- `admin`: full access including audit logs

## Development Commands

```bash
# Start all services (Docker required)
docker-compose up -d

# Access points:
# - Application: http://localhost:8080
# - API docs: http://localhost:8080/docs
# - Direct backend (dev): http://localhost:8000

# Frontend development (in /frontend)
npm run dev          # Vite dev server on :5173
npm run build        # TypeScript check + production build
npm run lint         # ESLint check
npm run lint --fix   # Auto-fix linting issues
npm test             # Run tests with Vitest
npm run coverage     # Generate coverage report

# Backend development (in /backend)
uv sync              # Install/sync Python dependencies
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
ruff check app/      # Lint Python code
ruff check app/ --fix  # Auto-fix linting issues
pytest               # Run all tests
pytest tests/unit/   # Run unit tests only
pytest --cov=app     # Run with coverage

# Database migrations (in /backend)
alembic upgrade head
alembic revision --autogenerate -m "description"
alembic downgrade -1  # Rollback one migration
```

## Architecture

```
Browser → Nginx (PEP entry) → FastAPI Backend → PostgreSQL
                                    ↓
                              Vault (KMS)
```

**Backend structure** (`/backend/app/`):
- `api/routers/` - HTTP endpoints: auth, films, halls, spectators, audit, perf, admin
- `dcs/` - Data-Centric Security core:
  - `pep/` - Policy Enforcement Point (applies decisions to data)
  - `pdp/` - Policy Decision Point (evaluates authorization)
  - `pip/` - Policy Information Point (gathers attributes)
  - `kms/` - Vault Transit integration for encrypt/decrypt
  - `crypto/` - HMAC lookup for searchable encrypted fields
- `db/` - SQLAlchemy models and session
- `schemas/` - Pydantic DTOs
- `services/` - Business logic
- `observability/` - Performance tracking middleware

**Frontend structure** (`/frontend/src/`):
- `pages/` - Route components (Films, Halls, Spectators, Audit)
- `components/` - Reusable UI components
- `api/` - HTTP client functions with JWT handling
- `state/auth.tsx` - Authentication context with localStorage persistence
- `types/` - TypeScript type definitions

## Code Conventions

### Python Backend
- **Style**: Follow PEP 8, enforced by `ruff`
- **Type hints**: Required for all function signatures
- **Docstrings**: Use Google style for public APIs
- **Error handling**: Raise specific exceptions (e.g., `HTTPException` with detail)
- **Naming**:
  - Classes: `PascalCase` (e.g., `PolicyDecisionPoint`)
  - Functions/variables: `snake_case`
  - Constants: `UPPER_SNAKE_CASE`
  - Private methods: prefix with `_`
- **Async**: Use `async/await` for all I/O operations (DB, Vault, HTTP)
- **Dependencies**: Inject via FastAPI dependency injection, not globals

**Import order**:
```python
# Standard library
import os
from datetime import datetime
from typing import Optional, List

# Third-party
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

# Local - absolute imports from app root
from app.db.session import get_db
from app.core.auth import get_current_user
from app.dcs.pep import PolicyEnforcementPoint
from app.schemas.film import FilmResponse
```

### TypeScript Frontend
- **Style**: 2-space indentation, single quotes
- **Components**: Functional components with TypeScript
- **Props**: Always define interface/type for component props
- **State**: Use Context API for auth, local state for UI
- **API calls**: Centralize in `/api` folder with proper error handling
- **Naming**:
  - Components: `PascalCase` (e.g., `FilmCard.tsx`)
  - Hooks: `use` prefix (e.g., `useAuth`)
  - Files: Match component name

**Import order** (with path aliases `@/`):
```typescript
// React
import { useState, useEffect } from 'react';

// Third-party
import { useNavigate } from 'react-router-dom';

// Local
import { useAuth } from '@/state/auth';
import { getFilms } from '@/api/films';
import { FilmCard } from '@/components/FilmCard';
import type { Film } from '@/types';
```

### SQL/Database
- **Migrations**: Always use Alembic, never manual schema changes
- **Naming**: `snake_case` for tables and columns
- **Indexes**: Add for frequently queried fields (e.g., `external_id_lookup`)
- **Constraints**: Define FK relationships explicitly

## Design Patterns & Best Practices

### Security Patterns
✅ **DO**: Always validate JWT tokens before accessing resources
✅ **DO**: Log all field-level access decisions for audit
✅ **DO**: Use parameterized queries (SQLAlchemy prevents SQL injection)
✅ **DO**: Encrypt PII at rest using Vault Transit
❌ **DON'T**: Store plaintext sensitive data in database
❌ **DON'T**: Cache decrypted data without TTL
❌ **DON'T**: Expose raw policy decisions in API responses

### DCS Implementation
- **PIP first**: Always gather all attributes before PDP evaluation
- **PDP caching**: Use `CACHE_LEVEL=2` in production for performance
- **PEP enforcement**: Apply decisions in middleware, not in business logic
- **Audit**: Log decisions AFTER PEP enforcement, include correlation_id

### FastAPI Patterns
✅ **DO**: Use dependency injection for services
```python
# Good
@router.get("/films")
async def get_films(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    pep: PolicyEnforcementPoint = Depends(get_pep)
):
    ...
```

❌ **DON'T**: Import services globally
```python
# Bad - tight coupling
from app.services.film_service import film_service
```

### React Patterns
✅ **DO**: Use custom hooks for reusable logic
```typescript
// Good - in hooks/useFilms.ts
export const useFilms = () => {
  const { token } = useAuth();
  const [films, setFilms] = useState([]);
  // ... fetch logic
  return { films, loading, error };
};
```

❌ **DON'T**: Fetch in components directly
```typescript
// Bad - not reusable
useEffect(() => {
  fetch('/api/films').then(...)
}, []);
```

## Error Handling

### Backend
- **Validation errors**: Return `422` with Pydantic validation details
- **Auth errors**: Return `401` (unauthorized) or `403` (forbidden)
- **Not found**: Return `404` with resource type in message
- **DCS errors**: 
  - Vault unreachable → Return `503 Service Unavailable`
  - Policy evaluation fails → Log error, default to DENY
  - Decryption fails → Treat as masked field, log warning

### Frontend
- **API errors**: Show toast notification with user-friendly message
- **Network failures**: Retry with exponential backoff (3 attempts)
- **401**: Clear token, redirect to login
- **403**: Show "Access Denied" message, don't retry

### Common Edge Cases
- **Empty results**: Display empty state with helpful message
- **Partial data**: If some fields denied, show available fields only
- **Concurrent updates**: Use optimistic locking (version field)
- **Vault rotation**: Handle key rotation gracefully (decrypt with old key if needed)

## Testing Strategy

### Backend Tests (pytest)
```bash
pytest                          # All tests
pytest tests/unit/             # Unit tests only
pytest tests/integration/      # Integration tests
pytest --cov=app --cov-report=html  # Coverage report
```

**Coverage requirements**: >80% for core DCS modules (PDP, PEP, KMS)

**Test structure**:
- `tests/unit/` - Pure functions, no external deps (mock DB, Vault)
- `tests/integration/` - Real DB (testcontainers), mock Vault
- `tests/e2e/` - Full stack with Docker Compose

**Key test cases**:
- PDP: All combinations of (role, classification level) → correct decision
- PEP: Verify encryption/decryption/masking applied correctly
- Audit: All decisions logged with correct correlation_id

### Frontend Tests (Vitest + React Testing Library)
```bash
npm test              # Run tests
npm run test:ui       # Interactive UI
npm run coverage      # Coverage report
```

**Test components**: Render with mock providers (AuthContext, API)
**Test user flows**: Login → Navigate → CRUD operations

## Performance Guidelines

### Backend Optimization
- **Database**:
  - Use `joinedload()` to avoid N+1 queries
  - Index foreign keys and frequently filtered fields
  - Use connection pooling (configured in `docker-compose.yml`)
- **Caching**:
  - `CACHE_LEVEL=0`: No cache (dev/testing)
  - `CACHE_LEVEL=1`: Classification + PDP cache (staging)
  - `CACHE_LEVEL=2`: + KMS cache (production)
  - Monitor cache hit rate in `/api/perf/stats`
- **Vault**:
  - Batch encrypt/decrypt when possible
  - Use Transit cache with appropriate TTL
- **Monitoring**:
  - Check `/api/perf/stats` for slow endpoints
  - Review `perf_log` table for bottlenecks

### Frontend Optimization
- **Bundle size**: Use dynamic imports for large components
- **API calls**: Debounce search inputs (300ms)
- **State**: Don't store large lists in context, use local state
- **Images**: Use lazy loading for film posters

### Target Metrics
- API response time: <200ms (p95) for read operations
- Cache hit rate: >90% in production
- Frontend bundle: <500KB gzipped

## Troubleshooting

### Common Issues

**"Vault is sealed"**
```bash
# Unseal Vault (dev mode auto-unseals, but if needed)
docker exec vault vault operator unseal <unseal-key>
```

**"Permission denied" for field access**
- Check user role in JWT token payload
- Verify field classification in `field_classification` table
- Review PDP logs in `audit_log` for decision reasoning

**"Decryption failed"**
- Ensure Vault Transit engine is enabled: `vault secrets enable transit`
- Verify key exists: `vault read transit/keys/dcs-key`
- Check `*_ct` column format: base64-encoded ciphertext

**Cache inconsistencies**
- Flush cache: Set `CACHE_TTL_*_SEC=0` temporarily
- Restart backend: `docker-compose restart backend`

**Database connection errors**
- Check PostgreSQL is running: `docker ps | grep postgres`
- Verify credentials in `docker-compose.yml`
- Check connection pool: `docker logs cinema-dcs-backend`

**Frontend not updating**
- Clear browser cache and localStorage
- Check API calls in Network tab (Dev Tools)
- Verify JWT token is being sent in Authorization header

### Debug Mode
```bash
# Enable verbose logging
export LOG_LEVEL=DEBUG
docker-compose up

# Check logs
docker logs -f cinema-dcs-backend
docker logs -f cinema-dcs-vault
```

### Useful Queries
```sql
-- Check field classifications
SELECT * FROM field_classification WHERE resource_type = 'film';

-- Audit trail for specific user
SELECT * FROM audit_log WHERE subject_id = 'user-id' ORDER BY timestamp DESC LIMIT 50;

-- Performance bottlenecks
SELECT endpoint, AVG(duration_ms) as avg_ms, COUNT(*) as count 
FROM perf_log 
GROUP BY endpoint 
ORDER BY avg_ms DESC;
```

## Git Workflow

### Branch Naming
- `feature/short-description` - New features
- `fix/bug-description` - Bug fixes
- `refactor/what-changed` - Code improvements
- `docs/what-documented` - Documentation only

### Commit Messages
Follow conventional commits:
```
feat(dcs): add field-level masking for PII
fix(api): handle Vault timeout gracefully
refactor(frontend): extract FilmCard component
docs(readme): update architecture diagram
```

### Pull Request Checklist
- [ ] Tests pass (`pytest` + `npm test`)
- [ ] No linting errors (`ruff check .` + `npm run lint`)
- [ ] Database migrations included if schema changed
- [ ] Updated CLAUDE.md if architecture/commands changed
- [ ] Added/updated tests for new functionality
- [ ] Verified DCS enforcement if touching security code

### Pre-commit
```bash
# Run before committing
ruff check app/ --fix
pytest tests/unit/
npm run lint --fix
```

## Key Configuration

Environment variables in `docker-compose.yml`:
- `DCS_MODE`: `on`/`off` - Toggle DCS enforcement
- `CACHE_LEVEL`: `0`/`1`/`2` - Caching strategy
- `CACHE_TTL_*_SEC` - TTL for classification, PDP, KMS, pepper caches
- `LOG_LEVEL`: `DEBUG`/`INFO`/`WARNING`/`ERROR`

Backend settings loaded via pydantic-settings in `/backend/app/core/config.py`.

## Database

Seeded with test users (dev/agent/admin password: `password`).

Key tables:
- `users`, `films`, `halls`, `spectators` - Domain entities
- `field_classification` - Maps (resource_type, field_name) → classification level
- `audit_log` - Tracks all field-level access decisions
- `perf_log` - Performance metrics per request

Sensitive fields stored encrypted (`*_ct` columns). Spectator ticket uses HMAC lookup (`external_id_lookup`) for searchable encryption.

## DCS Request Flow

1. **PIP** gathers subject attributes (role, tenant) and resource metadata (classification, labels)
2. **PDP** evaluates policy → returns per-field decisions (allow/decrypt/mask/deny)
3. **PEP** enforces decisions: calls Vault for decryption, applies masking, denies fields
4. **Audit** logs all decisions with request correlation

## Resources & References

### Documentation
- [FastAPI Docs](https://fastapi.tiangolo.com/)
- [SQLAlchemy ORM](https://docs.sqlalchemy.org/en/20/)
- [Vault Transit API](https://developer.hashicorp.com/vault/api-docs/secret/transit)
- [Pydantic Settings](https://docs.pydantic.dev/latest/concepts/pydantic_settings/)
- [React Router v6](https://reactrouter.com/en/main)
- [Vitest](https://vitest.dev/)

### Internal Docs (TODO)
- Architecture Decision Records: `/docs/adr/`
- API Collection: `/docs/api-collection.json`
- Database Schema: `/docs/schema.sql`
- DCS Policy Examples: `/docs/policies/`

### Related Standards
- XACML/ABAC specifications
- NIST Zero Trust Architecture
- OWASP API Security Top 10