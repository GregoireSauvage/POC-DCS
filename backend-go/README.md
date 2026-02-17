# Backend Go - Cinema DCS PoC

Backend Go pour le projet Cinema DCS (Data-Centric Security).

## ✅ État d'avancement

### Complété (P0 - Blockers critiques)

- ✅ **Configuration** : DATABASE_URL, VAULT_*, JWT_*
- ✅ **PostgreSQL** : Repository avec pgx, schéma partagé avec Python
- ✅ **Vault Transit** : KMS réel (remplace mock base64), cache niveau 3
- ✅ **Audit Logging** : Persistence en DB, logs décisions DCS
- ✅ **JWT Authentication** : Generation tokens, validation, endpoints /auth

### Architecture DCS

```
HTTP Request → JWT Middleware → PIP → PDP → PEP → Response
                                 ↓       ↓      ↓
                              Cache  Cache  Vault
                                              ↓
                                         PostgreSQL
                                              ↓
                                         Audit Log
```

## Quick Start

### Prérequis

- Go 1.22+
- PostgreSQL (via docker-compose du projet parent)
- Vault (via docker-compose du projet parent)

### Démarrage

```bash
# Build
go build -o bin/server ./cmd/server

# Run (avec services existants)
export DATABASE_URL="postgresql://cinema:cinema@localhost:5432/cinema?sslmode=disable"
export VAULT_ADDR="http://localhost:8200"
export VAULT_TOKEN="backend-token"
export VAULT_TRANSIT_KEY="cinema-dcs"
export JWT_SECRET="dev-secret-change-me"

./bin/server
```

### Endpoints disponibles

**Authentication**
- `POST /auth/login` - Login avec username/password → JWT token

**Films** (avec DCS enforcement)
- `GET /films` - Liste films avec décisions allow/decrypt/mask/deny par rôle
- `PATCH /films/{id}/time` - Update time_elapsed (write policy + read policy)

**Admin**
- `GET /admin/settings` - Lire DCS mode & cache level
- `PATCH /admin/settings` - Toggle DCS on/off, change cache level

**Health**
- `GET /health` - Health check
- `GET /ready` - Readiness check

## Configuration

Variables d'environnement (via `.env` ou docker-compose) :

```bash
# Database
DATABASE_URL=postgresql://cinema:cinema@postgres:5432/cinema

# Vault
VAULT_ADDR=http://vault:8200
VAULT_TOKEN=backend-token
VAULT_TRANSIT_KEY=cinema-dcs
VAULT_KV_PEPPER_PATH=secret/dcs

# JWT
JWT_SECRET=dev-secret-change-me
JWT_ISSUER=cinema-dcs-poc
JWT_AUDIENCE=cinema-ui
JWT_TTL_MINUTES=240

# DCS
DCS_MODE=on                    # on|off
CACHE_LEVEL=1                  # 0-3
CACHE_TTL_CLASSIF_SEC=300
CACHE_TTL_PDP_SEC=60
CACHE_TTL_KMS_SEC=10
CACHE_TTL_PEPPER_SEC=300

# Server
HTTP_ADDR=:8001
GRPC_ADDR=:50051
LOG_LEVEL=INFO
```

## Structure du projet

```
backend-go/
├── cmd/
│   └── server/          # Point d'entrée
├── internal/
│   ├── auth/            # JWT service
│   ├── config/          # Configuration
│   ├── dcs/             # DCS Core (PIP, PDP, PEP, KMS, cache)
│   ├── domain/          # Entités (Film, User, AuditLog)
│   ├── observability/   # Performance tracking
│   ├── repository/      # Interfaces + PostgreSQL impl
│   ├── server/          # Application setup
│   ├── service/         # Business logic
│   └── transport/       # HTTP + gRPC servers
├── proto/               # Définitions gRPC
├── scripts/             # Scripts utilitaires
├── go.mod
└── README.md
```

## Tests

```bash
# Run all tests
go test ./...

# With coverage
go test -cover ./...

# Specific package
go test ./internal/dcs/pdp/
```

## Développement

### Makefile

```bash
make build      # Compile binaire
make test       # Run tests
make lint       # golangci-lint
make run        # Run server locally
make clean      # Clean artifacts
```

### Hot reload (optionnel)

```bash
go install github.com/cosmtrek/air@latest
air  # Uses .air.toml config
```

## Parité avec backend Python

Voir `/docs/go-backend-parity-checklist.md` pour l'état d'avancement détaillé.

**Résumé actuel** : ~35% parité fonctionnelle
- ✅ Config & Infrastructure (100%)
- ✅ Cache & Runtime (100%)
- ✅ DCS Core Logic (90%)
- 🟡 HTTP Endpoints (30% - Films + Admin seulement)
- ❌ Hall / Spectator services (0%)
- ❌ gRPC implementations (0%)

## Logs

Le serveur log en JSON (slog) :

```json
{
  "time": "2026-02-06T10:30:00Z",
  "level": "INFO",
  "msg": "vault transit client connected",
  "addr": "http://vault:8200",
  "transit_key": "cinema-dcs"
}
```

## Troubleshooting

**Build fails with Go 1.18**
- Installer Go 1.22+ : `bash scripts/install-go.sh`

**Vault connection fails**
- Vérifier `VAULT_ADDR` et `VAULT_TOKEN`
- Check vault status: `vault status`

**Database connection fails**
- Vérifier PostgreSQL: `pg_isready -h localhost -p 5432`
- Check credentials dans `DATABASE_URL`

**JWT validation fails**
- Vérifier que `JWT_SECRET` est identique Python/Go
- Check token expiration (TTL=240min par défaut)

## Prochaines étapes (P1)

1. Spectator service + HMAC lookup
2. Hall service
3. POST /films endpoint
4. Performance logging endpoints (/perf, /perf/summary)
5. gRPC service implementations

## License

PoC interne
