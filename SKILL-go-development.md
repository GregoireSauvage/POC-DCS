---
name: go-project-structure
# prettier-ignore
description: Structure de projet et conventions Go. Utiliser pour créer un nouveau projet Go, organiser le code, appliquer les conventions de nommage, configurer les tests, ou créer Makefile/Dockerfile.
---

# Go Project Structure & Conventions

## Overview

Ce skill définit les conventions de structure et de code pour les projets Go, particulièrement pour les microservices gRPC.

## Structure standard

```
myservice/
├── cmd/                        # Points d'entrée (main packages)
│   ├── server/
│   │   └── main.go
│   └── cli/
│       └── main.go
├── internal/                   # Code privé (non importable)
│   ├── server/                 # Configuration serveur
│   ├── service/                # Logique métier
│   ├── repository/             # Accès données
│   ├── domain/                 # Entités/modèles
│   └── config/                 # Configuration
├── pkg/                        # Code réutilisable (importable)
│   └── middleware/
├── proto/                      # Fichiers .proto
│   └── <domain>/v1/
├── gen/                        # Code généré (proto, mocks)
│   └── go/
├── migrations/                 # Migrations DB
├── scripts/                    # Scripts utilitaires
├── api/                        # Specs OpenAPI (si REST aussi)
├── docs/                       # Documentation
├── buf.yaml
├── buf.gen.yaml
├── go.mod
├── go.sum
├── Makefile
├── Dockerfile
└── README.md
```

## Conventions de nommage

### Fichiers

```
user_service.go        # snake_case
user_service_test.go   # Tests avec _test suffix
user_repository.go
```

### Packages

```go
package service        // lowercase, singular
package repository
package userv1         // Pour code généré proto
```

### Variables et fonctions

```go
// Exporté (public) - PascalCase
func GetUser() {}
type UserService struct {}
var MaxRetries = 3

// Non exporté (privé) - camelCase
func getUserFromDB() {}
type userCache struct {}
var defaultTimeout = 5 * time.Second
```

### Interfaces

```go
// Nom = verbe + "er" ou description du comportement
type Reader interface {
    Read(p []byte) (n int, err error)
}

type UserRepository interface {
    GetByID(ctx context.Context, id string) (*User, error)
    Create(ctx context.Context, user *User) error
}

// Interface dans le package qui l'utilise, pas qui l'implémente
// internal/service/user_service.go
type UserRepository interface { ... }  // Définie ici
```

### Constructeurs

```go
// NewXxx retourne le type concret ou l'interface
func NewUserService(repo UserRepository, cache Cache) *UserService {
    return &UserService{
        repo:  repo,
        cache: cache,
    }
}

// Options pattern pour configs complexes
func NewServer(opts ...Option) *Server {
    s := &Server{
        port:    8080,
        timeout: 30 * time.Second,
    }
    for _, opt := range opts {
        opt(s)
    }
    return s
}

func WithPort(port int) Option {
    return func(s *Server) {
        s.port = port
    }
}
```

## Gestion des erreurs

### Wrapping

```go
import "fmt"

// Wrapper les erreurs avec contexte
if err != nil {
    return fmt.Errorf("failed to get user %s: %w", id, err)
}

// Vérifier les erreurs wrappées
if errors.Is(err, sql.ErrNoRows) {
    return nil, ErrNotFound
}

// Erreurs personnalisées
var (
    ErrNotFound     = errors.New("not found")
    ErrUnauthorized = errors.New("unauthorized")
)
```

### Sentinel errors vs error types

```go
// Sentinel errors pour cas simples
var ErrNotFound = errors.New("not found")

// Error types pour plus de contexte
type ValidationError struct {
    Field   string
    Message string
}

func (e *ValidationError) Error() string {
    return fmt.Sprintf("validation error on %s: %s", e.Field, e.Message)
}
```

## Context

```go
// Toujours en premier paramètre
func GetUser(ctx context.Context, id string) (*User, error)

// Propager le context
func (s *Service) Process(ctx context.Context) error {
    user, err := s.repo.GetUser(ctx, id)  // Passer ctx
    // ...
}

// Respecter les cancellations
select {
case <-ctx.Done():
    return ctx.Err()
case result := <-ch:
    return result, nil
}
```

## Dependency Injection

```go
// Injection par constructeur (préféré)
type UserService struct {
    repo   UserRepository
    cache  Cache
    logger *slog.Logger
}

func NewUserService(repo UserRepository, cache Cache, logger *slog.Logger) *UserService {
    return &UserService{
        repo:   repo,
        cache:  cache,
        logger: logger,
    }
}

// main.go - composition
func main() {
    db := database.Connect(cfg.DatabaseURL)
    repo := repository.NewUserRepository(db)
    cache := cache.NewRedisCache(cfg.RedisURL)
    logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
    
    userSvc := service.NewUserService(repo, cache, logger)
    // ...
}
```

## Configuration

```go
// internal/config/config.go
package config

import (
    "github.com/kelseyhightower/envconfig"
)

type Config struct {
    Port        int    `envconfig:"PORT" default:"50051"`
    DatabaseURL string `envconfig:"DATABASE_URL" required:"true"`
    RedisURL    string `envconfig:"REDIS_URL" default:"localhost:6379"`
    LogLevel    string `envconfig:"LOG_LEVEL" default:"info"`
}

func Load() (*Config, error) {
    var cfg Config
    if err := envconfig.Process("", &cfg); err != nil {
        return nil, fmt.Errorf("failed to load config: %w", err)
    }
    return &cfg, nil
}
```

## Logging (slog - Go 1.21+)

```go
import "log/slog"

// Setup
logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
    Level: slog.LevelInfo,
}))
slog.SetDefault(logger)

// Usage
slog.Info("user created",
    slog.String("user_id", user.ID),
    slog.String("email", user.Email),
)

slog.Error("failed to process request",
    slog.String("error", err.Error()),
    slog.String("request_id", reqID),
)

// Avec context
logger.InfoContext(ctx, "processing request")
```

## Tests

### Structure

```go
// user_service_test.go
package service_test  // ou service pour tests internes

import (
    "testing"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestUserService_GetUser(t *testing.T) {
    t.Run("returns user when found", func(t *testing.T) {
        // Arrange
        repo := &mockUserRepository{
            user: &domain.User{ID: "123", Name: "Alice"},
        }
        svc := service.NewUserService(repo)
        
        // Act
        user, err := svc.GetUser(context.Background(), "123")
        
        // Assert
        require.NoError(t, err)
        assert.Equal(t, "Alice", user.Name)
    })
    
    t.Run("returns error when not found", func(t *testing.T) {
        repo := &mockUserRepository{err: service.ErrNotFound}
        svc := service.NewUserService(repo)
        
        _, err := svc.GetUser(context.Background(), "unknown")
        
        assert.ErrorIs(t, err, service.ErrNotFound)
    })
}
```

### Table-driven tests

```go
func TestValidateEmail(t *testing.T) {
    tests := []struct {
        name    string
        email   string
        wantErr bool
    }{
        {"valid email", "user@example.com", false},
        {"missing @", "userexample.com", true},
        {"empty", "", true},
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := ValidateEmail(tt.email)
            if tt.wantErr {
                assert.Error(t, err)
            } else {
                assert.NoError(t, err)
            }
        })
    }
}
```

## Makefile

```makefile
.PHONY: build test lint proto run

# Variables
BINARY_NAME=server
GO=go

# Build
build:
	$(GO) build -o bin/$(BINARY_NAME) ./cmd/server

# Run
run:
	$(GO) run ./cmd/server

# Test
test:
	$(GO) test -v -race -cover ./...

test-coverage:
	$(GO) test -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html

# Lint
lint:
	golangci-lint run ./...

# Proto
proto:
	buf generate

proto-lint:
	buf lint

# Clean
clean:
	rm -rf bin/ gen/

# Docker
docker-build:
	docker build -t $(BINARY_NAME) .

# All
all: proto lint test build
```

## Dockerfile

```dockerfile
# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Deps
COPY go.mod go.sum ./
RUN go mod download

# Build
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /server ./cmd/server

# Runtime stage
FROM alpine:3.19

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

COPY --from=builder /server .

# Non-root user
RUN adduser -D -g '' appuser
USER appuser

EXPOSE 50051

ENTRYPOINT ["./server"]
```
