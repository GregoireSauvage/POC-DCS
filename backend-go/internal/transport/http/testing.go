package http

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/neoweyss/poc-dcs/backend-go/internal/auth"
	"github.com/neoweyss/poc-dcs/backend-go/internal/config"
	legacycache "github.com/neoweyss/poc-dcs/backend-go/internal/dcs/cache"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/enforcer"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/pep"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/pip"
	legacyruntime "github.com/neoweyss/poc-dcs/backend-go/internal/dcs/runtime"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/types"
	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
	infracache "github.com/neoweyss/poc-dcs/backend-go/internal/infra/cache"
	infrakms "github.com/neoweyss/poc-dcs/backend-go/internal/infra/kms"
	"github.com/neoweyss/poc-dcs/backend-go/internal/repository/memory"
	securedrepo "github.com/neoweyss/poc-dcs/backend-go/internal/repository/postgres/secured"
	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
	serviceauth "github.com/neoweyss/poc-dcs/backend-go/internal/service/authorization"
)

// TestDependenciesBuilder provides a fluent API for building test dependencies
// Allows easy customization of individual dependencies for focused testing
type TestDependenciesBuilder struct {
	deps Dependencies
}

func newHTTPAuthorizer(rt *config.DCSRuntime, cm *infracache.Manager, cfg *config.DCSConfig) service.Authorizer {
	policy := config.NewClassificationPolicy(cfg)
	pdp := serviceauth.NewPDP(policy)
	base := serviceauth.NewAuthorizer(rt, pdp)
	return serviceauth.NewCachedAuthorizer(rt, policy, cm.PDP, base)
}

// NewTestDependenciesBuilder creates a builder with sensible defaults for testing
func NewTestDependenciesBuilder(t *testing.T) *TestDependenciesBuilder {
	t.Helper()

	cfg := testConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	// Setup infrastructure
	rt := config.NewDCSRuntime("on", 1)
	cm := infracache.NewManager(rt, infracache.Options{
		MaxEntries:        100,
		ClassificationTTL: 60,
		PDPTTL:            60,
		KMSTTL:            60,
		PepperTTL:         60,
	})
	kmsClient := infrakms.NewLocalClient()

	// Setup DCS components
	dcsConfig := config.DefaultDCSConfig() // Use defaults for tests
	classificationStore := &pip.StaticClassificationStore{
		ByResource: map[string]map[string]types.Classification{
			"film": {
				"title":        types.ClassificationPublic,
				"time_elapsed": types.ClassificationSensitive,
			},
			"hall": {
				"name":            types.ClassificationPublic,
				"owner_user_id":   types.ClassificationInternal,
				"current_film_id": types.ClassificationInternal,
			},
			"spectator": {
				"name":        types.ClassificationPII,
				"age":         types.ClassificationSensitive,
				"external_id": types.ClassificationPII,
			},
		},
	}

	legacyRT := legacyruntime.Wrap(rt)
	legacyCache := legacycache.NewManager(legacyRT, legacycache.Options{
		MaxEntries:        100,
		ClassificationTTL: 60,
		PDPTTL:            60,
		KMSTTL:            60,
		PepperTTL:         60,
	})

	pipProvider := pip.NewProvider(legacyRT, legacyCache, classificationStore, pip.Config{
		Env:            cfg.Env,
		Channel:        "web",
		Purpose:        "access",
		DeviceTrust:    1.0,
		ClientIPHeader: "X-Forwarded-For",
	})
	authorizer := newHTTPAuthorizer(rt, cm, dcsConfig)
	filmApplier := pep.NewFilmApplier(legacyRT, kmsClient)
	spectatorApplier := pep.NewSpectatorApplier(kmsClient)
	dcsEnforcer := enforcer.New(pipProvider, authorizer, filmApplier, spectatorApplier, kmsClient, "")

	// Setup repositories (in-memory with seed data)
	seedCT, _ := kmsClient.Encrypt(context.Background(), "120")
	if seedCT == "" {
		seedCT = "120"
	}
	filmRepo := memory.NewFilmRepository([]service.FilmRecord{
		{TenantID: "t1", ID: "film-1", Title: "Interstellar", TimeElapsedCT: seedCT},
	})
	hallRepo := memory.NewHallRepository([]domain.Hall{
		{TenantID: "t1", ID: "hall-1", Name: "Hall A", OwnerUserID: "u-admin", CurrentFilmID: "film-1"},
	})
	spectatorRepo := memory.NewSpectatorRepository()

	// Setup services
	jwtService := auth.NewJWTService(cfg.JWTSecret, cfg.JWTIssuer, cfg.JWTAudience, cfg.JWTTTLMin)

	// No audit/perf services in tests by default (can be added via With methods)
	filmSecureRepo := securedrepo.NewFilmRepository(filmRepo, dcsEnforcer, logger.With(slog.String("component", "secured_film_repository")))
	hallSecureRepo := securedrepo.NewHallRepository(hallRepo, dcsEnforcer, logger.With(slog.String("component", "secured_hall_repository")))
	spectatorSecureRepo := securedrepo.NewSpectatorRepository(spectatorRepo, dcsEnforcer, rt, logger.With(slog.String("component", "secured_spectator_repository")))
	filmService := service.NewFilmService(filmSecureRepo, dcsEnforcer, nil, nil, rt)
	hallService := service.NewHallServiceWithSecureRepo(hallRepo, hallSecureRepo, dcsEnforcer, nil, nil, rt)
	spectatorService := service.NewSpectatorServiceWithSecureRepo(spectatorRepo, spectatorSecureRepo, hallRepo, dcsEnforcer, nil, nil, rt)

	return &TestDependenciesBuilder{
		deps: Dependencies{
			Config:           cfg,
			Logger:           logger,
			Runtime:          rt,
			Cache:            cm,
			Enforcer:         dcsEnforcer,
			FilmService:      filmService,
			HallService:      hallService,
			SpectatorService: spectatorService,
			AuthService:      nil, // No auth by default (no DB)
			AuditService:     nil, // No audit by default
			PerfService:      nil, // No perf by default
			JWTService:       jwtService,
		},
	}
}

// WithEnforcer overrides the DCS enforcer
func (b *TestDependenciesBuilder) WithEnforcer(enforcer service.PolicyEnforcer) *TestDependenciesBuilder {
	b.deps.Enforcer = enforcer
	return b
}

// WithFilmService overrides the film service
func (b *TestDependenciesBuilder) WithFilmService(svc *service.FilmService) *TestDependenciesBuilder {
	b.deps.FilmService = svc
	return b
}

// WithHallService overrides the hall service
func (b *TestDependenciesBuilder) WithHallService(svc service.HallService) *TestDependenciesBuilder {
	b.deps.HallService = svc
	return b
}

// WithSpectatorService overrides the spectator service
func (b *TestDependenciesBuilder) WithSpectatorService(svc *service.SpectatorService) *TestDependenciesBuilder {
	b.deps.SpectatorService = svc
	return b
}

// WithAuditService overrides the audit service
func (b *TestDependenciesBuilder) WithAuditService(svc *service.AuditService) *TestDependenciesBuilder {
	b.deps.AuditService = svc
	return b
}

// WithPerfService overrides the perf service
func (b *TestDependenciesBuilder) WithPerfService(svc service.PerfService) *TestDependenciesBuilder {
	b.deps.PerfService = svc
	return b
}

// WithAuthService overrides the auth service
func (b *TestDependenciesBuilder) WithAuthService(svc *service.AuthService) *TestDependenciesBuilder {
	b.deps.AuthService = svc
	return b
}

// WithJWTService overrides the JWT service
func (b *TestDependenciesBuilder) WithJWTService(svc *auth.JWTService) *TestDependenciesBuilder {
	b.deps.JWTService = svc
	return b
}

// WithConfig overrides the config
func (b *TestDependenciesBuilder) WithConfig(cfg *config.Config) *TestDependenciesBuilder {
	b.deps.Config = cfg
	return b
}

// WithRuntime overrides the runtime settings
func (b *TestDependenciesBuilder) WithRuntime(rt *config.DCSRuntime) *TestDependenciesBuilder {
	b.deps.Runtime = rt
	return b
}

// Build returns the constructed Dependencies struct
func (b *TestDependenciesBuilder) Build() Dependencies {
	return b.deps
}

// newTestServer creates a test server with default dependencies
func newTestServer(t *testing.T) *Server {
	t.Helper()
	deps := NewTestDependenciesBuilder(t).Build()
	return NewServer(deps)
}

// newTestServerWithDeps creates a test server with custom dependencies
// The customize function receives a builder and can override any dependencies
func newTestServerWithDeps(t *testing.T, customize func(*TestDependenciesBuilder)) *Server {
	t.Helper()
	builder := NewTestDependenciesBuilder(t)
	customize(builder)
	return NewServer(builder.Build())
}

// testConfig returns a config suitable for testing
func testConfig() *config.Config {
	return &config.Config{
		Env:             "dev",
		Service:         "backend-go-test",
		HTTPAddr:        ":0",
		GRPCAddr:        ":0",
		LogLevel:        slog.LevelError,
		DCSMode:         "on",
		DCSConfigPath:   "",
		CacheLevel:      1,
		CacheMaxEntries: 100,
		CacheTTLClassif: 60,
		CacheTTLPDP:     60,
		CacheTTLKMS:     60,
		CacheTTLPepper:  60,
		JWTSecret:       "test-secret",
		JWTIssuer:       "test-issuer",
		JWTAudience:     "test-audience",
		JWTTTLMin:       60,
		PerfSource:      "go",
	}
}

// adminAuthHeader generates a JWT token for an admin user
func adminAuthHeader(t *testing.T, s *Server) string {
	t.Helper()
	token, err := s.jwtService.GenerateToken(
		auth.JWTSubject{
			UserID:   "admin-id",
			TenantID: "t1",
			Username: "admin",
			Role:     "admin",
		})
	if err != nil {
		t.Fatalf("failed to generate admin token: %v", err)
	}
	return "Bearer " + token
}
