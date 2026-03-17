package http

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/neoweyss/poc-dcs/backend-go/internal/auth"
	"github.com/neoweyss/poc-dcs/backend-go/internal/config"
	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
	infrabinding "github.com/neoweyss/poc-dcs/backend-go/internal/infra/binding"
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
	deps                 Dependencies
	authorizer           service.Authorizer
	classificationReader service.ClassificationMetadataReader
	bindingDeps          securedrepo.BindingDependencies
	logger               *slog.Logger
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
	bindingManager := infrabinding.NewManager(infrabinding.Config{
		ProfileID:      dcsConfig.Binding.ProfileID,
		ProofAlgorithm: dcsConfig.Binding.ProofAlgorithm,
		KeyID:          dcsConfig.Binding.KeyID,
		Secret:         []byte(cfg.DCSBindingHMACKey),
	})
	authorizer := newHTTPAuthorizer(rt, cm, dcsConfig)

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
	bindingStore := memory.NewBindingRepository()
	labelIssuer := service.NewServerLabelIssuer(
		config.NewClassificationPolicy(dcsConfig),
		service.NewStaticClassificationReader(map[string][]domain.FieldClassification{
			"film": {
				{ResourceType: "film", FieldName: "title", Classification: "PUBLIC"},
				{ResourceType: "film", FieldName: "time_elapsed", Classification: "SENSITIVE"},
			},
			"hall": {
				{ResourceType: "hall", FieldName: "name", Classification: "PUBLIC"},
				{ResourceType: "hall", FieldName: "owner_user_id", Classification: "INTERNAL"},
				{ResourceType: "hall", FieldName: "current_film_id", Classification: "INTERNAL"},
			},
			"spectator": {
				{ResourceType: "spectator", FieldName: "name", Classification: "PII"},
				{ResourceType: "spectator", FieldName: "age", Classification: "SENSITIVE"},
				{ResourceType: "spectator", FieldName: "external_id", Classification: "PII"},
			},
		}),
		map[string]service.Classification{
			"film":      service.ClassificationSensitive,
			"hall":      service.ClassificationInternal,
			"spectator": service.ClassificationPII,
		},
	)
	bindingDeps := securedrepo.BindingDependencies{
		Store:       bindingStore,
		Verifier:    bindingManager,
		Issuer:      bindingManager,
		LabelIssuer: labelIssuer,
		Authorizer:  authorizer,
		Crypto:      kmsClient,
		ClassificationReader: service.NewStaticClassificationReader(map[string][]domain.FieldClassification{
			"film": {
				{ResourceType: "film", FieldName: "title", Classification: "PUBLIC"},
				{ResourceType: "film", FieldName: "time_elapsed", Classification: "SENSITIVE"},
			},
			"hall": {
				{ResourceType: "hall", FieldName: "name", Classification: "PUBLIC"},
				{ResourceType: "hall", FieldName: "owner_user_id", Classification: "INTERNAL"},
				{ResourceType: "hall", FieldName: "current_film_id", Classification: "INTERNAL"},
			},
			"spectator": {
				{ResourceType: "spectator", FieldName: "name", Classification: "PII"},
				{ResourceType: "spectator", FieldName: "age", Classification: "SENSITIVE"},
				{ResourceType: "spectator", FieldName: "external_id", Classification: "PII"},
			},
		}),
	}
	seedAccess := service.AccessContext{
		Principal: service.Principal{TenantID: "t1", UserID: "u-admin", Role: "admin"},
		Request:   service.RequestContext{RequestID: "seed", Channel: "seed", Purpose: "test", Env: "test"},
	}
	mustSeedBinding(t, bindingStore, bindingManager, labelIssuer, seedAccess, service.Resource{Type: "film", ID: "film-1", TenantID: "t1"}, filmBindingPayload{ResourceType: "film", TenantID: "t1", ID: "film-1", Title: "Interstellar", TimeElapsedCT: seedCT})
	mustSeedBinding(t, bindingStore, bindingManager, labelIssuer, seedAccess, service.Resource{Type: "hall", ID: "hall-1", TenantID: "t1"}, hallBindingPayload{ResourceType: "hall", TenantID: "t1", ID: "hall-1", Name: "Hall A", OwnerUserID: "u-admin", CurrentFilmID: "film-1"})

	// Setup services
	jwtService := auth.NewJWTService(cfg.JWTSecret, cfg.JWTIssuer, cfg.JWTAudience, cfg.JWTTTLMin)

	// No audit/perf services in tests by default (can be added via With methods)
	filmSecureRepo := securedrepo.NewFilmRepository(filmRepo, logger.With(slog.String("component", "secured_film_repository")), bindingDeps)
	hallSecureRepo := securedrepo.NewHallRepository(hallRepo, logger.With(slog.String("component", "secured_hall_repository")), bindingDeps)
	spectatorSecureRepo := securedrepo.NewSpectatorRepository(spectatorRepo, rt, logger.With(slog.String("component", "secured_spectator_repository")), bindingDeps)
	filmService := service.NewFilmService(filmSecureRepo, authorizer, bindingDeps.ClassificationReader, nil, nil, rt)
	hallService := service.NewHallService(hallSecureRepo, authorizer, bindingDeps.ClassificationReader, nil, nil, rt)
	spectatorService := service.NewSpectatorService(spectatorSecureRepo, hallRepo, authorizer, bindingDeps.ClassificationReader, nil, nil, rt)

	return &TestDependenciesBuilder{
		deps: Dependencies{
			Config:           cfg,
			Logger:           logger,
			Runtime:          rt,
			Cache:            cm,
			FilmService:      filmService,
			HallService:      hallService,
			SpectatorService: spectatorService,
			AuthService:      nil, // No auth by default (no DB)
			AuditService:     nil, // No audit by default
			PerfService:      nil, // No perf by default
			JWTService:       jwtService,
		},
		authorizer:           authorizer,
		classificationReader: bindingDeps.ClassificationReader,
		bindingDeps:          bindingDeps,
		logger:               logger,
	}
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

func (b *TestDependenciesBuilder) NewSecureHallService(raw service.HallRepository) service.HallService {
	if raw != nil {
		records, err := raw.ListByTenant(context.Background(), "t1")
		if err == nil {
			access := service.AccessContext{
				Principal: service.Principal{TenantID: "t1", UserID: "u-admin", Role: "admin"},
				Request:   service.RequestContext{RequestID: "seed-hall", Channel: "seed", Purpose: "test", Env: "test"},
			}
			for _, record := range records {
				label, err := b.bindingDeps.LabelIssuer.Issue(context.Background(), access, service.Resource{Type: "hall", ID: record.ID, TenantID: record.TenantID})
				if err != nil {
					panic(err)
				}
				binding, err := b.bindingDeps.Issuer.Create(context.Background(), hallBindingPayload{
					ResourceType:  "hall",
					TenantID:      record.TenantID,
					ID:            record.ID,
					Name:          record.Name,
					OwnerUserID:   record.OwnerUserID,
					CurrentFilmID: record.CurrentFilmID,
				}, label)
				if err != nil {
					panic(err)
				}
				if err := b.bindingDeps.Store.Upsert(context.Background(), service.ResourceBinding{
					TenantID:     record.TenantID,
					ResourceType: "hall",
					ResourceID:   record.ID,
					Label:        label,
					Binding:      binding,
				}); err != nil {
					panic(err)
				}
			}
		}
	}
	secureRepo := securedrepo.NewHallRepository(raw, b.logger.With(slog.String("component", "secured_hall_repository")), b.bindingDeps)
	return service.NewHallService(secureRepo, b.authorizer, b.classificationReader, nil, nil, b.deps.Runtime)
}

func (b *TestDependenciesBuilder) NewSecureSpectatorService(raw service.SpectatorRepository, hallRepo service.HallRepository) *service.SpectatorService {
	secureRepo := securedrepo.NewSpectatorRepository(raw, b.deps.Runtime, b.logger.With(slog.String("component", "secured_spectator_repository")), b.bindingDeps)
	return service.NewSpectatorService(secureRepo, hallRepo, b.authorizer, b.classificationReader, nil, nil, b.deps.Runtime)
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
		Env:               "dev",
		Service:           "backend-go-test",
		HTTPAddr:          ":0",
		GRPCAddr:          ":0",
		LogLevel:          slog.LevelError,
		PerfSource:        "go",
		DCSMode:           "on",
		DCSConfigPath:     "",
		DCSBindingHMACKey: "test-binding-secret",
		CacheLevel:        1,
		CacheMaxEntries:   100,
		CacheTTLClassif:   60,
		CacheTTLPDP:       60,
		CacheTTLKMS:       60,
		CacheTTLPepper:    60,
		JWTSecret:         "test-secret",
		JWTIssuer:         "test-issuer",
		JWTAudience:       "test-audience",
		JWTTTLMin:         60,
	}
}

func mustSeedBinding(
	t *testing.T,
	store service.BindingStore,
	issuer service.BindingIssuer,
	labelIssuer service.LabelIssuer,
	access service.AccessContext,
	resource service.Resource,
	payload any,
) {
	t.Helper()
	label, err := labelIssuer.Issue(context.Background(), access, resource)
	if err != nil {
		t.Fatalf("issue label: %v", err)
	}
	binding, err := issuer.Create(context.Background(), payload, label)
	if err != nil {
		t.Fatalf("create binding: %v", err)
	}
	if err := store.Upsert(context.Background(), service.ResourceBinding{
		TenantID:     resource.TenantID,
		ResourceType: resource.Type,
		ResourceID:   resource.ID,
		Label:        label,
		Binding:      binding,
	}); err != nil {
		t.Fatalf("seed binding: %v", err)
	}
}

type filmBindingPayload struct {
	ResourceType  string `json:"resource_type"`
	TenantID      string `json:"tenant_id"`
	ID            string `json:"id"`
	Title         string `json:"title"`
	TimeElapsedCT string `json:"time_elapsed_ct"`
}

type hallBindingPayload struct {
	ResourceType  string `json:"resource_type"`
	TenantID      string `json:"tenant_id"`
	ID            string `json:"id"`
	Name          string `json:"name"`
	OwnerUserID   string `json:"owner_user_id"`
	CurrentFilmID string `json:"current_film_id"`
}

func authHeaderForRole(t *testing.T, server *Server, userID, username, role string) string {
	t.Helper()

	token, err := server.jwtService.GenerateToken(auth.JWTSubject{
		UserID:   userID,
		TenantID: "t1",
		Username: username,
		Role:     role,
		Scopes:   []string{"cinema"},
	})
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	return "Bearer " + token
}

func adminAuthHeader(t *testing.T, server *Server) string {
	t.Helper()
	return authHeaderForRole(t, server, "u-admin", "admin", "admin")
}

func agentAuthHeader(t *testing.T, server *Server) string {
	t.Helper()
	return authHeaderForRole(t, server, "u-agent", "agent", "agent")
}

func developerAuthHeader(t *testing.T, server *Server) string {
	t.Helper()
	return authHeaderForRole(t, server, "u-developer", "developer", "developer")
}
