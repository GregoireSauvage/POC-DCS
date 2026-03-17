package http

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/neoweyss/poc-dcs/backend-go/internal/auth"
	"github.com/neoweyss/poc-dcs/backend-go/internal/config"
	infrabinding "github.com/neoweyss/poc-dcs/backend-go/internal/infra/binding"
	infracache "github.com/neoweyss/poc-dcs/backend-go/internal/infra/cache"
	infrakms "github.com/neoweyss/poc-dcs/backend-go/internal/infra/kms"
	"github.com/neoweyss/poc-dcs/backend-go/internal/repository/postgres"
	securedrepo "github.com/neoweyss/poc-dcs/backend-go/internal/repository/postgres/secured"
	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

// newServerWithDB creates a test server with a real database connection
// This duplicates the dependency construction logic for DB tests to avoid import cycles
func newServerWithDB(cfg *config.Config, logger *slog.Logger, db *postgres.Pool) *Server {
	// Load DCS config
	dcsCfg := config.DefaultDCSConfig()
	if cfg.DCSConfigPath != "" {
		loaded, err := config.LoadDCSConfig(cfg.DCSConfigPath)
		if err == nil {
			dcsCfg = loaded
		}
	}

	// Setup infrastructure
	rt := config.NewDCSRuntime(cfg.DCSMode, cfg.CacheLevel)
	cm := infracache.NewManager(rt, infracache.Options{
		MaxEntries:        cfg.CacheMaxEntries,
		ClassificationTTL: cfg.CacheTTLClassif,
		PDPTTL:            cfg.CacheTTLPDP,
		KMSTTL:            cfg.CacheTTLKMS,
		PepperTTL:         cfg.CacheTTLPepper,
	})

	// KMS client
	var kmsClient service.CryptoProvider
	if cfg.VaultAddr != "" && cfg.VaultToken != "" {
		vaultClient, err := infrakms.NewVaultTransitClient(
			cfg.VaultAddr, cfg.VaultToken, cfg.VaultTransitKey, cm, logger,
		)
		if err == nil {
			kmsClient = vaultClient
		} else {
			kmsClient = infrakms.NewLocalClient()
		}
	} else {
		kmsClient = infrakms.NewLocalClient()
	}

	classificationRepo := postgres.NewClassificationRepository(db)
	authorizer := newHTTPAuthorizer(rt, cm, dcsCfg)
	bindingManager := infrabinding.NewManager(infrabinding.Config{
		ProfileID:      dcsCfg.Binding.ProfileID,
		ProofAlgorithm: dcsCfg.Binding.ProofAlgorithm,
		KeyID:          dcsCfg.Binding.KeyID,
		Secret:         []byte(cfg.DCSBindingHMACKey),
	})

	// Repositories with DB
	filmStore := postgres.NewFilmRepository(db)
	hallStore := postgres.NewHallRepository(db)
	spectatorStore := postgres.NewSpectatorRepository(db)
	auditRepo := postgres.NewAuditLogRepository(db)
	perfRepo := postgres.NewPerfLogRepository(db)
	userRepo := postgres.NewUserRepository(db)
	bindingRepo := postgres.NewBindingRepository(db)

	// Services
	auditService := service.NewAuditService(auditRepo, authorizer, logger)
	perfService := service.NewPerfService(perfRepo, authorizer, cfg.PerfSource)
	labelIssuer := service.NewServerLabelIssuer(
		config.NewClassificationPolicy(dcsCfg),
		classificationRepo,
		map[string]service.Classification{"film": service.ClassificationSensitive, "hall": service.ClassificationInternal, "spectator": service.ClassificationPII},
	)
	bindingDeps := securedrepo.BindingDependencies{
		Store:                bindingRepo,
		Verifier:             bindingManager,
		Issuer:               bindingManager,
		LabelIssuer:          labelIssuer,
		Authorizer:           authorizer,
		Crypto:               kmsClient,
		ClassificationReader: classificationRepo,
	}
	filmRepo := securedrepo.NewFilmRepository(filmStore, logger.With(slog.String("component", "film_repository")), bindingDeps)
	hallRepo := securedrepo.NewHallRepository(hallStore, logger.With(slog.String("component", "hall_repository")), bindingDeps)
	spectatorRepo := securedrepo.NewSpectatorRepository(spectatorStore, rt, logger.With(slog.String("component", "spectator_repository")), bindingDeps)
	filmService := service.NewFilmService(filmRepo, authorizer, classificationRepo, auditService, perfService, rt)
	hallService := service.NewHallService(hallRepo, authorizer, classificationRepo, auditService, perfService, rt)
	spectatorService := service.NewSpectatorService(spectatorRepo, hallStore, authorizer, classificationRepo, auditService, perfService, rt)
	jwtService := auth.NewJWTService(cfg.JWTSecret, cfg.JWTIssuer, cfg.JWTAudience, cfg.JWTTTLMin)
	authService := service.NewAuthService(userRepo, jwtService)

	return NewServer(Dependencies{
		Config:           cfg,
		Logger:           logger,
		Runtime:          rt,
		Cache:            cm,
		FilmService:      filmService,
		HallService:      hallService,
		SpectatorService: spectatorService,
		AuthService:      authService,
		AuditService:     auditService,
		PerfService:      perfService,
		JWTService:       jwtService,
	})
}

// TestIntegration_WithRealDatabase tests the full stack with a real PostgreSQL database
// This test is skipped if DATABASE_URL is not set
func TestIntegration_WithRealDatabase(t *testing.T) {
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set, skipping database integration test")
	}

	ctx := context.Background()
	db, err := postgres.NewPool(ctx, dbURL)
	if err != nil {
		t.Fatalf("failed to connect to test database: %v", err)
	}
	defer db.Close()

	// Build server with real database using the canonical constructor chain
	cfg := testConfig()
	cfg.DatabaseURL = dbURL

	logger := testLogger()
	server := newServerWithDB(cfg, logger, db)

	// Test with real DB - all services should be wired
	if server.authService == nil {
		t.Error("authService should be wired with real DB")
	}
	if server.auditService == nil {
		t.Error("auditService should be wired with real DB")
	}
	if server.perfService == nil {
		t.Error("perfService should be wired with real DB")
	}

	// Run a full CRUD test with database persistence
	adminToken, _ := server.jwtService.GenerateToken(auth.JWTSubject{
		UserID: "u-admin", TenantID: "test-tenant", Username: "admin", Role: "admin",
	})

	// Create a film
	createReq := map[string]interface{}{
		"title":        "Database Test Film",
		"time_elapsed": "120",
	}
	createBody, _ := json.Marshal(createReq)

	req := httptest.NewRequest(http.MethodPost, "/films", bytes.NewReader(createBody))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("CREATE failed with real DB: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var createdFilm map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &createdFilm)
	filmID := createdFilm["id"].(string)

	// Read back the film
	req = httptest.NewRequest(http.MethodGet, "/films", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	rec = httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("READ failed with real DB: expected 200, got %d", rec.Code)
	}

	var films []map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &films)

	found := false
	for _, f := range films {
		if f["id"] == filmID {
			found = true
			if f["title"] != "Database Test Film" {
				t.Errorf("expected title 'Database Test Film', got %v", f["title"])
			}
			break
		}
	}

	if !found {
		t.Error("created film not found in database")
	}

	// Cleanup - note: in a real test you'd use transactions and rollback
	t.Log("Test completed - you may need to manually cleanup test data")
}

// TestIntegration_AuditLogging tests that audit logs are correctly persisted
func TestIntegration_AuditLogging(t *testing.T) {
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set, skipping audit logging test")
	}

	ctx := context.Background()
	db, err := postgres.NewPool(ctx, dbURL)
	if err != nil {
		t.Fatalf("failed to connect to test database: %v", err)
	}
	defer db.Close()

	cfg := testConfig()
	cfg.DatabaseURL = dbURL

	logger := testLogger()
	server := newServerWithDB(cfg, logger, db)

	adminToken, _ := server.jwtService.GenerateToken(auth.JWTSubject{
		UserID: "audit-test-user", TenantID: "audit-tenant", Username: "admin", Role: "admin",
	})

	// Make a request that should be audited
	req := httptest.NewRequest(http.MethodGet, "/films", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET films failed: expected 200, got %d", rec.Code)
	}

	// Try to read audit logs (admin-only endpoint)
	req = httptest.NewRequest(http.MethodGet, "/audit?limit=10", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	rec = httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET audit logs failed: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var auditLogs []map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &auditLogs)

	// Should have at least one audit log from our GET /films request
	if len(auditLogs) == 0 {
		t.Error("expected audit logs, got 0")
	}

	// Verify audit log contains expected fields
	if len(auditLogs) > 0 {
		log := auditLogs[0]
		if log["action"] == nil {
			t.Error("audit log missing 'action' field")
		}
		if log["subject_id"] == nil {
			t.Error("audit log missing 'subject_id' field")
		}
		if log["decision"] == nil {
			t.Error("audit log missing 'decision' field")
		}
	}
}

// TestIntegration_PerformanceLogging tests that performance metrics are tracked
func TestIntegration_PerformanceLogging(t *testing.T) {
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set, skipping performance logging test")
	}

	ctx := context.Background()
	db, err := postgres.NewPool(ctx, dbURL)
	if err != nil {
		t.Fatalf("failed to connect to test database: %v", err)
	}
	defer db.Close()

	cfg := testConfig()
	cfg.DatabaseURL = dbURL

	logger := testLogger()
	server := newServerWithDB(cfg, logger, db)

	adminToken, _ := server.jwtService.GenerateToken(auth.JWTSubject{
		UserID: "perf-test-user", TenantID: "perf-tenant", Username: "admin", Role: "admin",
	})

	// Make several requests to generate performance data
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/films", nil)
		req.Header.Set("Authorization", "Bearer "+adminToken)
		rec := httptest.NewRecorder()
		server.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("GET films failed on iteration %d: expected 200, got %d", i, rec.Code)
		}
	}

	// Try to read performance stats (admin-only endpoint)
	req := httptest.NewRequest(http.MethodGet, "/perf/stats", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET perf stats failed: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var perfStats map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &perfStats)

	// Verify we got performance statistics
	if perfStats["endpoints"] == nil {
		t.Error("expected 'endpoints' in performance stats")
	}
}

// TestIntegration_ClassificationPersistence tests DB-backed classification store
func TestIntegration_ClassificationPersistence(t *testing.T) {
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set, skipping classification persistence test")
	}

	ctx := context.Background()
	db, err := postgres.NewPool(ctx, dbURL)
	if err != nil {
		t.Fatalf("failed to connect to test database: %v", err)
	}
	defer db.Close()

	cfg := testConfig()
	cfg.DatabaseURL = dbURL

	logger := testLogger()
	server := newServerWithDB(cfg, logger, db)

	// The classification store should be DB-backed
	// Classifications should be loaded from database
	// This is verified by making requests and checking DCS enforcement

	devToken, _ := server.jwtService.GenerateToken(auth.JWTSubject{
		UserID: "u-dev", TenantID: "t1", Username: "dev", Role: "developer",
	})

	req := httptest.NewRequest(http.MethodGet, "/films", nil)
	req.Header.Set("Authorization", "Bearer "+devToken)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET films failed: expected 200, got %d", rec.Code)
	}

	var films []map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &films)

	// If DB classifications are loaded, time_elapsed (SENSITIVE) should be masked for developer
	if len(films) > 0 {
		timeElapsed := films[0]["time_elapsed"]
		if _, ok := timeElapsed.(float64); ok {
			t.Error("developer should see masked time_elapsed when DB classifications are loaded")
		}
	}
}
