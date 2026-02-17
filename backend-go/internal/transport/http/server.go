package http

import (
	"context"
	"errors"
	"log/slog"
	nethttp "net/http"
	"time"

	"github.com/neoweyss/poc-dcs/backend-go/internal/auth"
	"github.com/neoweyss/poc-dcs/backend-go/internal/config"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/cache"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/enforcer"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/kms"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/pdp"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/pep"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/pip"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/runtime"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/types"
	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
	"github.com/neoweyss/poc-dcs/backend-go/internal/repository/memory"
	"github.com/neoweyss/poc-dcs/backend-go/internal/repository/postgres"
	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

type Server struct {
	cfg              *config.Config
	logger           *slog.Logger
	server           *nethttp.Server
	mux              *nethttp.ServeMux
	runtime          *runtime.Settings
	cache            *cache.Manager
	enforcer         service.PolicyEnforcer
	filmFlow         *service.FilmService
	hallService      service.HallService
	spectatorService *service.SpectatorService
	authService      *service.AuthService
	auditService     *service.AuditService
	perfService      service.PerfService
	jwtService       *auth.JWTService
}

func NewServer(cfg *config.Config, logger *slog.Logger, db *postgres.Pool) *Server {
	rt := runtime.New(cfg.DCSMode, cfg.CacheLevel)
	cm := cache.NewManager(rt, cache.Options{
		MaxEntries:        cfg.CacheMaxEntries,
		ClassificationTTL: cfg.CacheTTLClassif,
		PDPTTL:            cfg.CacheTTLPDP,
		KMSTTL:            cfg.CacheTTLKMS,
		PepperTTL:         cfg.CacheTTLPepper,
	})

	// Create KMS client (Vault Transit if configured, otherwise local mock)
	var kmsClient service.KMS
	if cfg.VaultAddr != "" && cfg.VaultToken != "" {
		logger.Info("using Vault Transit KMS")
		vaultClient, err := kms.NewVaultTransitClient(
			cfg.VaultAddr,
			cfg.VaultToken,
			cfg.VaultTransitKey,
			cm,
			logger.With(slog.String("component", "vault")),
		)
		if err != nil {
			logger.Error("failed to create vault client, falling back to local KMS", slog.String("error", err.Error()))
			kmsClient = kms.NewLocalClient()
		} else {
			kmsClient = vaultClient
		}
	} else {
		logger.Warn("no Vault config provided, using local mock KMS (NOT SECURE)")
		kmsClient = kms.NewLocalClient()
	}

	// Create film repository (PostgreSQL if DB available, otherwise in-memory)
	var filmRepo service.FilmRepository
	if db != nil {
		logger.Info("using PostgreSQL film repository")
		filmRepo = postgres.NewFilmRepository(db)
	} else {
		logger.Warn("using in-memory film repository (for development only)")
		seedCT, err := kmsClient.Encrypt(context.Background(), "120")
		if err != nil {
			seedCT = "120"
		}
		filmRepo = memory.NewFilmRepository([]service.FilmRecord{
			{TenantID: "t1", ID: "film-1", Title: "Interstellar", TimeElapsedCT: seedCT},
		})
	}

	provider := pip.NewProvider(rt, cm, &pip.StaticClassificationStore{
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
	}, pip.Config{
		Env:            cfg.Env,
		Channel:        "web",
		Purpose:        "cinema_ops",
		DeviceTrust:    0.8,
		ClientIPHeader: "x-real-ip",
	})
	engine := pdp.NewEngine(rt, cm)
	filmApplier := pep.NewFilmApplier(rt, kmsClient)
	spectatorApplier := pep.NewSpectatorApplier(kmsClient)
	policyEnforcer := enforcer.New(provider, engine, filmApplier, spectatorApplier, kmsClient)

	// Create audit service if DB available
	var auditService *service.AuditService
	if db != nil {
		auditRepo := postgres.NewAuditLogRepository(db)
		auditService = service.NewAuditService(
			auditRepo,
			policyEnforcer,
			logger.With(slog.String("component", "audit")),
		)
		logger.Info("audit logging enabled")
	} else {
		logger.Warn("audit logging disabled (no database)")
	}

	// Create perf service if DB available
	var perfSvc service.PerfService
	if db != nil {
		perfRepo := postgres.NewPerfLogRepository(db)
		perfSvc = service.NewPerfService(perfRepo, policyEnforcer, cfg.PerfSource)
		logger.Info("performance logging enabled")
	} else {
		logger.Warn("performance logging disabled (no database)")
	}

	filmFlow := service.NewFilmService(filmRepo, policyEnforcer, kmsClient, auditService, perfSvc, rt)

	// Create hall repository (PostgreSQL if DB available, otherwise in-memory)
	var hallRepo service.HallRepository
	if db != nil {
		logger.Info("using PostgreSQL hall repository")
		hallRepo = postgres.NewHallRepository(db)
	} else {
		logger.Warn("using in-memory hall repository (for development only)")
		hallRepo = memory.NewHallRepository([]domain.Hall{
			{TenantID: "t1", ID: "hall-1", Name: "Hall A", OwnerUserID: "u-admin", CurrentFilmID: "film-1"},
		})
	}

	hallService := service.NewHallService(hallRepo, policyEnforcer, auditService, perfSvc, rt)

	// Create spectator repository (PostgreSQL if DB available, otherwise in-memory)
	var spectatorRepo service.SpectatorRepository
	if db != nil {
		logger.Info("using PostgreSQL spectator repository")
		spectatorRepo = postgres.NewSpectatorRepository(db)
	} else {
		logger.Warn("using in-memory spectator repository (for development only)")
		spectatorRepo = memory.NewSpectatorRepository()
	}
	spectatorService := service.NewSpectatorService(
		spectatorRepo,
		hallRepo,
		kmsClient,
		policyEnforcer,
		auditService,
		perfSvc,
		rt,
		cfg.VaultKVPepperPath,
	)

	// Create JWT service
	jwtSvc := auth.NewJWTService(cfg.JWTSecret, cfg.JWTIssuer, cfg.JWTAudience, cfg.JWTTTLMin)

	// Create auth service if DB available
	var authSvc *service.AuthService
	if db != nil {
		userRepo := postgres.NewUserRepository(db)
		authSvc = service.NewAuthService(userRepo, jwtSvc)
		logger.Info("authentication service enabled")
	} else {
		logger.Warn("authentication service disabled (no database)")
	}

	mux := nethttp.NewServeMux()

	s := &Server{
		cfg:              cfg,
		logger:           logger,
		mux:              mux,
		runtime:          rt,
		cache:            cm,
		enforcer:         policyEnforcer,
		filmFlow:         filmFlow,
		hallService:      hallService,
		spectatorService: spectatorService,
		authService:      authSvc,
		auditService:     auditService,
		perfService:      perfSvc,
		jwtService:       jwtSvc,
		server: &nethttp.Server{
			Addr:              cfg.HTTPAddr,
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
		},
	}
	s.registerRoutes()
	return s
}

func (s *Server) Handler() nethttp.Handler {
	return s.mux
}

func (s *Server) registerRoutes() {
	s.mux.HandleFunc("/health", func(w nethttp.ResponseWriter, _ *nethttp.Request) {
		writeJSON(w, nethttp.StatusOK, map[string]interface{}{"status": "ok", "service": "backend-go"})
	})
	s.mux.HandleFunc("/ready", func(w nethttp.ResponseWriter, _ *nethttp.Request) {
		writeJSON(w, nethttp.StatusOK, map[string]interface{}{"ready": true})
	})

	// Auth routes (no JWT required)
	s.mux.HandleFunc("/auth/login", s.handleLogin)

	// Admin routes (strict JWT + admin role required)
	s.mux.Handle("/admin/settings", s.adminMiddleware(nethttp.HandlerFunc(s.handleAdminSettings)))
	s.mux.Handle("/audit", s.adminMiddleware(nethttp.HandlerFunc(s.handleAudit)))
	s.mux.Handle("/audit/", s.adminMiddleware(nethttp.HandlerFunc(s.handleAudit))) // Trailing slash variant
	s.mux.Handle("/perf", s.adminMiddleware(nethttp.HandlerFunc(s.handlePerf)))
	s.mux.Handle("/perf/", s.adminMiddleware(nethttp.HandlerFunc(s.handlePerf))) // Trailing slash variant
	s.mux.Handle("/perf/summary", s.adminMiddleware(nethttp.HandlerFunc(s.handlePerfSummary)))

	// Protected routes (optional JWT - fallback to X-headers for dev)
	s.mux.Handle("/films", s.optionalJWTMiddleware(nethttp.HandlerFunc(s.handleFilms)))
	s.mux.Handle("/films/", s.optionalJWTMiddleware(nethttp.HandlerFunc(s.handleFilmSubroutes)))
	s.mux.Handle("/halls", s.optionalJWTMiddleware(nethttp.HandlerFunc(s.handleHalls)))
	s.mux.Handle("/halls/", s.optionalJWTMiddleware(nethttp.HandlerFunc(s.handleHalls))) // Trailing slash variant
	s.mux.Handle("/spectators", s.optionalJWTMiddleware(nethttp.HandlerFunc(s.handleSpectators)))
	s.mux.Handle("/spectators/", s.optionalJWTMiddleware(nethttp.HandlerFunc(s.handleSpectators))) // Trailing slash variant
	s.mux.Handle("/spectators/search", s.optionalJWTMiddleware(nethttp.HandlerFunc(s.handleSearchSpectators)))
}

func (s *Server) Start(ctx context.Context) error {
	errCh := make(chan error, 1)

	go func() {
		s.logger.Info("http server listening", slog.String("addr", s.cfg.HTTPAddr))
		err := s.server.ListenAndServe()
		if err != nil && !errors.Is(err, nethttp.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.logger.Info("http server shutting down")
		_ = s.server.Shutdown(shutdownCtx)
		return nil
	case err := <-errCh:
		return err
	}
}
