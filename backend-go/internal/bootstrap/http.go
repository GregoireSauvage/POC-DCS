package bootstrap

import (
	"context"
	"log/slog"

	"github.com/neoweyss/poc-dcs/backend-go/internal/auth"
	"github.com/neoweyss/poc-dcs/backend-go/internal/config"
	legacycache "github.com/neoweyss/poc-dcs/backend-go/internal/dcs/cache"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/enforcer"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/pep"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/pip"
	legacyruntime "github.com/neoweyss/poc-dcs/backend-go/internal/dcs/runtime"
	legacytypes "github.com/neoweyss/poc-dcs/backend-go/internal/dcs/types"
	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
	infracache "github.com/neoweyss/poc-dcs/backend-go/internal/infra/cache"
	infrakms "github.com/neoweyss/poc-dcs/backend-go/internal/infra/kms"
	"github.com/neoweyss/poc-dcs/backend-go/internal/infra/spif"
	"github.com/neoweyss/poc-dcs/backend-go/internal/repository"
	"github.com/neoweyss/poc-dcs/backend-go/internal/repository/memory"
	"github.com/neoweyss/poc-dcs/backend-go/internal/repository/postgres"
	securedrepo "github.com/neoweyss/poc-dcs/backend-go/internal/repository/postgres/secured"
	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
	serviceauth "github.com/neoweyss/poc-dcs/backend-go/internal/service/authorization"
	httptransport "github.com/neoweyss/poc-dcs/backend-go/internal/transport/http"
)

// BuildHTTPDependencies constructs all dependencies needed by the HTTP server
// This is the main composition root for the HTTP transport layer
func BuildHTTPDependencies(
	ctx context.Context,
	cfg *config.Config,
	logger *slog.Logger,
	db *postgres.Pool,
) httptransport.Dependencies {
	logger.Info("building HTTP server dependencies")

	infra := setupInfrastructure(cfg, logger, db)
	dcs := setupDCS(cfg, logger, infra)
	repos := setupRepositories(logger, db, infra.KMS)
	services := setupServices(cfg, logger, repos, dcs, infra.Runtime)

	logger.Info("HTTP server dependencies built successfully")

	return httptransport.Dependencies{
		Config:           cfg,
		Logger:           logger,
		Runtime:          infra.Runtime,
		Cache:            infra.Cache,
		Enforcer:         dcs.Enforcer,
		FilmService:      services.Film,
		HallService:      services.Hall,
		SpectatorService: services.Spectator,
		AuthService:      services.Auth,
		AuditService:     services.Audit,
		PerfService:      services.Perf,
		JWTService:       services.JWT,
	}
}

// Infrastructure holds the core infrastructure components
type Infrastructure struct {
	Runtime             *config.DCSRuntime
	Cache               *infracache.Manager
	KMS                 enforcer.CryptoService
	DCSConfig           *config.DCSConfig
	PolicyProvider      spif.Provider
	ClassificationStore pip.ClassificationStore
}

// DCSComponents holds all components of the DCS pipeline
type DCSComponents struct {
	Provider         *pip.Provider
	Authorizer       service.Authorizer
	FilmApplier      *pep.FilmApplier
	SpectatorApplier *pep.SpectatorApplier
	Enforcer         *enforcer.DcsEnforcer
}

// Repositories holds all data access repositories
type Repositories struct {
	Film           service.FilmRepository
	Hall           service.HallRepository
	Spectator      service.SpectatorRepository
	User           repository.UserRepository
	Audit          repository.AuditLogRepository
	Perf           repository.PerfLogRepository
	Classification pip.ClassificationRepository
}

// Services holds all business logic services
type Services struct {
	Film      *service.FilmService
	Hall      service.HallService
	Spectator *service.SpectatorService
	Auth      *service.AuthService
	Audit     *service.AuditService
	Perf      service.PerfService
	JWT       *auth.JWTService
}

// setupInfrastructure constructs all infrastructure components
func setupInfrastructure(cfg *config.Config, logger *slog.Logger, db *postgres.Pool) Infrastructure {
	var dcsConfig *config.DCSConfig
	if cfg.DCSConfigPath != "" {
		loaded, err := config.LoadDCSConfig(cfg.DCSConfigPath)
		if err != nil {
			logger.Warn("failed to load DCS config, using defaults", "path", cfg.DCSConfigPath, "error", err)
			dcsConfig = config.DefaultDCSConfig()
		} else {
			dcsConfig = loaded
			logger.Info("loaded DCS config from file", "path", cfg.DCSConfigPath)
		}
	} else {
		logger.Warn("DCS_CONFIG_PATH not set, using hardcoded defaults")
		dcsConfig = config.DefaultDCSConfig()
	}

	rt := config.NewDCSRuntime(cfg.DCSMode, cfg.CacheLevel)
	logger.Info("runtime settings initialized",
		slog.Bool("dcs_enabled", rt.DcsEnabled()),
		slog.Int("cache_level", rt.CacheLevel()),
	)

	cm := infracache.NewManager(rt, infracache.Options{
		MaxEntries:        cfg.CacheMaxEntries,
		ClassificationTTL: cfg.CacheTTLClassif,
		PDPTTL:            cfg.CacheTTLPDP,
		KMSTTL:            cfg.CacheTTLKMS,
		PepperTTL:         cfg.CacheTTLPepper,
	})
	logger.Info("cache manager initialized")

	var kmsClient enforcer.CryptoService
	if cfg.VaultAddr != "" && cfg.VaultToken != "" {
		logger.Info("using Vault Transit KMS")
		vaultClient, err := infrakms.NewVaultTransitClient(
			cfg.VaultAddr,
			cfg.VaultToken,
			cfg.VaultTransitKey,
			cm,
			logger.With(slog.String("component", "vault")),
		)
		if err != nil {
			logger.Error("failed to create vault client, falling back to local KMS", slog.String("error", err.Error()))
			kmsClient = infrakms.NewLocalClient()
		} else {
			kmsClient = vaultClient
		}
	} else {
		logger.Warn("no Vault config provided, using local mock KMS (NOT SECURE)")
		kmsClient = infrakms.NewLocalClient()
	}

	staticStore := &pip.StaticClassificationStore{
		ByResource: map[string]map[string]legacytypes.Classification{
			"film": {
				"title":        legacytypes.ClassificationPublic,
				"time_elapsed": legacytypes.ClassificationSensitive,
			},
			"hall": {
				"name":            legacytypes.ClassificationPublic,
				"owner_user_id":   legacytypes.ClassificationInternal,
				"current_film_id": legacytypes.ClassificationInternal,
			},
			"spectator": {
				"name":        legacytypes.ClassificationPII,
				"age":         legacytypes.ClassificationSensitive,
				"external_id": legacytypes.ClassificationPII,
			},
		},
	}

	var classificationStore pip.ClassificationStore
	if db != nil {
		classificationRepo := postgres.NewClassificationRepository(db)
		classificationStore = pip.NewDBClassificationStore(classificationRepo, staticStore)
		logger.Info("using DB-backed classification store with static fallback")
	} else {
		classificationStore = staticStore
		logger.Warn("using static classification store (no database)")
	}

	return Infrastructure{
		Runtime:             rt,
		Cache:               cm,
		KMS:                 kmsClient,
		DCSConfig:           dcsConfig,
		ClassificationStore: classificationStore,
		PolicyProvider:      spif.NewStaticProvider(dcsConfig.Policy),
	}
}

// setupDCS constructs the DCS pipeline
func setupDCS(cfg *config.Config, logger *slog.Logger, infra Infrastructure) DCSComponents {
	legacyRT := legacyruntime.Wrap(infra.Runtime)
	legacyCache := legacycache.NewManager(legacyRT, legacycache.Options{
		MaxEntries:        cfg.CacheMaxEntries,
		ClassificationTTL: cfg.CacheTTLClassif,
		PDPTTL:            cfg.CacheTTLPDP,
		KMSTTL:            cfg.CacheTTLKMS,
		PepperTTL:         cfg.CacheTTLPepper,
	})

	provider := pip.NewProvider(legacyRT, legacyCache, infra.ClassificationStore, pip.Config{
		Env:            cfg.Env,
		Channel:        infra.DCSConfig.PIP.Channel,
		Purpose:        infra.DCSConfig.PIP.Purpose,
		DeviceTrust:    infra.DCSConfig.PIP.DeviceTrust,
		ClientIPHeader: infra.DCSConfig.PIP.ClientIPHeader,
	})
	logger.Info("PIP provider initialized")

	policy := config.NewClassificationPolicy(infra.DCSConfig)
	pdpAuthorizer := serviceauth.NewPDP(policy)
	baseAuthorizer := serviceauth.NewAuthorizer(infra.Runtime, pdpAuthorizer)
	cachedAuthorizer := serviceauth.NewCachedAuthorizer(infra.Runtime, policy, infra.Cache.PDP, baseAuthorizer)
	logger.Info("authorization stack initialized")

	filmApplier := pep.NewFilmApplier(legacyRT, infra.KMS)
	spectatorApplier := pep.NewSpectatorApplier(infra.KMS)
	logger.Info("PEP appliers initialized", slog.String("appliers", "Film, Spectator"))

	dcsEnforcer := enforcer.New(provider, cachedAuthorizer, filmApplier, spectatorApplier, infra.KMS, cfg.VaultKVPepperPath)
	logger.Info("DCS enforcer initialized")

	return DCSComponents{
		Provider:         provider,
		Authorizer:       cachedAuthorizer,
		FilmApplier:      filmApplier,
		SpectatorApplier: spectatorApplier,
		Enforcer:         dcsEnforcer,
	}
}

// setupRepositories initializes all repositories
func setupRepositories(logger *slog.Logger, db *postgres.Pool, kmsClient enforcer.CryptoService) Repositories {
	var repos Repositories

	if db != nil {
		logger.Info("using PostgreSQL repositories")
		repos.Film = postgres.NewFilmRepository(db)
		repos.Hall = postgres.NewHallRepository(db)
		repos.Spectator = postgres.NewSpectatorRepository(db)
		repos.User = postgres.NewUserRepository(db)
		repos.Audit = postgres.NewAuditLogRepository(db)
		repos.Perf = postgres.NewPerfLogRepository(db)
		repos.Classification = postgres.NewClassificationRepository(db)
		logger.Info("PostgreSQL repositories initialized", slog.Int("count", 7))
	} else {
		logger.Warn("using in-memory repositories (data will be lost on restart)")
		seedCT, _ := kmsClient.Encrypt(context.Background(), "120")
		if seedCT == "" {
			seedCT = "120"
		}
		repos.Film = memory.NewFilmRepository([]service.FilmRecord{{TenantID: "t1", ID: "film-1", Title: "Interstellar", TimeElapsedCT: seedCT}})
		repos.Hall = memory.NewHallRepository([]domain.Hall{{TenantID: "t1", ID: "hall-1", Name: "Hall A", OwnerUserID: "u-admin", CurrentFilmID: "film-1"}})
		repos.Spectator = memory.NewSpectatorRepository()
		repos.User = nil
		repos.Audit = nil
		repos.Perf = nil
		repos.Classification = nil
		logger.Info("in-memory repositories initialized", slog.Int("count", 3), slog.String("note", "User/Audit/Perf disabled"))
	}

	return repos
}

// setupServices initializes all business logic services
func setupServices(cfg *config.Config, logger *slog.Logger, repos Repositories, dcs DCSComponents, rt *config.DCSRuntime) Services {
	var services Services

	if repos.Audit != nil {
		services.Audit = service.NewAuditService(repos.Audit, dcs.Enforcer, logger.With(slog.String("component", "audit")))
		logger.Info("audit service initialized")
	} else {
		logger.Warn("audit service disabled (no database)")
	}

	if repos.Perf != nil {
		services.Perf = service.NewPerfService(repos.Perf, dcs.Enforcer, cfg.PerfSource)
		logger.Info("performance service initialized")
	} else {
		logger.Warn("performance service disabled (no database)")
	}

	filmSecureRepo := securedrepo.NewFilmRepository(repos.Film, dcs.Enforcer, logger.With(slog.String("component", "secured_film_repository")))
	services.Film = service.NewFilmService(filmSecureRepo, dcs.Enforcer, services.Audit, services.Perf, rt)
	logger.Info("film service initialized")

	hallSecureRepo := securedrepo.NewHallRepository(repos.Hall, dcs.Enforcer, logger.With(slog.String("component", "secured_hall_repository")))
	services.Hall = service.NewHallServiceWithSecureRepo(repos.Hall, hallSecureRepo, dcs.Enforcer, services.Audit, services.Perf, rt)
	logger.Info("hall service initialized")

	spectatorSecureRepo := securedrepo.NewSpectatorRepository(repos.Spectator, dcs.Enforcer, rt, logger.With(slog.String("component", "secured_spectator_repository")))
	services.Spectator = service.NewSpectatorServiceWithSecureRepo(repos.Spectator, spectatorSecureRepo, repos.Hall, dcs.Enforcer, services.Audit, services.Perf, rt)
	logger.Info("spectator service initialized")

	services.JWT = auth.NewJWTService(cfg.JWTSecret, cfg.JWTIssuer, cfg.JWTAudience, cfg.JWTTTLMin)
	logger.Info("JWT service initialized", slog.Int("ttl_minutes", cfg.JWTTTLMin))

	if repos.User != nil {
		services.Auth = service.NewAuthService(repos.User, services.JWT)
		logger.Info("auth service initialized")
	} else {
		logger.Warn("auth service disabled (no database)")
	}

	return services
}
