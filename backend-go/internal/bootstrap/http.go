package bootstrap

import (
	"context"
	"log/slog"

	"github.com/neoweyss/poc-dcs/backend-go/internal/auth"
	"github.com/neoweyss/poc-dcs/backend-go/internal/config"
	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
	infrabinding "github.com/neoweyss/poc-dcs/backend-go/internal/infra/binding"
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

	_ = ctx
	infra := setupInfrastructure(cfg, logger, db)
	dcs := setupDCS(cfg, logger, infra)
	repos := setupRepositories(logger, db, infra.KMS)
	services := setupServices(cfg, logger, repos, dcs, infra)

	logger.Info("HTTP server dependencies built successfully")

	return httptransport.Dependencies{
		Config:           cfg,
		Logger:           logger,
		Runtime:          infra.Runtime,
		Cache:            infra.Cache,
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
	Runtime        *config.DCSRuntime
	Cache          *infracache.Manager
	KMS            service.CryptoProvider
	DCSConfig      *config.DCSConfig
	PolicyProvider spif.Provider
	BindingManager *infrabinding.Manager
}

// DCSComponents holds the canonical DCS runtime pieces.
type DCSComponents struct {
	Authorizer service.Authorizer
}

// Repositories holds all data access repositories
type Repositories struct {
	Film           service.FilmRepository
	Hall           service.HallRepository
	Spectator      service.SpectatorRepository
	User           repository.UserRepository
	Audit          repository.AuditLogRepository
	Perf           repository.PerfLogRepository
	Classification service.ClassificationMetadataReader
	Binding        service.BindingStore
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
		slog.String("dcs_mode", cfg.DCSMode),
		slog.Int("cache_level", rt.CacheLevel()),
		slog.String("policy_id", dcsConfig.Policy.PolicyID),
		slog.String("policy_version", dcsConfig.Policy.PolicyVersion),
		slog.Bool("dcs_enabled", rt.DcsEnabled()),
	)

	cm := infracache.NewManager(rt, infracache.Options{
		MaxEntries:        cfg.CacheMaxEntries,
		ClassificationTTL: cfg.CacheTTLClassif,
		PDPTTL:            cfg.CacheTTLPDP,
		KMSTTL:            cfg.CacheTTLKMS,
		PepperTTL:         cfg.CacheTTLPepper,
	})
	logger.Info("cache manager initialized")

	var kmsClient service.CryptoProvider
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

	if cfg.DCSBindingHMACKey == "" {
		logger.Error("DCS_BINDING_HMAC_KEY is required for binding enforcement")
		panic("missing DCS_BINDING_HMAC_KEY")
	}

	bindingManager := infrabinding.NewManager(infrabinding.Config{
		ProfileID:      dcsConfig.Binding.ProfileID,
		ProofAlgorithm: dcsConfig.Binding.ProofAlgorithm,
		KeyID:          dcsConfig.Binding.KeyID,
		Secret:         []byte(cfg.DCSBindingHMACKey),
	})

	if db != nil {
		logger.Info("classification metadata will be loaded from database")
	} else {
		logger.Warn("classification metadata will use static fallback (no database)")
	}

	return Infrastructure{
		Runtime:        rt,
		Cache:          cm,
		KMS:            kmsClient,
		DCSConfig:      dcsConfig,
		PolicyProvider: spif.NewStaticProvider(dcsConfig.Policy),
		BindingManager: bindingManager,
	}
}

func setupDCS(cfg *config.Config, logger *slog.Logger, infra Infrastructure) DCSComponents {
	_ = cfg
	policy := config.NewClassificationPolicy(infra.DCSConfig)
	pdpAuthorizer := serviceauth.NewPDP(policy)
	baseAuthorizer := serviceauth.NewAuthorizer(infra.Runtime, pdpAuthorizer)
	cachedAuthorizer := serviceauth.NewCachedAuthorizer(infra.Runtime, policy, infra.Cache.PDP, baseAuthorizer)
	logger.Info("authorization stack initialized")
	return DCSComponents{Authorizer: cachedAuthorizer}
}

func setupRepositories(logger *slog.Logger, db *postgres.Pool, kmsClient service.CryptoProvider) Repositories {
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
		repos.Binding = postgres.NewBindingRepository(db)
		logger.Info("PostgreSQL repositories initialized", slog.Int("count", 8))
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
		repos.Binding = memory.NewBindingRepository()
		logger.Info("in-memory repositories initialized", slog.Int("count", 4), slog.String("note", "User/Audit/Perf disabled"))
	}

	return repos
}

func setupServices(cfg *config.Config, logger *slog.Logger, repos Repositories, dcs DCSComponents, infra Infrastructure) Services {
	var services Services
	policy := config.NewClassificationPolicy(infra.DCSConfig)
	classificationReader := repos.Classification
	if classificationReader == nil {
		classificationReader = service.NewStaticClassificationReader(defaultClassificationMetadata())
	}
	labelIssuer := service.NewServerLabelIssuer(policy, classificationReader, defaultResourceMaxClassification())
	bindingDeps := securedrepo.BindingDependencies{
		Store:                repos.Binding,
		Verifier:             infra.BindingManager,
		Issuer:               infra.BindingManager,
		LabelIssuer:          labelIssuer,
		Authorizer:           dcs.Authorizer,
		Crypto:               infra.KMS,
		ClassificationReader: classificationReader,
		Runtime:              infra.Runtime,
	}

	if repos.Audit != nil {
		services.Audit = service.NewAuditService(repos.Audit, dcs.Authorizer, logger.With(slog.String("component", "audit")))
		logger.Info("audit service initialized")
	} else {
		logger.Warn("audit service disabled (no database)")
	}

	if repos.Perf != nil {
		services.Perf = service.NewPerfService(repos.Perf, dcs.Authorizer, cfg.PerfSource)
		logger.Info("performance service initialized")
	} else {
		logger.Warn("performance service disabled (no database)")
	}

	filmRepo := securedrepo.NewFilmRepository(repos.Film, logger.With(slog.String("component", "film_repository")), bindingDeps)
	services.Film = service.NewFilmService(filmRepo, dcs.Authorizer, classificationReader, services.Audit, services.Perf, infra.Runtime)
	logger.Info("film service initialized")

	hallRepo := securedrepo.NewHallRepository(repos.Hall, logger.With(slog.String("component", "hall_repository")), bindingDeps)
	services.Hall = service.NewHallService(hallRepo, dcs.Authorizer, classificationReader, services.Audit, services.Perf, infra.Runtime)
	logger.Info("hall service initialized")

	spectatorRepo := securedrepo.NewSpectatorRepository(repos.Spectator, infra.Runtime, logger.With(slog.String("component", "spectator_repository")), bindingDeps)
	services.Spectator = service.NewSpectatorService(spectatorRepo, repos.Hall, dcs.Authorizer, classificationReader, services.Audit, services.Perf, infra.Runtime)
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

func defaultClassificationMetadata() map[string][]domain.FieldClassification {
	return map[string][]domain.FieldClassification{
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
	}
}

func defaultResourceMaxClassification() map[string]service.Classification {
	return map[string]service.Classification{
		"film":      service.ClassificationSensitive,
		"hall":      service.ClassificationInternal,
		"spectator": service.ClassificationPII,
	}
}
