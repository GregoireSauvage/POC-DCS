package http

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	nethttp "net/http"
	"strconv"
	"strings"
	"time"

	"github.com/neoweyss/poc-dcs/backend-go/internal/config"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/cache"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/kms"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/pdp"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/pep"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/pip"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/runtime"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/types"
	"github.com/neoweyss/poc-dcs/backend-go/internal/observability/perf"
	"github.com/neoweyss/poc-dcs/backend-go/internal/repository/memory"
	"github.com/neoweyss/poc-dcs/backend-go/internal/repository/postgres"
	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

type Server struct {
	cfg      *config.Config
	logger   *slog.Logger
	server   *nethttp.Server
	mux      *nethttp.ServeMux
	runtime  *runtime.Settings
	cache    *cache.Manager
	filmFlow *service.FilmService
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
		},
	}, pip.Config{
		Env:            cfg.Env,
		Channel:        "web",
		Purpose:        "cinema_ops",
		DeviceTrust:    0.8,
		ClientIPHeader: "x-real-ip",
	})
	engine := pdp.NewEngine(rt, cm)
	applier := pep.NewFilmApplier(rt, kmsClient)

	// Create audit service if DB available
	var auditService *service.AuditService
	if db != nil {
		auditRepo := postgres.NewAuditLogRepository(db)
		auditService = service.NewAuditService(auditRepo, logger.With(slog.String("component", "audit")))
		logger.Info("audit logging enabled")
	} else {
		logger.Warn("audit logging disabled (no database)")
	}

	filmFlow := service.NewFilmService(filmRepo, provider, engine, applier, kmsClient, auditService)

	mux := nethttp.NewServeMux()

	s := &Server{
		cfg:      cfg,
		logger:   logger,
		mux:      mux,
		runtime:  rt,
		cache:    cm,
		filmFlow: filmFlow,
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

	s.mux.HandleFunc("/admin/settings", s.handleAdminSettings)
	s.mux.HandleFunc("/films", s.handleFilms)
	s.mux.HandleFunc("/films/", s.handleFilmSubroutes)
}

type adminSettingsUpdate struct {
	DCSMode    *string `json:"dcs_mode"`
	CacheLevel *int    `json:"cache_level"`
}

func (s *Server) handleAdminSettings(w nethttp.ResponseWriter, r *nethttp.Request) {
	switch r.Method {
	case nethttp.MethodGet:
		writeJSON(w, nethttp.StatusOK, map[string]interface{}{
			"dcs_mode":    s.runtime.Mode(),
			"cache_level": s.runtime.CacheLevel(),
		})
		return
	case nethttp.MethodPatch:
		var payload adminSettingsUpdate
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeError(w, nethttp.StatusBadRequest, "invalid JSON body")
			return
		}
		if payload.DCSMode != nil {
			mode := strings.ToLower(strings.TrimSpace(*payload.DCSMode))
			if mode != "on" && mode != "off" {
				writeError(w, nethttp.StatusBadRequest, "dcs_mode must be 'on' or 'off'")
				return
			}
		}
		if payload.CacheLevel != nil && *payload.CacheLevel < 0 {
			writeError(w, nethttp.StatusBadRequest, "cache_level must be >= 0")
			return
		}

		s.runtime.Set(payload.DCSMode, payload.CacheLevel)
		s.cache.ClearAll()
		writeJSON(w, nethttp.StatusOK, map[string]interface{}{
			"dcs_mode":    s.runtime.Mode(),
			"cache_level": s.runtime.CacheLevel(),
		})
		return
	default:
		w.WriteHeader(nethttp.StatusMethodNotAllowed)
		return
	}
}

func (s *Server) handleFilms(w nethttp.ResponseWriter, r *nethttp.Request) {
	if r.Method != nethttp.MethodGet {
		w.WriteHeader(nethttp.StatusMethodNotAllowed)
		return
	}
	principal := principalFromRequest(r)
	reqCtx := requestContextFromRequest(r, s.cfg.Env)

	films, pctx, err := s.filmFlow.List(r.Context(), principal, reqCtx)
	if err != nil {
		writeError(w, nethttp.StatusInternalServerError, err.Error())
		return
	}
	setPerfHeaders(w, pctx)
	writeJSON(w, nethttp.StatusOK, films)
}

func (s *Server) handleFilmSubroutes(w nethttp.ResponseWriter, r *nethttp.Request) {
	if r.Method != nethttp.MethodPatch {
		w.WriteHeader(nethttp.StatusMethodNotAllowed)
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/films/"), "/")
	if len(parts) != 2 || parts[1] != "time" || strings.TrimSpace(parts[0]) == "" {
		writeError(w, nethttp.StatusNotFound, "not found")
		return
	}
	timeElapsedRaw := r.URL.Query().Get("time_elapsed")
	timeElapsed, err := strconv.Atoi(timeElapsedRaw)
	if err != nil || timeElapsed < 0 {
		writeError(w, nethttp.StatusBadRequest, "time_elapsed must be a non-negative integer")
		return
	}

	principal := principalFromRequest(r)
	reqCtx := requestContextFromRequest(r, s.cfg.Env)
	film, pctx, err := s.filmFlow.UpdateTime(r.Context(), principal, reqCtx, parts[0], timeElapsed)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrForbidden):
			writeError(w, nethttp.StatusForbidden, "forbidden")
		case errors.Is(err, service.ErrNotFound):
			writeError(w, nethttp.StatusNotFound, "film not found")
		default:
			writeError(w, nethttp.StatusInternalServerError, err.Error())
		}
		return
	}
	setPerfHeaders(w, pctx)
	writeJSON(w, nethttp.StatusOK, film)
}

func principalFromRequest(r *nethttp.Request) types.Principal {
	return types.Principal{
		TenantID: readHeaderOrDefault(r, "X-Tenant-ID", "t1"),
		UserID:   readHeaderOrDefault(r, "X-User-ID", "u-dev"),
		Username: readHeaderOrDefault(r, "X-Username", "dev"),
		Role:     readHeaderOrDefault(r, "X-Role", "developer"),
	}
}

func requestContextFromRequest(r *nethttp.Request, env string) types.RequestContext {
	return types.RequestContext{
		RequestID:   readHeaderOrDefault(r, "X-Request-ID", "http-no-request-id"),
		ClientIP:    readHeaderOrDefault(r, "X-Real-IP", r.RemoteAddr),
		Channel:     "web",
		Purpose:     "cinema_ops",
		DeviceTrust: 0.8,
		Env:         env,
	}
}

func readHeaderOrDefault(r *nethttp.Request, key, fallback string) string {
	val := strings.TrimSpace(r.Header.Get(key))
	if val == "" {
		return fallback
	}
	return val
}

func setPerfHeaders(w nethttp.ResponseWriter, pctx *perf.Context) {
	if pctx == nil {
		return
	}
	w.Header().Set("x-perf-total-ms", fmt.Sprintf("%.3f", pctx.TotalMS()))
	for key, value := range pctx.Metrics() {
		w.Header().Set("x-perf-"+strings.ReplaceAll(key, "_", "-"), fmt.Sprintf("%.3f", value))
	}
}

func writeError(w nethttp.ResponseWriter, code int, message string) {
	writeJSON(w, code, map[string]interface{}{"detail": message})
}

func writeJSON(w nethttp.ResponseWriter, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(payload)
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
