package http

import (
	"context"
	"errors"
	"log/slog"
	nethttp "net/http"
	"time"

	"github.com/neoweyss/poc-dcs/backend-go/internal/auth"
	"github.com/neoweyss/poc-dcs/backend-go/internal/config"
	"github.com/neoweyss/poc-dcs/backend-go/internal/infra/cache"
	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

type Server struct {
	cfg              *config.Config
	logger           *slog.Logger
	server           *nethttp.Server
	mux              *nethttp.ServeMux
	runtime          *config.DCSRuntime
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

// NewServer creates a new HTTP server with pre-constructed dependencies (Composition Root Pattern)
// This is the primary constructor - all dependencies must be built externally and passed in
func NewServer(deps Dependencies) *Server {
	mux := nethttp.NewServeMux()

	s := &Server{
		cfg:              deps.Config,
		logger:           deps.Logger,
		mux:              mux,
		runtime:          deps.Runtime,
		cache:            deps.Cache,
		enforcer:         deps.Enforcer,
		filmFlow:         deps.FilmService,
		hallService:      deps.HallService,
		spectatorService: deps.SpectatorService,
		authService:      deps.AuthService,
		auditService:     deps.AuditService,
		perfService:      deps.PerfService,
		jwtService:       deps.JWTService,
		server: &nethttp.Server{
			Addr:              deps.Config.HTTPAddr,
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
	s.mux.Handle("/admin/settings", s.adminMiddleware(s.accessContextMiddleware(nethttp.HandlerFunc(s.handleAdminSettings))))
	s.mux.Handle("/audit", s.adminMiddleware(s.accessContextMiddleware(nethttp.HandlerFunc(s.handleAudit))))
	s.mux.Handle("/audit/", s.adminMiddleware(s.accessContextMiddleware(nethttp.HandlerFunc(s.handleAudit)))) // Trailing slash variant
	s.mux.Handle("/perf", s.adminMiddleware(s.accessContextMiddleware(nethttp.HandlerFunc(s.handlePerf))))
	s.mux.Handle("/perf/", s.adminMiddleware(s.accessContextMiddleware(nethttp.HandlerFunc(s.handlePerf)))) // Trailing slash variant
	s.mux.Handle("/perf/summary", s.adminMiddleware(s.accessContextMiddleware(nethttp.HandlerFunc(s.handlePerfSummary))))

	// Protected routes (optional JWT - fallback to X-headers for dev)
	s.mux.Handle("/films", s.optionalJWTMiddleware(s.accessContextMiddleware(nethttp.HandlerFunc(s.handleFilms))))
	s.mux.Handle("/films/", s.optionalJWTMiddleware(s.accessContextMiddleware(nethttp.HandlerFunc(s.handleFilmSubroutes))))
	s.mux.Handle("/halls", s.optionalJWTMiddleware(s.accessContextMiddleware(nethttp.HandlerFunc(s.handleHalls))))
	s.mux.Handle("/halls/", s.optionalJWTMiddleware(s.accessContextMiddleware(nethttp.HandlerFunc(s.handleHalls)))) // Trailing slash variant
	s.mux.Handle("/spectators", s.optionalJWTMiddleware(s.accessContextMiddleware(nethttp.HandlerFunc(s.handleSpectators))))
	s.mux.Handle("/spectators/", s.optionalJWTMiddleware(s.accessContextMiddleware(nethttp.HandlerFunc(s.handleSpectators)))) // Trailing slash variant
	s.mux.Handle("/spectators/search", s.optionalJWTMiddleware(s.accessContextMiddleware(nethttp.HandlerFunc(s.handleSearchSpectators))))
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
