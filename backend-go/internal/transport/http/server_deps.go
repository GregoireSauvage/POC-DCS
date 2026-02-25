package http

import (
	"log/slog"

	"github.com/neoweyss/poc-dcs/backend-go/internal/auth"
	"github.com/neoweyss/poc-dcs/backend-go/internal/config"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/cache"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/runtime"
	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

// Dependencies defines the contract between the composition root and the HTTP server
// All dependencies must be constructed externally and passed to NewServer()
type Dependencies struct {
	// Core infrastructure
	Config  *config.Config
	Logger  *slog.Logger
	Runtime *runtime.Settings
	Cache   *cache.Manager

	// DCS enforcement
	Enforcer service.PolicyEnforcer

	// Domain services
	FilmService      *service.FilmService
	HallService      service.HallService
	SpectatorService *service.SpectatorService

	// Auth & Audit services (may be nil if DB not available)
	AuthService  *service.AuthService  // nil if no DB
	AuditService *service.AuditService // nil if no DB
	PerfService  service.PerfService   // nil if no DB

	// JWT service (always available)
	JWTService *auth.JWTService
}
