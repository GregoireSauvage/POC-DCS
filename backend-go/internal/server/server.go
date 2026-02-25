package server

import (
	"context"
	"fmt"
	"log/slog"

	"golang.org/x/sync/errgroup"

	"github.com/neoweyss/poc-dcs/backend-go/internal/bootstrap"
	"github.com/neoweyss/poc-dcs/backend-go/internal/config"
	"github.com/neoweyss/poc-dcs/backend-go/internal/repository/postgres"
	grpctransport "github.com/neoweyss/poc-dcs/backend-go/internal/transport/grpc"
	httptransport "github.com/neoweyss/poc-dcs/backend-go/internal/transport/http"
)

type App struct {
	cfg        *config.Config
	logger     *slog.Logger
	db         *postgres.Pool
	httpServer *httptransport.Server
	grpcServer *grpctransport.Server
}

func New(cfg *config.Config, logger *slog.Logger) *App {
	ctx := context.Background()

	// Initialize database connection if URL is provided
	var db *postgres.Pool
	if cfg.DatabaseURL != "" {
		logger.Info("connecting to database", slog.String("url", maskDBURL(cfg.DatabaseURL)))
		var err error
		db, err = postgres.NewPool(ctx, cfg.DatabaseURL)
		if err != nil {
			logger.Error("failed to connect to database, falling back to in-memory", slog.String("error", err.Error()))
		} else {
			logger.Info("database connection established")
		}
	} else {
		logger.Warn("no DATABASE_URL provided, using in-memory repository")
	}

	// Build HTTP dependencies using composition root
	httpDeps := bootstrap.BuildHTTPDependencies(ctx, cfg, logger.With(slog.String("transport", "http")), db)

	return &App{
		cfg:        cfg,
		logger:     logger,
		db:         db,
		httpServer: httptransport.NewServer(httpDeps),
		grpcServer: grpctransport.NewServer(cfg, logger.With(slog.String("transport", "grpc"))),
	}
}

// maskDBURL masks the password in database URL for logging
func maskDBURL(url string) string {
	// Simple masking: postgresql://user:PASSWORD@host/db -> postgresql://user:***@host/db
	return fmt.Sprintf("%s (password masked)", url[:20]+"***")
}

func (a *App) Run(ctx context.Context) error {
	a.logger.Info("starting application",
		slog.String("service", a.cfg.Service),
		slog.String("env", a.cfg.Env),
		slog.String("http_addr", a.cfg.HTTPAddr),
		slog.String("grpc_addr", a.cfg.GRPCAddr),
	)

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		return a.grpcServer.Start(ctx)
	})

	g.Go(func() error {
		return a.httpServer.Start(ctx)
	})

	// Wait for all servers or context cancellation
	err := g.Wait()

	// Cleanup
	a.logger.Info("shutting down application")
	if a.db != nil {
		a.logger.Info("closing database connection")
		a.db.Close()
	}

	return err
}
