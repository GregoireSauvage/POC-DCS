package server

import (
	"context"
	"log/slog"

	"golang.org/x/sync/errgroup"

	"github.com/neoweyss/poc-dcs/backend-go/internal/config"
	grpctransport "github.com/neoweyss/poc-dcs/backend-go/internal/transport/grpc"
	httptransport "github.com/neoweyss/poc-dcs/backend-go/internal/transport/http"
)

type App struct {
	cfg        *config.Config
	logger     *slog.Logger
	httpServer *httptransport.Server
	grpcServer *grpctransport.Server
}

func New(cfg *config.Config, logger *slog.Logger) *App {
	return &App{
		cfg:        cfg,
		logger:     logger,
		httpServer: httptransport.NewServer(cfg, logger.With(slog.String("transport", "http"))),
		grpcServer: grpctransport.NewServer(cfg, logger.With(slog.String("transport", "grpc"))),
	}
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

	return g.Wait()
}
