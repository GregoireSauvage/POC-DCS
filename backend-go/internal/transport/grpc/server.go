package grpc

import (
	"context"
	"errors"
	"log/slog"
	"net"

	"github.com/neoweyss/poc-dcs/backend-go/internal/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	grpc_health_v1 "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
)

type Server struct {
	cfg         *config.Config
	logger      *slog.Logger
	server      *grpc.Server
	healthCheck *health.Server
}

func NewServer(cfg *config.Config, logger *slog.Logger) *Server {
	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			unaryRequestIDInterceptor(),
		),
	)

	healthCheck := health.NewServer()
	grpc_health_v1.RegisterHealthServer(grpcServer, healthCheck)
	reflection.Register(grpcServer)

	return &Server{
		cfg:         cfg,
		logger:      logger,
		server:      grpcServer,
		healthCheck: healthCheck,
	}
}

func (s *Server) Start(ctx context.Context) error {
	lis, err := net.Listen("tcp", s.cfg.GRPCAddr)
	if err != nil {
		return err
	}

	s.healthCheck.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)

	errCh := make(chan error, 1)
	go func() {
		s.logger.Info("grpc server listening", slog.String("addr", s.cfg.GRPCAddr))
		if serveErr := s.server.Serve(lis); serveErr != nil && !errors.Is(serveErr, grpc.ErrServerStopped) {
			errCh <- serveErr
			return
		}
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		s.logger.Info("grpc server shutting down")
		s.healthCheck.SetServingStatus("", grpc_health_v1.HealthCheckResponse_NOT_SERVING)
		s.server.GracefulStop()
		return nil
	case serveErr := <-errCh:
		return serveErr
	}
}
