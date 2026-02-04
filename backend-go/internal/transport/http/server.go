package http

import (
	"context"
	"errors"
	"log/slog"
	nethttp "net/http"
	"time"

	"github.com/neoweyss/poc-dcs/backend-go/internal/config"
)

type Server struct {
	cfg    *config.Config
	logger *slog.Logger
	server *nethttp.Server
}

func NewServer(cfg *config.Config, logger *slog.Logger) *Server {
	mux := nethttp.NewServeMux()
	mux.HandleFunc("/health", func(w nethttp.ResponseWriter, _ *nethttp.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(nethttp.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","service":"backend-go"}`))
	})
	mux.HandleFunc("/ready", func(w nethttp.ResponseWriter, _ *nethttp.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(nethttp.StatusOK)
		_, _ = w.Write([]byte(`{"ready":true}`))
	})

	return &Server{
		cfg:    cfg,
		logger: logger,
		server: &nethttp.Server{
			Addr:              cfg.HTTPAddr,
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
		},
	}
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
