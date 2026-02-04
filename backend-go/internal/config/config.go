package config

import (
	"log/slog"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Env         string
	Service     string
	HTTPAddr    string
	GRPCAddr    string
	LogLevel    slog.Level
	EnablePprof bool
}

func Load() *Config {
	return &Config{
		Env:         getenv("ENV", "dev"),
		Service:     getenv("SERVICE_NAME", "cinema-dcs-backend-go"),
		HTTPAddr:    getenv("HTTP_ADDR", ":8001"),
		GRPCAddr:    getenv("GRPC_ADDR", ":50051"),
		LogLevel:    parseLogLevel(getenv("LOG_LEVEL", "INFO")),
		EnablePprof: parseBool(getenv("ENABLE_PPROF", "false")),
	}
}

func getenv(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func parseBool(raw string) bool {
	v, err := strconv.ParseBool(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	return v
}

func parseLogLevel(raw string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
