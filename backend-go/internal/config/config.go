package config

import (
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Env      string
	Service  string
	HTTPAddr string
	GRPCAddr string
	LogLevel slog.Level

	DCSMode    string
	CacheLevel int

	CacheMaxEntries int
	CacheTTLClassif time.Duration
	CacheTTLPDP     time.Duration
	CacheTTLKMS     time.Duration
	CacheTTLPepper  time.Duration
	EnablePprof     bool
}

func Load() *Config {
	return &Config{
		Env:      getenv("ENV", "dev"),
		Service:  getenv("SERVICE_NAME", "cinema-dcs-backend-go"),
		HTTPAddr: getenv("HTTP_ADDR", ":8001"),
		GRPCAddr: getenv("GRPC_ADDR", ":50051"),
		LogLevel: parseLogLevel(getenv("LOG_LEVEL", "INFO")),

		DCSMode:    getenv("DCS_MODE", "on"),
		CacheLevel: parseInt(getenv("CACHE_LEVEL", "1"), 1),

		CacheMaxEntries: parseInt(getenv("CACHE_MAX_ENTRIES", "500"), 500),
		CacheTTLClassif: parseDurationSeconds(getenv("CACHE_TTL_CLASSIF_SEC", "300"), 300),
		CacheTTLPDP:     parseDurationSeconds(getenv("CACHE_TTL_PDP_SEC", "60"), 60),
		CacheTTLKMS:     parseDurationSeconds(getenv("CACHE_TTL_KMS_SEC", "10"), 10),
		CacheTTLPepper:  parseDurationSeconds(getenv("CACHE_TTL_PEPPER_SEC", "300"), 300),
		EnablePprof:     parseBool(getenv("ENABLE_PPROF", "false")),
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

func parseInt(raw string, fallback int) int {
	v, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return fallback
	}
	return v
}

func parseDurationSeconds(raw string, fallbackSec int) time.Duration {
	v, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || v <= 0 {
		v = fallbackSec
	}
	return time.Duration(v) * time.Second
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
