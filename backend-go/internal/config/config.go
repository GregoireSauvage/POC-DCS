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

	// Database
	DatabaseURL string

	// Vault
	VaultAddr          string
	VaultToken         string
	VaultTransitKey    string
	VaultKVPepperPath  string

	// JWT
	JWTSecret   string
	JWTIssuer   string
	JWTAudience string
	JWTTTLMin   int

	// DCS
	DCSMode       string
	DCSConfigPath string
	CacheLevel    int

	// Perf
	PerfSource string

	// Cache
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

		// Database
		DatabaseURL: getenv("DATABASE_URL", ""),

		// Vault
		VaultAddr:         getenv("VAULT_ADDR", "http://localhost:8200"),
		VaultToken:        getenv("VAULT_TOKEN", ""),
		VaultTransitKey:   getenv("VAULT_TRANSIT_KEY", "cinema-dcs"),
		VaultKVPepperPath: getenv("VAULT_KV_PEPPER_PATH", "secret/dcs"),

		// JWT
		JWTSecret:   getenv("JWT_SECRET", "dev-secret-change-me"),
		JWTIssuer:   getenv("JWT_ISSUER", "cinema-dcs-poc"),
		JWTAudience: getenv("JWT_AUDIENCE", "cinema-ui"),
		JWTTTLMin:   parseInt(getenv("JWT_TTL_MINUTES", "240"), 240),

		// DCS
		DCSMode:       getenv("DCS_MODE", "on"),
		DCSConfigPath: getenv("DCS_CONFIG_PATH", ""),
		CacheLevel:    parseInt(getenv("CACHE_LEVEL", "1"), 1),

		// Perf
		PerfSource: getenv("PERF_SOURCE", "go"),

		// Cache
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
