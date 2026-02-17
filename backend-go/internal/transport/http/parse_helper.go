package http

import (
	"errors"
	nethttp "net/http"
	"strconv"
	"strings"
)

func parseLimit(r *nethttp.Request) (int, error) {
	raw := strings.TrimSpace(r.URL.Query().Get("limit"))
	if raw == "" {
		return 200, nil
	}
	val, err := strconv.Atoi(raw)
	if err != nil || val < 1 || val > 1000 {
		return 0, errors.New("invalid limit")
	}
	return val, nil
}

func parseActionParam(r *nethttp.Request) *string {
	raw := strings.TrimSpace(r.URL.Query().Get("action"))
	if raw == "" {
		return nil
	}
	return &raw
}

func parseSourceParam(r *nethttp.Request) *string {
	raw := strings.TrimSpace(r.URL.Query().Get("source"))
	if raw == "" {
		return nil
	}
	return &raw
}

func parseBoolParam(r *nethttp.Request, key string) (bool, error) {
	raw := strings.TrimSpace(r.URL.Query().Get(key))
	if raw == "" {
		return false, nil
	}
	switch strings.ToLower(raw) {
	case "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off":
		return false, nil
	default:
		return false, errors.New("invalid boolean")
	}
}
