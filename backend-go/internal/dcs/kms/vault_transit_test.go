package kms

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/cache"
	"github.com/neoweyss/poc-dcs/backend-go/internal/dcs/runtime"
)

func newCacheManagerForTest(cacheLevel int) *cache.Manager {
	rt := runtime.New("on", cacheLevel)
	return cache.NewManager(rt, cache.Options{
		MaxEntries:        100,
		ClassificationTTL: time.Minute,
		PDPTTL:            time.Minute,
		KMSTTL:            time.Minute,
		PepperTTL:         time.Minute,
	})
}

func newVaultLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newVaultTestServer(t *testing.T, handlers map[string]http.HandlerFunc) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimSuffix(r.URL.Path, "/")
		for route, h := range handlers {
			trimmedRoute := strings.TrimSuffix(route, "/")
			if path == trimmedRoute || strings.HasPrefix(path, trimmedRoute+"/") {
				h(w, r)
				return
			}
		}
		if path == "/v1/sys/seal-status" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"sealed":       false,
				"t":            1,
				"n":            1,
				"progress":     0,
				"version":      "1.15.0",
				"cluster_name": "test",
				"cluster_id":   "test-id",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"errors": []string{"no handler for path: " + path},
		})
	}))
}

func newVaultClientForTest(t *testing.T, serverURL string, cacheLevel int) *VaultTransitClient {
	t.Helper()
	client, err := NewVaultTransitClient(serverURL, "test-token", "dcs-key", newCacheManagerForTest(cacheLevel), newVaultLogger())
	if err != nil {
		t.Fatalf("failed to create VaultTransitClient: %v", err)
	}
	return client
}

func TestNewVaultTransitClient_VaultSealed(t *testing.T) {
	server := newVaultTestServer(t, map[string]http.HandlerFunc{
		"/v1/sys/seal-status": func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{"sealed": true})
		},
	})
	defer server.Close()

	_, err := NewVaultTransitClient(server.URL, "test-token", "dcs-key", newCacheManagerForTest(3), newVaultLogger())
	if err == nil {
		t.Fatalf("expected error when vault is sealed")
	}
	if !strings.Contains(err.Error(), "vault is sealed") {
		t.Fatalf("expected sealed error, got %v", err)
	}
}

func TestVaultTransitClient_EncryptDecryptWithCache(t *testing.T) {
	var encryptCalls int
	var decryptCalls int
	const ciphertext = "vault:v1:abcdefghijklmnopqrstuvwxyz0123456789"

	server := newVaultTestServer(t, map[string]http.HandlerFunc{
		"/v1/transit/encrypt/dcs-key": func(w http.ResponseWriter, r *http.Request) {
			encryptCalls++
			var payload map[string]any
			_ = json.NewDecoder(r.Body).Decode(&payload)
			if _, ok := payload["plaintext"]; !ok {
				t.Fatalf("expected plaintext in encrypt payload")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{"ciphertext": ciphertext},
			})
		},
		"/v1/transit/decrypt/dcs-key": func(w http.ResponseWriter, r *http.Request) {
			decryptCalls++
			var payload map[string]any
			_ = json.NewDecoder(r.Body).Decode(&payload)
			if got, _ := payload["ciphertext"].(string); got != ciphertext {
				t.Fatalf("unexpected ciphertext: %q", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"plaintext": base64.StdEncoding.EncodeToString([]byte("120")),
				},
			})
		},
	})
	defer server.Close()

	client := newVaultClientForTest(t, server.URL, 3)

	enc, err := client.Encrypt(context.Background(), "120")
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	if enc != ciphertext {
		t.Fatalf("unexpected ciphertext: %q", enc)
	}

	plain1, err := client.Decrypt(context.Background(), ciphertext)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	plain2, err := client.Decrypt(context.Background(), ciphertext)
	if err != nil {
		t.Fatalf("decrypt second call failed: %v", err)
	}

	if plain1 != "120" || plain2 != "120" {
		t.Fatalf("unexpected plaintexts: %q %q", plain1, plain2)
	}
	if encryptCalls != 1 {
		t.Fatalf("expected one encrypt call, got %d", encryptCalls)
	}
	if decryptCalls != 1 {
		t.Fatalf("expected second decrypt to hit cache, got %d vault calls", decryptCalls)
	}
}

func TestVaultTransitClient_EncryptErrorPayloads(t *testing.T) {
	tests := []struct {
		name    string
		payload map[string]any
	}{
		{
			name:    "nil data",
			payload: map[string]any{},
		},
		{
			name: "missing ciphertext",
			payload: map[string]any{
				"data": map[string]any{"foo": "bar"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := newVaultTestServer(t, map[string]http.HandlerFunc{
				"/v1/transit/encrypt/dcs-key": func(w http.ResponseWriter, _ *http.Request) {
					_ = json.NewEncoder(w).Encode(tc.payload)
				},
			})
			defer server.Close()
			client := newVaultClientForTest(t, server.URL, 3)

			_, err := client.Encrypt(context.Background(), "120")
			if err == nil {
				t.Fatalf("expected encrypt error for payload %v", tc.payload)
			}
		})
	}
}

func TestVaultTransitClient_DecryptErrorPayloads(t *testing.T) {
	tests := []struct {
		name    string
		payload map[string]any
	}{
		{
			name:    "nil data",
			payload: map[string]any{},
		},
		{
			name: "missing plaintext",
			payload: map[string]any{
				"data": map[string]any{"foo": "bar"},
			},
		},
		{
			name: "invalid base64 plaintext",
			payload: map[string]any{
				"data": map[string]any{"plaintext": "@@@"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := newVaultTestServer(t, map[string]http.HandlerFunc{
				"/v1/transit/decrypt/dcs-key": func(w http.ResponseWriter, _ *http.Request) {
					_ = json.NewEncoder(w).Encode(tc.payload)
				},
			})
			defer server.Close()
			client := newVaultClientForTest(t, server.URL, 3)

			_, err := client.Decrypt(context.Background(), "vault:v1:abcdefghijklmnopqrstuvwxyz0123456789")
			if err == nil {
				t.Fatalf("expected decrypt error for payload %v", tc.payload)
			}
		})
	}
}

func TestVaultTransitClient_GetPepperAndComputeLookup_WithCache(t *testing.T) {
	var pepperCalls int
	server := newVaultTestServer(t, map[string]http.HandlerFunc{
		"/v1/secret/data/dcs": func(w http.ResponseWriter, _ *http.Request) {
			pepperCalls++
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"data": map[string]any{
						"pepper": "pepper-secret",
					},
				},
			})
		},
	})
	defer server.Close()

	client := newVaultClientForTest(t, server.URL, 1)

	pepper1, err := client.GetPepper(context.Background(), "dcs")
	if err != nil {
		t.Fatalf("GetPepper failed: %v", err)
	}
	pepper2, err := client.GetPepper(context.Background(), "dcs")
	if err != nil {
		t.Fatalf("GetPepper second call failed: %v", err)
	}
	if string(pepper1) != "pepper-secret" || string(pepper2) != "pepper-secret" {
		t.Fatalf("unexpected pepper values: %q %q", string(pepper1), string(pepper2))
	}
	if pepperCalls != 1 {
		t.Fatalf("expected pepper cache hit on second call, got %d calls", pepperCalls)
	}

	lookup, err := client.ComputeLookup(context.Background(), "  abc123  ", "dcs")
	if err != nil {
		t.Fatalf("ComputeLookup failed: %v", err)
	}

	want := ComputeHMACLookup([]byte("pepper-secret"), NormalizeExternalID("  abc123  "))
	if string(lookup) != string(want) {
		t.Fatalf("lookup mismatch: got %x want %x", lookup, want)
	}
}

func TestVaultTransitClient_GetPepperErrors(t *testing.T) {
	tests := []struct {
		name    string
		payload map[string]any
	}{
		{
			name:    "secret not found",
			payload: map[string]any{},
		},
		{
			name: "unexpected secret format",
			payload: map[string]any{
				"data": map[string]any{
					"data": "bad-format",
				},
			},
		},
		{
			name: "pepper key missing",
			payload: map[string]any{
				"data": map[string]any{
					"data": map[string]any{"foo": "bar"},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := newVaultTestServer(t, map[string]http.HandlerFunc{
				"/v1/secret/data/dcs": func(w http.ResponseWriter, _ *http.Request) {
					_ = json.NewEncoder(w).Encode(tc.payload)
				},
			})
			defer server.Close()
			client := newVaultClientForTest(t, server.URL, 1)

			_, err := client.GetPepper(context.Background(), "dcs")
			if err == nil {
				t.Fatalf("expected GetPepper error for payload %v", tc.payload)
			}
		})
	}
}
