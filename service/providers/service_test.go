package providers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/airlockrun/airlock/networkpolicy"
)

func TestValidateSlug(t *testing.T) {
	tests := []struct {
		name string
		slug string
		ok   bool
	}{
		{name: "single word", slug: "local", ok: true},
		{name: "kebab with digits", slug: "local-gpu-2", ok: true},
		{name: "uppercase", slug: "Local", ok: false},
		{name: "underscore", slug: "local_gpu", ok: false},
		{name: "leading hyphen", slug: "-local", ok: false},
		{name: "repeated hyphen", slug: "local--gpu", ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateSlug(tt.slug); (err == nil) != tt.ok {
				t.Fatalf("validateSlug(%q) error = %v, want valid=%v", tt.slug, err, tt.ok)
			}
		})
	}
}

func TestDiscoverModelsTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond)
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer server.Close()

	client := &http.Client{Timeout: 20 * time.Millisecond}
	if _, err := discoverModels(context.Background(), client, server.URL, ""); err == nil {
		t.Fatal("discoverModels returned nil error for a timed-out endpoint")
	}
}

func TestDiscoverModelsNetworkPolicy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":[{"id":"local-model"}]}`))
	}))
	defer server.Close()

	t.Run("localhost allowed by development policy", func(t *testing.T) {
		models, err := discoverModels(context.Background(), networkpolicy.New(nil, true).ProviderEndpointClient(time.Second), server.URL, "")
		if err != nil {
			t.Fatalf("discoverModels: %v", err)
		}
		if len(models) != 1 || models[0].ModelID != "local-model" {
			t.Fatalf("models = %+v", models)
		}
	})

	t.Run("localhost blocked without configured allowance", func(t *testing.T) {
		if _, err := discoverModels(context.Background(), networkpolicy.New(nil, false).ProviderEndpointClient(time.Second), server.URL, ""); err == nil {
			t.Fatal("discoverModels returned nil error for blocked localhost endpoint")
		}
	})
}

func TestProviderDiscoveryClientRejectsRedirects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/models-elsewhere", http.StatusFound)
	}))
	defer server.Close()

	client := newDiscoveryClient(&http.Client{})
	if client.Timeout != discoveryTimeout {
		t.Fatalf("client timeout = %s, want %s", client.Timeout, discoveryTimeout)
	}
	if _, err := discoverModels(context.Background(), client, server.URL, ""); err == nil {
		t.Fatal("discoverModels followed a redirect")
	}
}
