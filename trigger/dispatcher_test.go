package trigger

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/airlockrun/airlock/container"
	"github.com/google/uuid"
)

// mockContainerManager is a test double for ContainerManager.
type mockContainerManager struct {
	container *container.Container
	startErr  error
	started   []container.AgentOpts
}

func (m *mockContainerManager) StartAgent(_ context.Context, opts container.AgentOpts) (*container.Container, error) {
	m.started = append(m.started, opts)
	if m.startErr != nil {
		return nil, m.startErr
	}
	return m.container, nil
}

func (m *mockContainerManager) GetRunning(_ context.Context, _ uuid.UUID) (*container.Container, error) {
	return m.container, nil
}

func (m *mockContainerManager) StopAgent(_ context.Context, _ string) error { return nil }

func (m *mockContainerManager) StartToolserver(_ context.Context, _ container.ToolserverOpts) (*container.Container, error) {
	return &container.Container{}, nil
}

func (m *mockContainerManager) StopToolserver(_ context.Context, _ string) error { return nil }
func (m *mockContainerManager) KillToolserver(_ context.Context, _ string) error { return nil }

func (m *mockContainerManager) RemoveImage(_ context.Context, _ string) error { return nil }

func TestForwardWebhook(t *testing.T) {
	// Create a mock agent server that receives the webhook.
	var receivedPath string
	var receivedRunID string
	var receivedBody []byte
	agentSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		receivedRunID = r.Header.Get("X-Run-ID")
		buf := make([]byte, 1024)
		n, _ := r.Body.Read(buf)
		receivedBody = buf[:n]
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"type":"finish","data":{}}` + "\n"))
	}))
	defer agentSrv.Close()

	cm := &mockContainerManager{
		container: &container.Container{
			ID:       "test-container",
			Name:     "test-agent",
			Endpoint: agentSrv.URL,
			Token:    "test-token",
		},
	}

	d := &Dispatcher{
		containers: cm,
	}

	body := []byte(`{"event":"push"}`)
	rc, err := d.forward(context.Background(), cm.container, "POST", "/webhook/github", body, uuid.New(), nil, 2*time.Minute)
	if err != nil {
		t.Fatalf("forward: %v", err)
	}
	defer rc.Close()

	if receivedPath != "/webhook/github" {
		t.Errorf("path = %q, want /webhook/github", receivedPath)
	}
	if receivedRunID == "" {
		t.Error("X-Run-ID header not set")
	}
	if string(receivedBody) != `{"event":"push"}` {
		t.Errorf("body = %q, want %q", receivedBody, `{"event":"push"}`)
	}
}

func TestForwardSetsBridgeIDHeader(t *testing.T) {
	var receivedBridgeID string
	agentSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBridgeID = r.Header.Get("X-Bridge-ID")
		w.WriteHeader(http.StatusOK)
	}))
	defer agentSrv.Close()

	cm := &mockContainerManager{
		container: &container.Container{
			Endpoint: agentSrv.URL,
			Token:    "tok",
		},
	}

	d := &Dispatcher{
		containers: cm,
	}

	bridgeID := uuid.New()
	rc, err := d.forward(context.Background(), cm.container, "POST", "/prompt", nil, uuid.New(), &bridgeID, 5*time.Minute)
	if err != nil {
		t.Fatalf("forward: %v", err)
	}
	rc.Close()

	if receivedBridgeID != bridgeID.String() {
		t.Errorf("X-Bridge-ID = %q, want %q", receivedBridgeID, bridgeID.String())
	}
}

func TestForwardReturnsErrorOnBadStatus(t *testing.T) {
	agentSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "agent crashed"})
	}))
	defer agentSrv.Close()

	cm := &mockContainerManager{
		container: &container.Container{
			Endpoint: agentSrv.URL,
			Token:    "tok",
		},
	}

	d := &Dispatcher{
		containers: cm,
	}

	_, err := d.forward(context.Background(), cm.container, "POST", "/cron/daily", nil, uuid.New(), nil, 2*time.Minute)
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}
