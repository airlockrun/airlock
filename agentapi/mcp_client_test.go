package agentapi

import (
	"bufio"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/networkpolicy"
	"github.com/airlockrun/goai/mcp"
)

func TestMCPHTTPClientUsesCallerClient(t *testing.T) {
	client := networkpolicy.New(nil, false).Client(time.Second)
	_, _, err := DiscoverMCPTools(t.Context(), client, "https://169.254.169.254/mcp", nil, "")
	if !errors.Is(err, networkpolicy.ErrDisallowedURL) {
		t.Fatalf("DiscoverMCPTools() error = %v, want %v", err, networkpolicy.ErrDisallowedURL)
	}
}

func TestMCPHTTPClientSession(t *testing.T) {
	var mu sync.Mutex
	var methods []string
	deleted := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
		}
		if r.Method == http.MethodDelete {
			if r.Header.Get(mcp.HeaderSessionID) != "session-1" {
				t.Errorf("DELETE session ID = %q", r.Header.Get(mcp.HeaderSessionID))
			}
			mu.Lock()
			deleted = true
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		}

		var request struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mu.Lock()
		methods = append(methods, request.Method)
		mu.Unlock()
		if request.Method != "initialize" && r.Header.Get(mcp.HeaderProtocolVersion) != "2025-06-18" {
			t.Errorf("%s protocol version = %q", request.Method, r.Header.Get(mcp.HeaderProtocolVersion))
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set(mcp.HeaderSessionID, "session-1")
		if request.Method == "notifications/initialized" {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		results := map[string]any{
			"initialize":     map[string]any{"protocolVersion": "2025-06-18", "instructions": "Use carefully."},
			"tools/list":     map[string]any{"tools": []map[string]any{{"name": "lookup", "description": "Look up a value", "inputSchema": map[string]any{"type": "object"}}}},
			"resources/list": map[string]any{"resources": []any{}},
			"tools/call": map[string]any{"content": []map[string]any{
				{"type": "text", "text": "found"},
				{"type": "image", "mimeType": "image/png", "data": "aW1hZ2U="},
			}},
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": results[request.Method]})
	}))
	defer server.Close()

	client := server.Client()
	tools, instructions, err := DiscoverMCPTools(t.Context(), client, server.URL, nil, "secret")
	if err != nil {
		t.Fatalf("DiscoverMCPTools(): %v", err)
	}
	if instructions != "Use carefully." {
		t.Errorf("instructions = %q", instructions)
	}
	if len(tools) != 1 || tools[0].Name != "lookup" {
		t.Fatalf("tools = %#v", tools)
	}
	mu.Lock()
	if !deleted {
		t.Error("discovery did not close the MCP session")
	}
	mu.Unlock()

	result, err := callMCPTool(t.Context(), client, server.URL, nil, "secret", wire.MCPToolCallRequest{
		Tool:      "lookup",
		Arguments: json.RawMessage(`{"query":"airlock"}`),
	})
	if err != nil {
		t.Fatalf("callMCPTool(): %v", err)
	}
	if len(result.Content) != 2 || result.Content[0].Text != "found" || result.Content[1].Type != "image" {
		t.Fatalf("result = %#v", result)
	}

	mu.Lock()
	defer mu.Unlock()
	want := []string{
		"initialize", "notifications/initialized", "tools/list", "resources/list",
		"initialize", "notifications/initialized", "tools/list", "resources/list", "tools/call",
	}
	if len(methods) != len(want) {
		t.Fatalf("methods = %v, want %v", methods, want)
	}
	for i := range want {
		if methods[i] != want[i] {
			t.Fatalf("methods = %v, want %v", methods, want)
		}
	}
}

func TestParseMCPSSE(t *testing.T) {
	stream := "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"tools\":[]}}\n\n"
	result, err := parseMCPSSE(responseLimitReader{reader: bufio.NewReader(strings.NewReader(stream))}, 7)
	if err != nil {
		t.Fatalf("parseMCPSSE(): %v", err)
	}
	if string(result) != `{"tools":[]}` {
		t.Fatalf("result = %s", result)
	}
}
