package sysagent

import (
	"net/http"
	"testing"
)

func TestHTTPClientForProvider(t *testing.T) {
	client := &http.Client{}
	s := &Service{providerHTTPClient: client}

	if got := s.httpClientForProvider("openai-compatible"); got != client {
		t.Fatal("openai-compatible provider did not receive the sysagent HTTP client")
	}
	if got := s.httpClientForProvider("anthropic"); got != nil {
		t.Fatal("hosted provider received the provider endpoint HTTP client")
	}
}
