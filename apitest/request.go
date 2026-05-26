package apitest

import (
	"bytes"
	"context"
	"io"
	"net/http"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// AgentSubdomainSuffix is the suffix used when crafting subdomain
// requests: a request for slug "foo" hits Host "foo.apitest.local".
// Matches the AgentDomain wired into Setup's config.
const AgentSubdomainSuffix = ".apitest.local"

// Do executes req against the harness server, decoding any response
// body into out when out is non-nil and the response carries one.
// On non-2xx the body is returned via the (*ResponseError).Body field
// of the returned error — tests typically just assert status code from
// the returned response then read body bytes themselves.
func (h *Harness) Do(req *http.Request) *http.Response {
	h.T.Helper()
	resp, err := h.Server.Client().Do(req)
	if err != nil {
		h.T.Fatalf("apitest: do request %s %s: %v", req.Method, req.URL, err)
	}
	return resp
}

// NewRequest builds an authenticated HTTP request against the harness
// server. method/path are joined with Server.URL. Bearer auth is added
// when token is non-empty. body is encoded as JSON.
func (h *Harness) NewRequest(method, path, token string, body any) *http.Request {
	h.T.Helper()
	var rdr io.Reader
	if body != nil {
		if m, ok := body.(proto.Message); ok {
			raw, err := protojson.Marshal(m)
			if err != nil {
				h.T.Fatalf("apitest: marshal proto request: %v", err)
			}
			rdr = bytes.NewReader(raw)
		} else if b, ok := body.([]byte); ok {
			rdr = bytes.NewReader(b)
		} else {
			h.T.Fatalf("apitest: NewRequest body must be proto.Message or []byte, got %T", body)
		}
	}
	req, err := http.NewRequestWithContext(context.Background(), method, h.Server.URL+path, rdr)
	if err != nil {
		h.T.Fatalf("apitest: build request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

// NewSubdomainRequest is NewRequest plus a Host header of
// "{slug}{AgentSubdomainSuffix}". httptest.Server listens on
// 127.0.0.1, so SubdomainProxy reads the Host header to decide which
// branch to take — overriding it lets a test drive the subdomain path
// without DNS games.
func (h *Harness) NewSubdomainRequest(method, slug, path, token string, body any) *http.Request {
	h.T.Helper()
	req := h.NewRequest(method, path, token, body)
	req.Host = slug + AgentSubdomainSuffix
	return req
}

// DecodeProto reads resp.Body fully and unmarshals into dst, failing
// the test on any error. Closes the body. Use after asserting status
// code on a successful response.
func (h *Harness) DecodeProto(resp *http.Response, dst proto.Message) {
	h.T.Helper()
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		h.T.Fatalf("apitest: read response body: %v", err)
	}
	if err := protojson.Unmarshal(raw, dst); err != nil {
		h.T.Fatalf("apitest: unmarshal response %T: %v\nbody: %s", dst, err, string(raw))
	}
}

// ReadBody is DecodeProto for non-proto responses (error bodies,
// plain JSON). Returns the body bytes; closes the body.
func (h *Harness) ReadBody(resp *http.Response) []byte {
	h.T.Helper()
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		h.T.Fatalf("apitest: read response body: %v", err)
	}
	return raw
}
