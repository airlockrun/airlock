package apihelpers

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
)

func TestDecodeProtoBodyLimit(t *testing.T) {
	req := httptest.NewRequest("POST", "/", strings.NewReader(strings.Repeat("x", int(MaxRequestBodyBytes)+1)))
	req.ContentLength = -1
	if err := DecodeProto(req, &airlockv1.ErrorResponse{}); !errors.Is(err, ErrRequestBodyTooLarge) {
		t.Fatalf("DecodeProto() error = %v, want ErrRequestBodyTooLarge", err)
	}
}

func TestReadJSON(t *testing.T) {
	t.Run("single value", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/", strings.NewReader(`{"value":"ok"}`))
		var got map[string]string
		if err := ReadJSON(req, &got); err != nil {
			t.Fatal(err)
		}
		if got["value"] != "ok" {
			t.Fatalf("value = %q, want ok", got["value"])
		}
	})

	t.Run("rejects trailing value", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/", strings.NewReader(`{} {}`))
		if err := ReadJSON(req, &map[string]string{}); err == nil {
			t.Fatal("ReadJSON() accepted multiple JSON values")
		}
	})

	t.Run("limit", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/", strings.NewReader(strings.Repeat("x", int(MaxRequestBodyBytes)+1)))
		req.ContentLength = -1
		if err := ReadJSON(req, &map[string]string{}); !errors.Is(err, ErrRequestBodyTooLarge) {
			t.Fatalf("ReadJSON() error = %v, want ErrRequestBodyTooLarge", err)
		}
	})
}
