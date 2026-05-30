package apperr

import (
	"errors"
	"net/http"
	"testing"
)

func TestHTTPStatus(t *testing.T) {
	tests := []struct {
		err  error
		want int
	}{
		{nil, http.StatusOK},
		{ErrUnauthorized, http.StatusUnauthorized},
		{ErrForbidden, http.StatusForbidden},
		{ErrNotFound, http.StatusNotFound},
		{ErrConflict, http.StatusConflict},
		{ErrInvalidInput, http.StatusBadRequest},
		{errors.New("other"), http.StatusInternalServerError},
		{Detail(ErrForbidden, "no"), http.StatusForbidden}, // detail-wrapped keeps the sentinel
	}
	for _, tt := range tests {
		if got := HTTPStatus(tt.err); got != tt.want {
			t.Errorf("HTTPStatus(%v) = %d, want %d", tt.err, got, tt.want)
		}
	}
}

func TestDetailKeepsSentinel(t *testing.T) {
	err := Detail(ErrNotFound, "agent %s missing", "x")
	if !errors.Is(err, ErrNotFound) {
		t.Error("Detail should wrap the sentinel for errors.Is")
	}
	if err.Error() != "agent x missing" {
		t.Errorf("Error() = %q, want formatted message", err.Error())
	}
}
