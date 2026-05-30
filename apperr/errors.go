// Package apperr holds the cross-cutting sentinel errors, their
// detail-wrapper, and the HTTP status mapping. It is a leaf package
// (no airlock imports) so the authorization layer (authz) and the
// service layer can both return the same sentinels without an import
// cycle — service re-exports these as service.ErrX aliases.
//
// Methods return a sentinel that HTTPStatus translates to a status code
// at the HTTP boundary. User-facing message strings are chosen per
// endpoint by the handler — lower layers don't synthesize prose.
package apperr

import (
	"errors"
	"fmt"
	"net/http"
)

var (
	// ErrUnauthorized — caller has no credentials. Maps to 401.
	ErrUnauthorized = errors.New("unauthorized")

	// ErrForbidden — caller is authenticated but lacks the required
	// agent-access level or tenant role. Maps to 403.
	ErrForbidden = errors.New("forbidden")

	// ErrNotFound — target row does not exist. Maps to 404.
	ErrNotFound = errors.New("not found")

	// ErrConflict — write rejected by a uniqueness or state constraint
	// (already exists, wrong-state transition, etc.). Maps to 409.
	ErrConflict = errors.New("conflict")

	// ErrInvalidInput — caller-supplied data is malformed or fails a
	// service-level invariant. Maps to 400. HTTP-level parse errors
	// (bad JSON, bad UUID in URL) stay in the handler.
	ErrInvalidInput = errors.New("invalid input")
)

// detailErr lets a caller attach a specific user-facing message to a
// sentinel without losing the sentinel for HTTPStatus / errors.Is. Used
// for endpoints whose 400 message conveys *which* field is bad — the
// bare sentinel alone would force the handler to pick a generic string.
type detailErr struct {
	msg      string
	sentinel error
}

func (e *detailErr) Error() string { return e.msg }
func (e *detailErr) Unwrap() error { return e.sentinel }

// Detail wraps a sentinel with a printf-style detail message. The
// returned error.Error() returns just the formatted message (no
// "<msg>: <sentinel>" suffix), while errors.Is(err, sentinel) is true.
func Detail(sentinel error, format string, args ...any) error {
	return &detailErr{msg: fmt.Sprintf(format, args...), sentinel: sentinel}
}

// HTTPStatus maps a sentinel error to its HTTP status code. Handlers
// call this with whatever a lower layer returned and let it pick
// 401/403/404/409/400; anything else is a 500.
func HTTPStatus(err error) int {
	switch {
	case err == nil:
		return http.StatusOK
	case errors.Is(err, ErrUnauthorized):
		return http.StatusUnauthorized
	case errors.Is(err, ErrForbidden):
		return http.StatusForbidden
	case errors.Is(err, ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, ErrConflict):
		return http.StatusConflict
	case errors.Is(err, ErrInvalidInput):
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}
