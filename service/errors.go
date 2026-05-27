// Package service holds the per-domain business-logic layer that sits
// between HTTP handlers and the database. Handlers parse + serialize;
// services own authorization gating, sqlc queries, and side effects.
//
// Methods return sentinel errors (see below) that HTTPStatus translates
// to status codes at the HTTP boundary. User-facing message strings are
// chosen per endpoint by the handler — services don't synthesize prose.
package service

import (
	"errors"
	"fmt"
)

// detailErr lets a service attach a specific user-facing message to a
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
