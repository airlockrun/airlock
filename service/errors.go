// Package service holds the per-domain business-logic layer that sits
// between HTTP handlers and the database. Handlers parse + serialize;
// services own authorization gating, sqlc queries, and side effects.
//
// The sentinel errors, their Detail wrapper, and HTTPStatus live in the
// leaf package apperr so the authz layer can return them without an
// import cycle; they are re-exported here as service.ErrX for the many
// callers (and errors.Is checks) that reference them through service.
package service

import "github.com/airlockrun/airlock/apperr"

// Sentinel errors, re-exported from apperr. Same values, so
// errors.Is(err, service.ErrForbidden) matches an apperr.ErrForbidden
// returned by authz.
var (
	ErrUnauthorized = apperr.ErrUnauthorized
	ErrForbidden    = apperr.ErrForbidden
	ErrNotFound     = apperr.ErrNotFound
	ErrConflict     = apperr.ErrConflict
	ErrInvalidInput = apperr.ErrInvalidInput
)

// Detail wraps a sentinel with a printf-style detail message; see
// apperr.Detail.
func Detail(sentinel error, format string, args ...any) error {
	return apperr.Detail(sentinel, format, args...)
}
