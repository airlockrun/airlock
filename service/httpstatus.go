package service

import "github.com/airlockrun/airlock/apperr"

// HTTPStatus maps a service sentinel error to its HTTP status code; see
// apperr.HTTPStatus.
func HTTPStatus(err error) int { return apperr.HTTPStatus(err) }
