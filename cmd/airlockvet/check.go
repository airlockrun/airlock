package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// check is the private CI, release, and HQ gate. The nested enterprise module
// needs its own invocation because a core ./... pattern cannot include it.
// Both scans run even on diagnostics so a single run reports all blockers.
func check(run func(dir string) error) error {
	var errs []error
	for _, dir := range []string{".", "enterprise"} {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err != nil {
			errs = append(errs, fmt.Errorf("airlockvet %s module: %w", dir, err))
			continue
		}
		if err := run(dir); err != nil {
			errs = append(errs, fmt.Errorf("airlockvet %s: %w", dir, err))
		}
	}
	return errors.Join(errs...)
}
