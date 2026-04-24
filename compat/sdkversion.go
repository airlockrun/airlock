// Package compat verifies that agent containers and this airlock process
// were built against compatible agentsdk versions. Airlock imports agentsdk
// directly, so agentsdk.Version at airlock's compile time is the single
// source of truth for "what this airlock expects from its agents."
package compat

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/airlockrun/agentsdk"
)

// CheckSDKVersion returns nil if reported is compatible with airlock's
// bundled agentsdk (same semver major). Returns a descriptive error
// otherwise, safe to surface to the agent operator.
func CheckSDKVersion(reported string) error {
	return checkAgainst(reported, agentsdk.Version)
}

func checkAgainst(reported, expected string) error {
	rMaj, err := majorOf(reported)
	if err != nil {
		return fmt.Errorf("agent reported invalid agentsdk version %q", reported)
	}
	eMaj, err := majorOf(expected)
	if err != nil {
		// Should never happen — expected comes from our own build.
		return fmt.Errorf("airlock has invalid bundled agentsdk version %q", expected)
	}
	if rMaj != eMaj {
		return fmt.Errorf(
			"agentsdk %s is incompatible with airlock's required %s (major %d ≠ %d) — rebuild the agent",
			reported, expected, rMaj, eMaj)
	}
	return nil
}

func majorOf(v string) (int, error) {
	v = strings.TrimSpace(strings.TrimPrefix(v, "v"))
	if v == "" {
		return 0, fmt.Errorf("empty version")
	}
	parts := strings.SplitN(v, ".", 2)
	n, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, err
	}
	return n, nil
}
