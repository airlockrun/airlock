// Package lockout implements per-(email, ip) login throttling for the
// airlock auth path. The mechanism is intentionally application-only —
// per-IP rate limiting is the operator's reverse-proxy job. See
// airlock/CLAUDE.md and the project README for the threat-model rationale.
package lockout

import "time"

type Policy struct {
	WindowMinutes int
	Threshold     int
	TierDelays    []time.Duration
	PadDuration   time.Duration
}

var Default = Policy{
	WindowMinutes: 15,
	Threshold:     10,
	TierDelays:    []time.Duration{5 * time.Minute, 15 * time.Minute, 60 * time.Minute},
	PadDuration:   400 * time.Millisecond,
}

func (p Policy) CooldownFor(tier int) time.Duration {
	if tier < 0 {
		tier = 0
	}
	if tier >= len(p.TierDelays) {
		tier = len(p.TierDelays) - 1
	}
	return p.TierDelays[tier]
}

// PadResponse sleeps so total elapsed time since `start` reaches
// p.PadDuration. No-op if already past. Used on the auth-failure paths to
// collapse the timing channel between unknown-email (fast), wrong-password
// (bcrypt-slow), and lockout (fast) responses.
func (p Policy) PadResponse(start time.Time) {
	if remaining := p.PadDuration - time.Since(start); remaining > 0 {
		time.Sleep(remaining)
	}
}
