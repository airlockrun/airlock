package lockout

import (
	"testing"
	"time"
)

func TestCooldownFor(t *testing.T) {
	p := Default
	cases := []struct {
		tier int
		want time.Duration
	}{
		{-1, 5 * time.Minute},
		{0, 5 * time.Minute},
		{1, 15 * time.Minute},
		{2, 60 * time.Minute},
		{3, 60 * time.Minute},
		{99, 60 * time.Minute},
	}
	for _, c := range cases {
		if got := p.CooldownFor(c.tier); got != c.want {
			t.Errorf("CooldownFor(%d) = %v, want %v", c.tier, got, c.want)
		}
	}
}

func TestPadResponseSleepsToTarget(t *testing.T) {
	p := Policy{PadDuration: 50 * time.Millisecond}
	start := time.Now()
	p.PadResponse(start)
	elapsed := time.Since(start)
	if elapsed < 45*time.Millisecond {
		t.Errorf("PadResponse returned too fast: %v", elapsed)
	}
	if elapsed > 200*time.Millisecond {
		t.Errorf("PadResponse slept too long: %v", elapsed)
	}
}

func TestPadResponseNoOpWhenPastTarget(t *testing.T) {
	p := Policy{PadDuration: 1 * time.Millisecond}
	start := time.Now().Add(-1 * time.Second)
	begin := time.Now()
	p.PadResponse(start)
	if elapsed := time.Since(begin); elapsed > 5*time.Millisecond {
		t.Errorf("PadResponse should be no-op when past target, slept %v", elapsed)
	}
}
