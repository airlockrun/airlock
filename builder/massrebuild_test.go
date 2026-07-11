package builder

import (
	"strings"
	"testing"
)

func TestSDKSeriesChanged(t *testing.T) {
	tests := []struct {
		name     string
		from, to string
		want     bool
	}{
		{"empty from (first boot)", "", "0.4.0-rc.1", false},
		{"rc bump same series", "0.4.0-rc.1", "0.4.0-rc.2", false},
		{"patch bump same series", "0.3.1-rc.6", "0.3.2", false},
		{"pre-1.0 minor bump is breaking", "0.3.1-rc.6", "0.4.0-rc.1", true},
		{"major bump is breaking", "0.9.0", "1.0.0", true},
		{"post-1.0 minor bump not breaking", "1.2.0", "1.3.0", false},
		{"post-1.0 major bump breaking", "1.9.3", "2.0.0", true},
		{"v prefix tolerated", "v0.3.1", "v0.4.0", true},
		{"unparseable from", "garbage", "0.4.0", false},
		{"identical", "0.4.0-rc.1", "0.4.0-rc.1", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sdkSeriesChanged(tt.from, tt.to); got != tt.want {
				t.Errorf("sdkSeriesChanged(%q, %q) = %v, want %v", tt.from, tt.to, got, tt.want)
			}
		})
	}
}

func TestSDKMigrationInstruction(t *testing.T) {
	if got := sdkMigrationInstruction("0.4.0-rc.1", "0.4.0-rc.2"); got != "" {
		t.Errorf("rc bump should yield no instruction, got %q", got)
	}
	instr := sdkMigrationInstruction("0.3.1-rc.6", "0.4.0-rc.1")
	if instr == "" {
		t.Fatal("breaking bump should yield a migration instruction")
	}
	for _, want := range []string{"0.3.1-rc.6", "0.4.0-rc.1", "REFERENCE.md"} {
		if !strings.Contains(instr, want) {
			t.Errorf("instruction missing %q:\n%s", want, instr)
		}
	}
}
