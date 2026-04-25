package lockout

import "testing"

func TestNormalizeIP(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"203.0.113.50", "203.0.113.50"},
		{"203.0.113.50:443", "203.0.113.50"},
		{"::1", "::"},
		{"[::1]:443", "::"},
		{"2001:db8:1234:5678:abcd:ef01:2345:6789", "2001:db8:1234:5678::"},
		{"[2001:db8:1234:5678:abcd:ef01:2345:6789]:443", "2001:db8:1234:5678::"},
		{"::ffff:203.0.113.50", "203.0.113.50"},
		{"", UnknownIP},
		{"not-an-ip", UnknownIP},
		{"999.999.999.999", UnknownIP},
	}
	for _, c := range cases {
		got := NormalizeIP(c.in)
		if got != c.want {
			t.Errorf("NormalizeIP(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
