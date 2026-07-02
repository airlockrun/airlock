package builder

import "testing"

func TestParseRemoteState(t *testing.T) {
	const sha = "0123456789abcdef0123456789abcdef01234567"
	cases := []struct {
		name    string
		out     string
		branch  string
		empty   bool
		hasBr   bool
		headSHA string
	}{
		{"empty remote", "", "main", true, false, ""},
		{"whitespace only", "\n  \n", "main", true, false, ""},
		{"branch present", sha + "\trefs/heads/main", "main", false, true, sha},
		{"other branches, target absent", sha + "\trefs/heads/dev", "main", false, false, ""},
		{"default branch main when unset", sha + "\trefs/heads/main", "", false, true, sha},
		{"multiple heads picks target", "aaa\trefs/heads/dev\n" + sha + "\trefs/heads/release", "release", false, true, sha},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseRemoteState(tc.out, tc.branch)
			if got.Empty != tc.empty || got.HasBranch != tc.hasBr || got.HeadSHA != tc.headSHA {
				t.Errorf("parseRemoteState = %+v, want {Empty:%v HasBranch:%v HeadSHA:%q}", got, tc.empty, tc.hasBr, tc.headSHA)
			}
		})
	}
}
