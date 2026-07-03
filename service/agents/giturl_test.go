package agents

import "testing"

func TestNormalizeGitRemoteURL(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"git@github.com:owner/repo.git", "https://github.com/owner/repo.git", false},
		{"git@gitlab.com:group/sub/repo.git", "https://gitlab.com/group/sub/repo.git", false},
		{"ssh://git@github.com/owner/repo.git", "https://github.com/owner/repo.git", false},
		{"ssh://git@github.com:22/owner/repo.git", "https://github.com/owner/repo.git", false},
		{"https://github.com/owner/repo.git", "https://github.com/owner/repo.git", false},
		{"  https://github.com/owner/repo.git  ", "https://github.com/owner/repo.git", false},
		{"http://localhost:3000/repo.git", "http://localhost:3000/repo.git", false},
		{"git://github.com/owner/repo.git", "", true},
		{"file:///tmp/repo", "", true},
		{"", "", true},
		{"not a url", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := normalizeGitRemoteURL(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("normalizeGitRemoteURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
