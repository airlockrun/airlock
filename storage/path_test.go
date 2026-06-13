package storage

import "testing"

func TestCleanAgentPath(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		// Valid forms
		{"simple", "uploads/foo.png", "uploads/foo.png", false},
		{"nested", "a/b/c/d.txt", "a/b/c/d.txt", false},
		{"single-segment", "file.bin", "file.bin", false},
		{"dot-folder", "uploads/.hidden", "uploads/.hidden", false},
		{"trailing-dot-segment", "a/b/.", "a/b", false}, // path.Clean reduces
		// Invalid
		{"empty", "", "", true},
		{"nul", "foo\x00bar", "", true},
		{"backslash", "uploads\\foo.png", "", true},
		{"absolute", "/etc/passwd", "", true},
		{"empty-segment", "a//b", "", true},
		{"traversal", "../secret", "", true},
		{"traversal-nested", "a/../../b", "", true},
		{"only-dotdot", "..", "", true},
		{"only-dot", ".", "", true},
		{"leading-slash-after-clean", "./../foo", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CleanAgentPath(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tc.wantErr)
			}
			if !tc.wantErr && got != tc.want {
				t.Errorf("got %q want %q", got, tc.want)
			}
		})
	}
}
