package prompt

import (
	"testing"

	"github.com/airlockrun/agentsdk"
)

func TestRenderExtras(t *testing.T) {
	tests := []struct {
		name   string
		raw    []byte
		access agentsdk.Access
		want   string
	}{
		{
			name:   "nil raw returns empty",
			raw:    nil,
			access: agentsdk.AccessAdmin,
			want:   "",
		},
		{
			name:   "empty array returns empty",
			raw:    []byte("[]"),
			access: agentsdk.AccessAdmin,
			want:   "",
		},
		{
			name:   "malformed JSON returns empty",
			raw:    []byte("not json"),
			access: agentsdk.AccessAdmin,
			want:   "",
		},
		{
			name:   "no-access spec visible to all",
			raw:    []byte(`[{"text":"baseline"}]`),
			access: agentsdk.AccessPublic,
			want:   "baseline",
		},
		{
			name:   "admin-only filtered out for user",
			raw:    []byte(`[{"text":"admin note","access":["admin"]}]`),
			access: agentsdk.AccessUser,
			want:   "",
		},
		{
			name:   "admin-only kept for admin",
			raw:    []byte(`[{"text":"admin note","access":["admin"]}]`),
			access: agentsdk.AccessAdmin,
			want:   "admin note",
		},
		{
			name: "multi-access list includes user but not public",
			raw: []byte(`[
				{"text":"members","access":["admin","user"]},
				{"text":"public"}
			]`),
			access: agentsdk.AccessUser,
			want:   "members\n\npublic",
		},
		{
			name: "public caller gets only all-access fragments",
			raw: []byte(`[
				{"text":"shared"},
				{"text":"admin","access":["admin"]},
				{"text":"user","access":["user"]}
			]`),
			access: agentsdk.AccessPublic,
			want:   "shared",
		},
		{
			name: "order preserved across filter",
			raw: []byte(`[
				{"text":"a"},
				{"text":"b","access":["admin"]},
				{"text":"c"},
				{"text":"d","access":["admin"]}
			]`),
			access: agentsdk.AccessAdmin,
			want:   "a\n\nb\n\nc\n\nd",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RenderExtras(tt.raw, tt.access)
			if got != tt.want {
				t.Errorf("RenderExtras() = %q, want %q", got, tt.want)
			}
		})
	}
}
