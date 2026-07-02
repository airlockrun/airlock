package catalog

import "testing"

// TestModelMeetsCapabilityImage covers the image slot gate: any model that can
// output images qualifies (image_gen capability), whether it's a dedicated
// generator or a chat model with image output — not just Kind=="image".
func TestModelMeetsCapabilityImage(t *testing.T) {
	cases := []struct {
		name string
		m    Model
		want bool
	}{
		{"dedicated image generator", Model{Kind: "image", Caps: []string{"image_gen"}}, true},
		{"chat model with image output", Model{Kind: "language", Caps: []string{"text", "image_gen"}}, true},
		{"text-only chat model", Model{Kind: "language", Caps: []string{"text"}}, false},
		{"embedding model", Model{Kind: "embedding", Caps: []string{"embedding"}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, reason := ModelMeetsCapability(tc.m, "image")
			if ok != tc.want {
				t.Errorf("ModelMeetsCapability(image) = %v (%q), want %v", ok, reason, tc.want)
			}
		})
	}
}
