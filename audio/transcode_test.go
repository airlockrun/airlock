package audio

import (
	"context"
	"testing"
)

func TestDetectSTTFormat(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want string
	}{
		{"mp3 id3", []byte("ID3\x04\x00\x00\x00\x00\x00\x00"), "mp3"},
		{"mp3 framesync", []byte{0xFF, 0xFB, 0x90, 0x00}, "mp3"},
		{"wav riff wave", []byte("RIFF\x24\x00\x00\x00WAVEfmt "), "wav"},
		{"mp4 ftyp", []byte("\x00\x00\x00 ftypisom\x00\x00\x02\x00"), "mp4"},
		{"webm ebml", []byte{0x1A, 0x45, 0xDF, 0xA3, 0x9F, 0x42}, "webm"},
		{"ogg — not whitelisted", []byte("OggS\x00\x02\x00\x00"), ""},
		{"flac — not whitelisted", []byte("fLaC\x00\x00\x00\x22"), ""},
		{"riff but not wave", []byte("RIFF\x00\x00\x00\x00AVI LIST"), ""},
		{"too short", []byte("ID"), ""},
		{"empty", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := detectSTTFormat(tc.data); got != tc.want {
				t.Errorf("detectSTTFormat = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestNormalizeForSTT_PassThrough(t *testing.T) {
	// MP3 bytes — should pass through without invoking ffmpeg.
	in := []byte("ID3\x04\x00\x00\x00\x00\x00\x00rest-of-file")
	out, filename, mime, err := NormalizeForSTT(context.Background(), in, "clip.mp3", "audio/mpeg")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if &out[0] != &in[0] {
		t.Errorf("bytes were not the same slice — NormalizeForSTT unexpectedly copied/transcoded")
	}
	if filename != "clip.mp3" || mime != "audio/mpeg" {
		t.Errorf("pass-through changed filename/mime: %q %q", filename, mime)
	}
}

func TestStripExt(t *testing.T) {
	cases := map[string]string{
		"voice.ogg":  "voice",
		"clip.tar.gz": "clip.tar",
		"noext":      "noext",
		".hidden":    ".hidden",
		"":           "",
	}
	for in, want := range cases {
		if got := stripExt(in); got != want {
			t.Errorf("stripExt(%q) = %q, want %q", in, got, want)
		}
	}
}
