package attachref

import (
	"bytes"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"testing"
)

// pngBytes returns a minimal valid PNG of the given dimensions filled with
// solid gray. Used as preprocessing input.
func pngBytes(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, color.RGBA{128, 128, 128, 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("encode png: %v", err)
	}
	return buf.Bytes()
}

func TestPreprocessImage_SkipsTinyImage(t *testing.T) {
	raw := pngBytes(t, 400, 300)
	if len(raw) > skipBytesLimit {
		t.Fatalf("fixture PNG too big: %d bytes", len(raw))
	}

	got, err := preprocessImage(raw, "image/png")
	if err != nil {
		t.Fatalf("preprocessImage: %v", err)
	}
	if !got.Skip {
		t.Errorf("expected Skip=true for small image, got Bytes=%d", len(got.Bytes))
	}
	if got.MimeType != "image/png" {
		t.Errorf("MimeType = %q, want image/png", got.MimeType)
	}
}

func TestPreprocessImage_ResizesLargePNG(t *testing.T) {
	raw := pngBytes(t, 4000, 3000)

	got, err := preprocessImage(raw, "image/png")
	if err != nil {
		t.Fatalf("preprocessImage: %v", err)
	}
	if got.Skip {
		t.Fatal("expected resize, got Skip=true")
	}
	if got.MimeType != "image/jpeg" {
		t.Errorf("MimeType = %q, want image/jpeg", got.MimeType)
	}

	cfg, _, err := image.DecodeConfig(bytes.NewReader(got.Bytes))
	if err != nil {
		t.Fatalf("decode output: %v", err)
	}
	if cfg.Width > maxSide || cfg.Height > maxSide {
		t.Errorf("output size %dx%d exceeds maxSide %d", cfg.Width, cfg.Height, maxSide)
	}
	if cfg.Width != maxSide && cfg.Height != maxSide {
		t.Errorf("expected longest side == %d, got %dx%d", maxSide, cfg.Width, cfg.Height)
	}
}

func TestPreprocessImage_NonImagePassthrough(t *testing.T) {
	got, err := preprocessImage([]byte("hello"), "text/plain")
	if err != nil {
		t.Fatalf("preprocessImage: %v", err)
	}
	if !got.Skip {
		t.Error("expected Skip=true for non-image")
	}
	if got.MimeType != "text/plain" {
		t.Errorf("MimeType = %q, want text/plain", got.MimeType)
	}
}

func TestPreprocessImage_LargeByteCountTriggersReencode(t *testing.T) {
	// Build a JPEG that's already below the pixel limits but >200KB: pad
	// with "noise" so encoder output is large. We just need to verify the
	// bytes-based trigger works when dims are fine.
	img := image.NewRGBA(image.Rect(0, 0, 800, 600))
	for y := 0; y < 600; y++ {
		for x := 0; x < 800; x++ {
			img.Set(x, y, color.RGBA{uint8(x ^ y), uint8(x + y), uint8(x - y), 255})
		}
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 100}); err != nil {
		t.Fatalf("encode fixture jpeg: %v", err)
	}
	if buf.Len() <= skipBytesLimit {
		t.Skipf("fixture too small (%d bytes) to trigger re-encode path", buf.Len())
	}
	got, err := preprocessImage(buf.Bytes(), "image/jpeg")
	if err != nil {
		t.Fatalf("preprocessImage: %v", err)
	}
	if got.Skip {
		t.Error("expected re-encode for oversized-bytes input")
	}
	if len(got.Bytes) >= buf.Len() {
		t.Logf("note: re-encoded bytes (%d) not smaller than input (%d)", len(got.Bytes), buf.Len())
	}
}

func TestTargetSize(t *testing.T) {
	tests := []struct {
		name       string
		w, h, max  int
		wantW, wantH int
	}{
		{"no-op (both within max)", 400, 300, 1600, 400, 300},
		{"landscape shrinks by width", 4000, 3000, 1600, 1600, 1200},
		{"portrait shrinks by height", 3000, 4000, 1600, 1200, 1600},
		{"square shrinks", 3200, 3200, 1600, 1600, 1600},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w, h := targetSize(tt.w, tt.h, tt.max)
			if w != tt.wantW || h != tt.wantH {
				t.Errorf("targetSize(%d, %d, %d) = (%d, %d), want (%d, %d)",
					tt.w, tt.h, tt.max, w, h, tt.wantW, tt.wantH)
			}
		})
	}
}
