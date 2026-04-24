package attachref

import (
	"bytes"
	"fmt"
	"image"
	"image/jpeg"
	_ "image/png" // register PNG decoder
	"io"
	"strings"

	"golang.org/x/image/draw"
	_ "golang.org/x/image/webp" // register webp decoder
)

// Preprocessing tuning knobs. Kept non-configurable for now — tweak here if
// provider quality/size tradeoffs shift.
const (
	maxSide          = 1600 // resize longest side to this, preserving aspect ratio
	jpegQuality      = 85
	skipBytesLimit   = 200 * 1024 // original bytes below this + dims already small → no re-encode
	skipPixelDimLimit = 1600      // both dims must be ≤ this to skip
)

// preprocessResult carries the bytes that should land in `llm/K` plus the
// final MIME type. For non-image MIMEs or tiny images we return the original
// unchanged (bytes, mime) so the caller can server-side copy instead of PUT.
type preprocessResult struct {
	Bytes    []byte // non-nil if a re-encode happened (caller PUTs these)
	MimeType string // post-preprocessing MIME
	Skip     bool   // true → caller should CopyObject(src→dst) instead of PUT Bytes
}

// preprocessImage decodes, resizes, and re-encodes an image. Returns a
// preprocessResult indicating whether the caller should PUT fresh bytes or
// server-side-copy the original.
//
// Non-image MIMEs return {Skip: true, MimeType: originalMime} — resolver
// should CopyObject.
func preprocessImage(originalBytes []byte, originalMime string) (preprocessResult, error) {
	if !strings.HasPrefix(originalMime, "image/") {
		return preprocessResult{Skip: true, MimeType: originalMime}, nil
	}

	// Fast-skip: if the object is already small in both bytes and dimensions,
	// don't bother decoding. We still create the `llm/` copy at the call site.
	if len(originalBytes) <= skipBytesLimit {
		cfg, _, cfgErr := image.DecodeConfig(bytes.NewReader(originalBytes))
		if cfgErr == nil && cfg.Width <= skipPixelDimLimit && cfg.Height <= skipPixelDimLimit {
			return preprocessResult{Skip: true, MimeType: originalMime}, nil
		}
	}

	src, _, err := image.Decode(bytes.NewReader(originalBytes))
	if err != nil {
		return preprocessResult{}, fmt.Errorf("decode image: %w", err)
	}

	srcBounds := src.Bounds()
	srcW, srcH := srcBounds.Dx(), srcBounds.Dy()
	dstW, dstH := targetSize(srcW, srcH, maxSide)

	var dst image.Image
	if dstW == srcW && dstH == srcH {
		dst = src
	} else {
		resized := image.NewRGBA(image.Rect(0, 0, dstW, dstH))
		draw.CatmullRom.Scale(resized, resized.Bounds(), src, srcBounds, draw.Over, nil)
		dst = resized
	}

	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, dst, &jpeg.Options{Quality: jpegQuality}); err != nil {
		return preprocessResult{}, fmt.Errorf("encode jpeg: %w", err)
	}

	return preprocessResult{
		Bytes:    buf.Bytes(),
		MimeType: "image/jpeg",
	}, nil
}

// targetSize computes the resized dimensions preserving aspect ratio,
// scaling so the longest side is at most max. Returns the original
// dimensions if neither side exceeds max.
func targetSize(w, h, max int) (int, int) {
	if w <= max && h <= max {
		return w, h
	}
	if w >= h {
		return max, h * max / w
	}
	return w * max / h, max
}

// readAll drains a reader into a byte slice with a sane cap to avoid
// runaway allocations on upstream bugs.
const maxAttachmentBytes = 64 * 1024 * 1024

func readAll(r io.Reader) ([]byte, error) {
	var buf bytes.Buffer
	_, err := io.Copy(&buf, io.LimitReader(r, maxAttachmentBytes+1))
	if err != nil {
		return nil, err
	}
	if buf.Len() > maxAttachmentBytes {
		return nil, fmt.Errorf("attachment exceeds %d bytes", maxAttachmentBytes)
	}
	return buf.Bytes(), nil
}
