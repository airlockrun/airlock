package attachref_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"image"
	"image/color"
	"image/png"
	"os"
	"strings"
	"testing"

	"github.com/airlockrun/airlock/attachref"
	"github.com/airlockrun/airlock/storage"
	"github.com/airlockrun/goai/message"
	solprovider "github.com/airlockrun/sol/provider"
	solsession "github.com/airlockrun/sol/session"
	"github.com/google/uuid"
)

func newTestS3(t *testing.T) *storage.S3Client {
	t.Helper()
	endpoint := os.Getenv("S3_URL")
	if endpoint == "" {
		t.Skip("S3_URL not set — attachref tests require MinIO")
	}
	bucket := os.Getenv("S3_BUCKET")
	if bucket == "" {
		bucket = "airlock-test-" + uuid.New().String()[:8]
	}
	region := os.Getenv("S3_REGION")
	if region == "" {
		region = "us-east-1"
	}
	client := storage.NewS3ClientFromParams(
		endpoint,
		os.Getenv("S3_ACCESS_KEY"),
		os.Getenv("S3_SECRET_KEY"),
		bucket,
		region,
	)
	if err := client.EnsureBucket(context.Background()); err != nil {
		t.Fatalf("EnsureBucket: %v", err)
	}
	return client
}

func putImage(t *testing.T, s3 *storage.S3Client, agentID uuid.UUID, key string, w, h int) {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, color.RGBA{uint8(x % 255), uint8(y % 255), 128, 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("encode png: %v", err)
	}
	fullKey := "agents/" + agentID.String() + "/" + key
	if err := s3.PutObject(context.Background(), fullKey, bytes.NewReader(buf.Bytes()), int64(buf.Len())); err != nil {
		t.Fatalf("PutObject: %v", err)
	}
	t.Cleanup(func() {
		_ = s3.DeleteObject(context.Background(), fullKey)
		_ = s3.DeleteObject(context.Background(), "llm/"+fullKey)
	})
}

func TestResolveForStorage_CanonicalizesAndSetsSource(t *testing.T) {
	s3 := newTestS3(t)
	ctx := context.Background()
	agentID := uuid.New()
	key := "tmp/img-" + uuid.New().String()[:8] + ".png"
	putImage(t, s3, agentID, key, 400, 300) // tiny — skip path

	msgs := []solsession.Message{
		{
			Role: "tool",
			Parts: []solsession.Part{
				{
					Type:  "image",
					Image: &solsession.ImagePart{Image: attachref.Sentinel + key, MimeType: "image/png", Source: key},
				},
			},
		},
	}

	if err := attachref.ResolveForStorage(ctx, s3, agentID, msgs); err != nil {
		t.Fatalf("ResolveForStorage: %v", err)
	}

	got := msgs[0].Parts[0].Image
	wantSource := "llm/agents/" + agentID.String() + "/" + key
	if got.Source != wantSource {
		t.Errorf("Source = %q, want %q", got.Source, wantSource)
	}
	if got.Image != attachref.Sentinel+key {
		t.Errorf("Image = %q, want sentinel preserved", got.Image)
	}

	// Canonical blob should exist.
	if _, _, err := s3.HeadObject(ctx, wantSource); err != nil {
		t.Errorf("canonical blob missing: %v", err)
	}
}

func TestResolveForLLM_URLModeForOpenAI(t *testing.T) {
	s3 := newTestS3(t)
	ctx := context.Background()
	agentID := uuid.New()
	key := "tmp/url-" + uuid.New().String()[:8] + ".png"
	putImage(t, s3, agentID, key, 400, 300)

	msgs := []message.Message{
		{
			Role: message.RoleUser,
			Content: message.Content{
				Parts: []message.Part{
					message.TextPart{Text: "look at this"},
					message.ImagePart{Image: attachref.Sentinel + key, MimeType: "image/png"},
				},
			},
		},
	}

	policy := solprovider.PolicyFor("openai", "gpt-4o")
	if !policy.SupportsURL {
		t.Fatal("openai policy should SupportsURL")
	}

	if err := attachref.ResolveForLLM(ctx, s3, agentID, policy, msgs); err != nil {
		t.Fatalf("ResolveForLLM: %v", err)
	}

	ip, ok := msgs[0].Content.Parts[1].(message.ImagePart)
	if !ok {
		t.Fatalf("part 1 kind = %T, want ImagePart", msgs[0].Content.Parts[1])
	}
	if !strings.HasPrefix(ip.Image, "http") {
		t.Errorf("expected http URL, got %q", ip.Image)
	}
}

func TestResolveForLLM_InlineModeForNonURLProvider(t *testing.T) {
	s3 := newTestS3(t)
	ctx := context.Background()
	agentID := uuid.New()
	key := "tmp/inline-" + uuid.New().String()[:8] + ".png"
	putImage(t, s3, agentID, key, 400, 300)

	msgs := []message.Message{
		{
			Role: message.RoleUser,
			Content: message.Content{
				Parts: []message.Part{
					message.ImagePart{Image: attachref.Sentinel + key, MimeType: "image/png"},
				},
			},
		},
	}

	// deepseek doesn't appear in AttachmentOverlay so it falls back to
	// DefaultAttachmentPolicy, which is inline-only.
	policy := solprovider.PolicyFor("deepseek", "deepseek-chat")
	if policy.SupportsURL {
		t.Fatal("default policy should not SupportsURL")
	}

	if err := attachref.ResolveForLLM(ctx, s3, agentID, policy, msgs); err != nil {
		t.Fatalf("ResolveForLLM: %v", err)
	}

	ip := msgs[0].Content.Parts[0].(message.ImagePart)
	if strings.HasPrefix(ip.Image, "http") || strings.HasPrefix(ip.Image, attachref.Sentinel) {
		t.Errorf("expected base64 payload, got %q", ip.Image[:min(40, len(ip.Image))])
	}
	if _, err := base64.StdEncoding.DecodeString(ip.Image); err != nil {
		t.Errorf("not valid base64: %v", err)
	}
}

// Anthropic + Google now support URL for images AND files. Verify both
// kinds route to their correct fields.
func TestResolveForLLM_FileURLRoutesToFilePartURL(t *testing.T) {
	s3 := newTestS3(t)
	ctx := context.Background()
	agentID := uuid.New()
	key := "tmp/doc-" + uuid.New().String()[:8] + ".pdf"

	// Upload a non-image blob (resolver will server-side copy as-is).
	fullKey := "agents/" + agentID.String() + "/" + key
	body := []byte("%PDF-1.4\n%fake pdf for test\n")
	if err := s3.PutObject(ctx, fullKey, bytes.NewReader(body), int64(len(body))); err != nil {
		t.Fatalf("PutObject: %v", err)
	}
	t.Cleanup(func() {
		_ = s3.DeleteObject(ctx, fullKey)
		_ = s3.DeleteObject(ctx, "llm/"+fullKey)
	})

	msgs := []message.Message{
		{
			Role: message.RoleUser,
			Content: message.Content{
				Parts: []message.Part{
					message.FilePart{Data: attachref.Sentinel + key, MimeType: "application/pdf", Filename: "doc.pdf"},
				},
			},
		},
	}

	policy := solprovider.PolicyFor("anthropic", "claude-3-5-sonnet-20241022")
	if !policy.SupportsFileURL {
		t.Fatal("anthropic policy should SupportsFileURL")
	}

	if err := attachref.ResolveForLLM(ctx, s3, agentID, policy, msgs); err != nil {
		t.Fatalf("ResolveForLLM: %v", err)
	}

	fp := msgs[0].Content.Parts[0].(message.FilePart)
	if !strings.HasPrefix(fp.URL, "http") {
		t.Errorf("expected http URL on FilePart.URL, got %q", fp.URL)
	}
	if fp.Data != "" {
		t.Errorf("expected FilePart.Data empty in URL mode, got %d bytes", len(fp.Data))
	}
}

// OpenAI's policy has SupportsURL=true but SupportsFileURL=false (chat API
// PDFs are base64-only). Verify files still inline even when images URL.
func TestResolveForLLM_OpenAIFilesStayInline(t *testing.T) {
	s3 := newTestS3(t)
	ctx := context.Background()
	agentID := uuid.New()
	key := "tmp/doc-" + uuid.New().String()[:8] + ".pdf"
	fullKey := "agents/" + agentID.String() + "/" + key
	body := []byte("%PDF-1.4\n%fake pdf\n")
	if err := s3.PutObject(ctx, fullKey, bytes.NewReader(body), int64(len(body))); err != nil {
		t.Fatalf("PutObject: %v", err)
	}
	t.Cleanup(func() {
		_ = s3.DeleteObject(ctx, fullKey)
		_ = s3.DeleteObject(ctx, "llm/"+fullKey)
	})

	msgs := []message.Message{
		{
			Role: message.RoleUser,
			Content: message.Content{
				Parts: []message.Part{
					message.FilePart{Data: attachref.Sentinel + key, MimeType: "application/pdf"},
				},
			},
		},
	}

	policy := solprovider.PolicyFor("openai", "gpt-4o")
	if policy.SupportsFileURL {
		t.Fatal("openai policy should not SupportsFileURL")
	}

	if err := attachref.ResolveForLLM(ctx, s3, agentID, policy, msgs); err != nil {
		t.Fatalf("ResolveForLLM: %v", err)
	}

	fp := msgs[0].Content.Parts[0].(message.FilePart)
	if fp.URL != "" {
		t.Errorf("expected FilePart.URL empty (file URL unsupported), got %q", fp.URL)
	}
	if fp.Data == "" {
		t.Error("expected base64 FilePart.Data")
	}
	if _, err := base64.StdEncoding.DecodeString(fp.Data); err != nil {
		t.Errorf("FilePart.Data not valid base64: %v", err)
	}
}

func TestResolveForLLM_EvictsPastInlineCap(t *testing.T) {
	s3 := newTestS3(t)
	ctx := context.Background()
	agentID := uuid.New()

	// Three images across three "turns" — oldest two should evict if cap
	// is smaller than their combined base64.
	keys := []string{}
	for i := 0; i < 3; i++ {
		k := "tmp/evict-" + uuid.New().String()[:8] + ".png"
		putImage(t, s3, agentID, k, 400, 300)
		keys = append(keys, k)
	}

	msgs := []message.Message{
		{Role: message.RoleUser, Content: message.Content{Parts: []message.Part{
			message.ImagePart{Image: attachref.Sentinel + keys[0], MimeType: "image/png"},
		}}},
		{Role: message.RoleUser, Content: message.Content{Parts: []message.Part{
			message.ImagePart{Image: attachref.Sentinel + keys[1], MimeType: "image/png"},
		}}},
		{Role: message.RoleUser, Content: message.Content{Parts: []message.Part{
			message.ImagePart{Image: attachref.Sentinel + keys[2], MimeType: "image/png"},
		}}},
	}

	// 400x300 gradient PNGs are ~1.4KB base64 each. Cap 2000 fits one, evicts rest.
	policy := solprovider.AttachmentPolicy{
		MaxInlineBytesTotal: 2000,
		SupportsURL:         false,
	}

	if err := attachref.ResolveForLLM(ctx, s3, agentID, policy, msgs); err != nil {
		t.Fatalf("ResolveForLLM: %v", err)
	}

	// Oldest messages should become text placeholders; most-recent stays.
	_, lastIsImage := msgs[2].Content.Parts[0].(message.ImagePart)
	if !lastIsImage {
		t.Error("last (current-turn) part should remain an image")
	}
	_, firstIsText := msgs[0].Content.Parts[0].(message.TextPart)
	if !firstIsText {
		t.Errorf("oldest part should evict to text placeholder, got %T", msgs[0].Content.Parts[0])
	}
	if firstIsText {
		tp := msgs[0].Content.Parts[0].(message.TextPart)
		if !strings.Contains(tp.Text, keys[0]) {
			t.Errorf("placeholder missing original key: %q", tp.Text)
		}
		if !strings.Contains(tp.Text, "attachToContext") {
			t.Errorf("placeholder missing re-attach instruction: %q", tp.Text)
		}
	}
}

func TestResolveForLLM_CurrentTurnOverCapFailsLoud(t *testing.T) {
	s3 := newTestS3(t)
	ctx := context.Background()
	agentID := uuid.New()

	k := "tmp/big-" + uuid.New().String()[:8] + ".png"
	putImage(t, s3, agentID, k, 400, 300)

	msgs := []message.Message{
		{Role: message.RoleUser, Content: message.Content{Parts: []message.Part{
			message.ImagePart{Image: attachref.Sentinel + k, MimeType: "image/png"},
		}}},
	}

	policy := solprovider.AttachmentPolicy{
		MaxInlineBytesTotal: 500, // below single image size
		SupportsURL:         false,
	}

	err := attachref.ResolveForLLM(ctx, s3, agentID, policy, msgs)
	if err == nil {
		t.Fatal("expected error for current-turn overflow, got nil")
	}
	if !strings.Contains(err.Error(), "size cap") {
		t.Errorf("error = %v, want contains 'size cap'", err)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
