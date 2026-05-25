package storage_test

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/airlockrun/airlock/storage"
	"github.com/google/uuid"
)

func newTestClient(t *testing.T) *storage.S3Client {
	t.Helper()
	endpoint := os.Getenv("S3_URL")
	if endpoint == "" {
		t.Skip("S3_URL not set, skipping live S3 test")
	}
	accessKey := os.Getenv("S3_ACCESS_KEY")
	secretKey := os.Getenv("S3_SECRET_KEY")
	bucket := os.Getenv("S3_BUCKET")
	if bucket == "" {
		bucket = "airlock-test-" + uuid.New().String()[:8]
	}
	region := os.Getenv("S3_REGION")
	if region == "" {
		region = "us-east-1"
	}

	client := storage.NewS3ClientFromParams(endpoint, accessKey, secretKey, bucket, region)
	ctx := context.Background()
	if err := client.EnsureBucket(ctx); err != nil {
		t.Fatalf("EnsureBucket: %v", err)
	}
	return client
}

func TestPutGetDeleteRoundTrip(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()
	key := "test/" + uuid.New().String() + ".txt"
	content := "hello world"

	// Put
	err := client.PutObject(ctx, key, bytes.NewReader([]byte(content)), int64(len(content)))
	if err != nil {
		t.Fatalf("PutObject: %v", err)
	}

	// Get
	reader, err := client.GetObject(ctx, key)
	if err != nil {
		t.Fatalf("GetObject: %v", err)
	}
	got, err := io.ReadAll(reader)
	reader.Close()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != content {
		t.Fatalf("content mismatch: got %q, want %q", string(got), content)
	}

	// List
	objects, err := client.ListObjects(ctx, "test/")
	if err != nil {
		t.Fatalf("ListObjects: %v", err)
	}
	found := false
	for _, obj := range objects {
		if obj.Key == key {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("key %s not found in ListObjects", key)
	}

	// Delete
	err = client.DeleteObject(ctx, key)
	if err != nil {
		t.Fatalf("DeleteObject: %v", err)
	}

	// Verify deleted
	_, err = client.GetObject(ctx, key)
	if err == nil {
		t.Fatal("expected error after delete, got nil")
	}
}

func TestCopyObject(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()
	srcKey := "test/copy-src-" + uuid.New().String()[:8] + ".txt"
	dstKey := "test/copy-dst-" + uuid.New().String()[:8] + ".txt"
	content := "copy me"

	err := client.PutObject(ctx, srcKey, bytes.NewReader([]byte(content)), int64(len(content)))
	if err != nil {
		t.Fatalf("PutObject: %v", err)
	}
	defer client.DeleteObject(ctx, srcKey)
	defer client.DeleteObject(ctx, dstKey)

	// Copy
	if err := client.CopyObject(ctx, srcKey, dstKey); err != nil {
		t.Fatalf("CopyObject: %v", err)
	}

	// Verify copy contents match
	reader, err := client.GetObject(ctx, dstKey)
	if err != nil {
		t.Fatalf("GetObject dst: %v", err)
	}
	got, err := io.ReadAll(reader)
	reader.Close()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != content {
		t.Fatalf("content mismatch: got %q, want %q", string(got), content)
	}
}

// escapeS3Key is internal; test it via the exported wrapper used by
// CopyObject. Slashes must be preserved (S3 keys are flat strings but
// the SDK treats path-shaped keys segment-by-segment); non-ASCII must
// be percent-encoded so x-amz-copy-source can carry them.
func TestEscapeS3Key(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"plain/path.txt", "plain/path.txt"},
		{"agents/abc/tmp/файл.png", "agents/abc/tmp/%D1%84%D0%B0%D0%B9%D0%BB.png"},
		{"a/b c/d.txt", "a/b%20c/d.txt"},
		{"中文/テスト.bin", "%E4%B8%AD%E6%96%87/%E3%83%86%E3%82%B9%E3%83%88.bin"},
	}
	for _, c := range cases {
		got := storage.EscapeS3KeyForTest(c.in)
		if got != c.want {
			t.Errorf("escapeS3Key(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// Regression: a key with non-Latin codepoints used to make CopyObject
// fail with "failed to copy file" because the raw key landed in the
// x-amz-copy-source HTTP header (ASCII-only). CopyObject must now
// percent-encode the source before the SDK signs the request.
func TestCopyObject_NonLatinKey(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()
	suffix := uuid.New().String()[:8]
	srcKey := "test/копия-" + suffix + "-файл.txt"
	dstKey := "test/копия-" + suffix + "-результат.txt"
	content := "non-latin copy"

	if err := client.PutObject(ctx, srcKey, bytes.NewReader([]byte(content)), int64(len(content))); err != nil {
		t.Fatalf("PutObject: %v", err)
	}
	defer client.DeleteObject(ctx, srcKey)
	defer client.DeleteObject(ctx, dstKey)

	if err := client.CopyObject(ctx, srcKey, dstKey); err != nil {
		t.Fatalf("CopyObject with non-Latin key: %v", err)
	}

	reader, err := client.GetObject(ctx, dstKey)
	if err != nil {
		t.Fatalf("GetObject dst: %v", err)
	}
	got, err := io.ReadAll(reader)
	reader.Close()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != content {
		t.Fatalf("content mismatch: got %q, want %q", string(got), content)
	}
}

func TestPresignURLs(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()
	key := "test/presign-" + uuid.New().String() + ".txt"

	content := "presign test"
	err := client.PutObject(ctx, key, bytes.NewReader([]byte(content)), int64(len(content)))
	if err != nil {
		t.Fatalf("PutObject: %v", err)
	}
	defer client.DeleteObject(ctx, key)

	// Presigned GET
	getURL, err := client.PresignGetURL(ctx, key, 5*time.Minute)
	if err != nil {
		t.Fatalf("PresignGetURL: %v", err)
	}
	if getURL == "" {
		t.Fatal("empty presigned GET URL")
	}

	// Presigned PUT
	putURL, err := client.PresignPutURL(ctx, key, 5*time.Minute)
	if err != nil {
		t.Fatalf("PresignPutURL: %v", err)
	}
	if putURL == "" {
		t.Fatal("empty presigned PUT URL")
	}
}

func TestSyncDownUp(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()
	tenantID := uuid.New()
	spaceID := uuid.New()

	// Upload some test files to S3
	prefix := storage.SpacePrefix(tenantID, spaceID)
	files := map[string]string{
		prefix + "hello.txt":        "hello",
		prefix + "subdir/world.txt": "world",
	}
	for key, content := range files {
		err := client.PutObject(ctx, key, bytes.NewReader([]byte(content)), int64(len(content)))
		if err != nil {
			t.Fatalf("PutObject %s: %v", key, err)
		}
	}
	defer client.DeletePrefix(ctx, prefix)

	// SyncDown
	tmpDir := t.TempDir()
	err := client.SyncDown(ctx, tenantID, spaceID, tmpDir)
	if err != nil {
		t.Fatalf("SyncDown: %v", err)
	}

	// Verify local files
	got, err := os.ReadFile(filepath.Join(tmpDir, "shared", "hello.txt"))
	if err != nil {
		t.Fatalf("read hello.txt: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("hello.txt: got %q, want %q", string(got), "hello")
	}

	got, err = os.ReadFile(filepath.Join(tmpDir, "shared", "subdir", "world.txt"))
	if err != nil {
		t.Fatalf("read world.txt: %v", err)
	}
	if string(got) != "world" {
		t.Fatalf("world.txt: got %q, want %q", string(got), "world")
	}

	// Modify and add a file locally
	os.WriteFile(filepath.Join(tmpDir, "shared", "new.txt"), []byte("new file"), 0o644)

	// SyncUp
	err = client.SyncUp(ctx, tenantID, spaceID, tmpDir)
	if err != nil {
		t.Fatalf("SyncUp: %v", err)
	}

	// Verify in S3
	reader, err := client.GetObject(ctx, prefix+"new.txt")
	if err != nil {
		t.Fatalf("GetObject new.txt: %v", err)
	}
	gotBytes, _ := io.ReadAll(reader)
	reader.Close()
	if string(gotBytes) != "new file" {
		t.Fatalf("new.txt in S3: got %q, want %q", string(gotBytes), "new file")
	}
}
