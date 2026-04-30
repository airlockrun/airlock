package storage

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/airlockrun/airlock/config"
	"github.com/google/uuid"
)

// S3Client provides S3/MinIO file storage for spaces.
type S3Client struct {
	client          *s3.Client
	presigner       *s3.PresignClient
	publicPresigner *s3.PresignClient // signs URLs for the public endpoint (nil if not configured)
	bucket          string
}

// ObjectInfo describes an object in S3.
type ObjectInfo struct {
	Key          string
	Size         int64
	LastModified time.Time
	Metadata     map[string]string // user-defined S3 metadata (X-Amz-Meta-*)
}

// NewS3Client creates an S3Client from config. Panics if S3URL is empty.
func NewS3Client(cfg *config.Config) *S3Client {
	if cfg.S3URL == "" {
		panic("S3_URL is required")
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion(cfg.S3Region),
		awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(cfg.S3AccessKey, cfg.S3SecretKey, ""),
		),
	)
	if err != nil {
		panic(fmt.Sprintf("s3: failed to load AWS config: %v", err))
	}

	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(cfg.S3URL)
		o.UsePathStyle = true
	})

	sc := &S3Client{
		client:    client,
		presigner: s3.NewPresignClient(client),
		bucket:    cfg.S3Bucket,
	}

	// Create a separate presign client for public URLs if configured.
	if cfg.S3URLPublic != "" {
		publicClient := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(cfg.S3URLPublic)
			o.UsePathStyle = true
		})
		sc.publicPresigner = s3.NewPresignClient(publicClient)
	}

	return sc
}

// NewS3ClientFromParams creates an S3Client from explicit parameters (for non-airlock binaries like Anchor).
func NewS3ClientFromParams(endpoint, accessKey, secretKey, bucket, region string) *S3Client {
	if endpoint == "" {
		panic("s3 endpoint is required")
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion(region),
		awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(accessKey, secretKey, ""),
		),
	)
	if err != nil {
		panic(fmt.Sprintf("s3: failed to load AWS config: %v", err))
	}

	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(endpoint)
		o.UsePathStyle = true
	})

	return &S3Client{
		client:    client,
		presigner: s3.NewPresignClient(client),
		bucket:    bucket,
	}
}

// EnsureBucket creates the bucket if it doesn't exist.
// Ping is a read-only liveness check: HeadBucket on the configured bucket.
// Returns nil if S3/MinIO is reachable and the bucket exists.
func (c *S3Client) Ping(ctx context.Context) error {
	_, err := c.client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: &c.bucket,
	})
	return err
}

func (c *S3Client) EnsureBucket(ctx context.Context) error {
	_, err := c.client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: &c.bucket,
	})
	if err == nil {
		return nil
	}
	_, err = c.client.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: &c.bucket,
	})
	return err
}

// PutObject uploads data from a reader to the given key.
// If the reader is not seekable, it is buffered into memory first.
func (c *S3Client) PutObject(ctx context.Context, key string, reader io.Reader, size int64) error {
	return c.PutObjectWithMetadata(ctx, key, reader, size, nil)
}

// PutObjectWithMetadata is the same as PutObject but persists user-defined
// metadata (X-Amz-Meta-*) on the stored object. The "filename" key carries
// the original upload filename — surfaced via HeadObject.Metadata. The
// "content-type" key, if set, overrides the auto-detected Content-Type.
func (c *S3Client) PutObjectWithMetadata(ctx context.Context, key string, reader io.Reader, size int64, meta map[string]string) error {
	// AWS SDK v2 requires seekable bodies for hash computation over plain HTTP.
	// Buffer non-seekable readers (e.g. HTTP request bodies) into bytes.
	// We always buffer so we can sniff the content type from the first 512 bytes.
	data, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("buffer reader: %w", err)
	}
	size = int64(len(data))
	body := bytes.NewReader(data)

	ct := http.DetectContentType(data)
	if override, ok := meta["content-type"]; ok && override != "" {
		ct = override
	}

	// Build user-metadata map (excluding "content-type" which goes into
	// the standard header instead of X-Amz-Meta-*).
	var userMeta map[string]string
	if len(meta) > 0 {
		userMeta = make(map[string]string, len(meta))
		for k, v := range meta {
			if k == "content-type" {
				continue
			}
			userMeta[k] = v
		}
	}

	input := &s3.PutObjectInput{
		Bucket:      &c.bucket,
		Key:         &key,
		Body:        body,
		ContentType: &ct,
		Metadata:    userMeta,
	}
	if size >= 0 {
		input.ContentLength = &size
	}
	_, err = c.client.PutObject(ctx, input)
	return err
}

// GetObject returns a reader for the object at the given key. Caller must close the reader.
func (c *S3Client) GetObject(ctx context.Context, key string) (io.ReadCloser, error) {
	out, err := c.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &c.bucket,
		Key:    &key,
	})
	if err != nil {
		return nil, err
	}
	return out.Body, nil
}

// HeadObject returns metadata for the object at the given key.
func (c *S3Client) HeadObject(ctx context.Context, key string) (ObjectInfo, string, error) {
	out, err := c.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: &c.bucket,
		Key:    &key,
	})
	if err != nil {
		return ObjectInfo{}, "", err
	}
	contentType := ""
	if out.ContentType != nil {
		contentType = *out.ContentType
	}
	var lastMod time.Time
	if out.LastModified != nil {
		lastMod = *out.LastModified
	}
	return ObjectInfo{
		Key:          key,
		Size:         *out.ContentLength,
		LastModified: lastMod,
		Metadata:     out.Metadata,
	}, contentType, nil
}

// CopyObject performs a server-side copy from srcKey to dstKey within the same bucket.
func (c *S3Client) CopyObject(ctx context.Context, srcKey, dstKey string) error {
	copySource := c.bucket + "/" + srcKey
	_, err := c.client.CopyObject(ctx, &s3.CopyObjectInput{
		Bucket:     &c.bucket,
		CopySource: &copySource,
		Key:        &dstKey,
	})
	return err
}

// DeleteObject deletes the object at the given key.
func (c *S3Client) DeleteObject(ctx context.Context, key string) error {
	_, err := c.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: &c.bucket,
		Key:    &key,
	})
	return err
}

// ListObjects lists objects under the given prefix.
func (c *S3Client) ListObjects(ctx context.Context, prefix string) ([]ObjectInfo, error) {
	var objects []ObjectInfo
	paginator := s3.NewListObjectsV2Paginator(c.client, &s3.ListObjectsV2Input{
		Bucket: &c.bucket,
		Prefix: &prefix,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, obj := range page.Contents {
			objects = append(objects, ObjectInfo{
				Key:          aws.ToString(obj.Key),
				Size:         aws.ToInt64(obj.Size),
				LastModified: aws.ToTime(obj.LastModified),
			})
		}
	}
	return objects, nil
}

// PresignGetURL returns a presigned GET URL for downloading a file.
func (c *S3Client) PresignGetURL(ctx context.Context, key string, expiry time.Duration) (string, error) {
	req, err := c.presigner.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket: &c.bucket,
		Key:    &key,
	}, s3.WithPresignExpires(expiry))
	if err != nil {
		return "", err
	}
	return req.URL, nil
}

// PublicPresignGetURL returns a presigned GET URL signed for the public endpoint.
// If S3_URL_PUBLIC is not configured, falls back to the internal presigned URL.
func (c *S3Client) PublicPresignGetURL(ctx context.Context, key string, expiry time.Duration) (string, error) {
	presigner := c.presigner
	if c.publicPresigner != nil {
		presigner = c.publicPresigner
	}
	req, err := presigner.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket: &c.bucket,
		Key:    &key,
	}, s3.WithPresignExpires(expiry))
	if err != nil {
		return "", err
	}
	return req.URL, nil
}

// PresignPutURL returns a presigned PUT URL for uploading a file.
func (c *S3Client) PresignPutURL(ctx context.Context, key string, expiry time.Duration) (string, error) {
	req, err := c.presigner.PresignPutObject(ctx, &s3.PutObjectInput{
		Bucket: &c.bucket,
		Key:    &key,
	}, s3.WithPresignExpires(expiry))
	if err != nil {
		return "", err
	}
	return req.URL, nil
}

// DeletePrefix deletes all objects under the given prefix.
func (c *S3Client) DeletePrefix(ctx context.Context, prefix string) error {
	objects, err := c.ListObjects(ctx, prefix)
	if err != nil {
		return err
	}
	if len(objects) == 0 {
		return nil
	}

	deleteObjects := make([]types.ObjectIdentifier, len(objects))
	for i, obj := range objects {
		deleteObjects[i] = types.ObjectIdentifier{Key: aws.String(obj.Key)}
	}

	_, err = c.client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
		Bucket: &c.bucket,
		Delete: &types.Delete{Objects: deleteObjects},
	})
	return err
}

// --- Space sync helpers ---
// Key layout: {tenantID}/{spaceID}/shared/{path}

// SpacePrefix returns the S3 prefix for a space's shared files.
func SpacePrefix(tenantID, spaceID uuid.UUID) string {
	return tenantID.String() + "/" + spaceID.String() + "/shared/"
}

// SyncDown downloads the shared/ directory from S3 to localRoot/shared/.
func (c *S3Client) SyncDown(ctx context.Context, tenantID, spaceID uuid.UUID, localRoot string) error {
	prefix := SpacePrefix(tenantID, spaceID)
	objects, err := c.ListObjects(ctx, prefix)
	if err != nil {
		return fmt.Errorf("list objects: %w", err)
	}

	for _, obj := range objects {
		relPath := strings.TrimPrefix(obj.Key, tenantID.String()+"/"+spaceID.String()+"/")
		localPath := filepath.Join(localRoot, relPath)

		if err := os.MkdirAll(filepath.Dir(localPath), 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", filepath.Dir(localPath), err)
		}

		reader, err := c.GetObject(ctx, obj.Key)
		if err != nil {
			return fmt.Errorf("get %s: %w", obj.Key, err)
		}

		f, err := os.Create(localPath)
		if err != nil {
			reader.Close()
			return fmt.Errorf("create %s: %w", localPath, err)
		}

		_, err = io.Copy(f, reader)
		reader.Close()
		f.Close()
		if err != nil {
			return fmt.Errorf("copy %s: %w", localPath, err)
		}
	}
	return nil
}

// SyncUp uploads the shared/ directory from localRoot/shared/ to S3.
func (c *S3Client) SyncUp(ctx context.Context, tenantID, spaceID uuid.UUID, localRoot string) error {
	sharedDir := filepath.Join(localRoot, "shared")
	return filepath.Walk(sharedDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(localRoot, path)
		if err != nil {
			return err
		}
		key := tenantID.String() + "/" + spaceID.String() + "/" + relPath

		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("open %s: %w", path, err)
		}
		defer f.Close()

		return c.PutObject(ctx, key, f, info.Size())
	})
}

// SyncPath uploads a single file from localRoot to S3.
// relPath is relative to localRoot (e.g., "shared/foo.txt").
func (c *S3Client) SyncPath(ctx context.Context, tenantID, spaceID uuid.UUID, relPath, localRoot string) error {
	localPath := filepath.Join(localRoot, relPath)
	info, err := os.Stat(localPath)
	if err != nil {
		return err
	}

	key := tenantID.String() + "/" + spaceID.String() + "/" + relPath

	f, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer f.Close()

	return c.PutObject(ctx, key, f, info.Size())
}
