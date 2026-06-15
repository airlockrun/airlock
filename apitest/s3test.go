// Package apitest is the integration test harness for the airlock API.
// Imported only from _test.go files, so testcontainers and other test-only
// deps never reach the production binary.
package apitest

import (
	"context"
	"fmt"

	tcminio "github.com/testcontainers/testcontainers-go/modules/minio"
)

// minioImage matches the production storage image so test behaviour
// matches deploy. Pinned to a recent stable tag.
const minioImage = "minio/minio:RELEASE.2024-09-13T20-26-02Z"

// S3Params is everything an S3 client needs to point at MinIO.
type S3Params struct {
	Endpoint  string
	AccessKey string
	SecretKey string
	Bucket    string
	Region    string
}

// setupS3 boots a MinIO container (the production storage image) and returns
// connection params plus a teardown. ok=false when no S3 is available (no
// Docker); the caller should skip tests that need S3.
//
// The bucket is NOT created here — apitest.Setup creates it via
// S3Client.EnsureBucket after constructing the client.
func setupS3(ctx context.Context) (params S3Params, release func(), ok bool) {
	const (
		accessKey = "airlock-test"
		secretKey = "airlock-test-secret"
		bucket    = "airlock-test"
		region    = "us-east-1"
	)

	ctr, err := tcminio.Run(ctx, minioImage,
		tcminio.WithUsername(accessKey),
		tcminio.WithPassword(secretKey),
	)
	if err != nil {
		if ctr != nil {
			_ = ctr.Terminate(context.Background())
		}
		return S3Params{}, func() {}, false
	}

	terminate := func() { _ = ctr.Terminate(context.Background()) }

	host, err := ctr.ConnectionString(ctx)
	if err != nil {
		terminate()
		panic(fmt.Sprintf("apitest: minio connection string: %v", err))
	}

	return S3Params{
		Endpoint:  "http://" + host,
		AccessKey: accessKey,
		SecretKey: secretKey,
		Bucket:    bucket,
		Region:    region,
	}, terminate, true
}
