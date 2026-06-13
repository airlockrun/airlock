package api

import (
	"net/http/httptest"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// decodeProtoResp unmarshals a recorder body into dst and fails the
// test on parse error. The handler-level tests use this so a malformed
// response surfaces as t.Fatalf rather than a nil-pointer panic on
// the subsequent dst.Field access.
func decodeProtoResp(t *testing.T, rec *httptest.ResponseRecorder, dst proto.Message) {
	t.Helper()
	if err := protojson.Unmarshal(rec.Body.Bytes(), dst); err != nil {
		t.Fatalf("unmarshal %T: %v\nbody: %s", dst, err, rec.Body.String())
	}
}
