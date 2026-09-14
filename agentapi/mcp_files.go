package agentapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"time"

	"github.com/airlockrun/airlock/service/mcpaccess"
	runtimesvc "github.com/airlockrun/airlock/service/runtime"
	"github.com/airlockrun/airlock/storage"
)

const (
	maxInlineResourceBytes = 10 * 1024 * 1024
	presignedURLTTL        = time.Hour
)

// rewriterCtx translates external file values using a service-issued exact-run
// handle. No caller-supplied identity or storage key grants file access.
type rewriterCtx struct {
	ctx          context.Context
	s3           *storage.S3Client
	files        *mcpaccess.RunFiles
	extraContent []map[string]any
}

func materializeInbound(rc *rewriterCtx, args json.RawMessage, schemaRaw []byte) (json.RawMessage, *runtimesvc.MaterializeError) {
	return materializeFiles(args, schemaRaw, rc.inboundRewriter)
}

func materializeOutbound(rc *rewriterCtx, body []byte, schemaRaw []byte) ([]byte, *runtimesvc.MaterializeError) {
	return materializeFiles(body, schemaRaw, rc.outboundRewriter)
}

func materializeFiles(raw, schemaRaw []byte, rewrite func(string, any, string) (any, *runtimesvc.MaterializeError)) (json.RawMessage, *runtimesvc.MaterializeError) {
	schema, err := runtimesvc.ParseSchema(schemaRaw)
	if err != nil {
		return nil, &runtimesvc.MaterializeError{Code: runtimesvc.RpcErrInternal, Message: "invalid tool schema"}
	}
	if !runtimesvc.SchemaHasAgentMarker(schema) {
		return raw, nil
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, &runtimesvc.MaterializeError{Code: runtimesvc.RpcErrInvalidParams, Message: "invalid file value"}
	}
	value, materializeErr := runtimesvc.WalkSchema(value, schema, "", rewrite)
	if materializeErr != nil {
		return nil, materializeErr
	}
	out, err := json.Marshal(value)
	if err != nil {
		return nil, &runtimesvc.MaterializeError{Code: runtimesvc.RpcErrInternal, Message: "encode file value"}
	}
	return out, nil
}

func (rc *rewriterCtx) inboundRewriter(format string, value any, ptr string) (any, *runtimesvc.MaterializeError) {
	if format == "agent-dir" {
		return nil, &runtimesvc.MaterializeError{Code: runtimesvc.RpcErrInvalidParams, Message: "directory paths not supported across MCP boundaries at " + ptr}
	}
	if path, ok := value.(string); ok {
		file, err := rc.files.Resolve(rc.ctx, path)
		if err != nil {
			return nil, &runtimesvc.MaterializeError{Code: runtimesvc.RpcErrInvalidParams, Message: "file unavailable at " + ptr}
		}
		return file.Relative, nil
	}
	obj, ok := value.(map[string]any)
	if !ok {
		return nil, &runtimesvc.MaterializeError{Code: runtimesvc.RpcErrInvalidParams, Message: "agent-file must be a path or {filename, mimeType, data} at " + ptr}
	}
	data, _ := obj["data"].(string)
	if data == "" || len(data) > base64.StdEncoding.EncodedLen(maxInlineResourceBytes) {
		return nil, &runtimesvc.MaterializeError{Code: runtimesvc.RpcErrInvalidParams, Message: "missing or oversized inline file at " + ptr}
	}
	raw, err := base64.StdEncoding.DecodeString(data)
	if err != nil || len(raw) > maxInlineResourceBytes {
		return nil, &runtimesvc.MaterializeError{Code: runtimesvc.RpcErrInvalidParams, Message: "invalid inline file at " + ptr}
	}
	filename, _ := obj["filename"].(string)
	if filename == "" {
		filename = "upload.bin"
	}
	mimeType, _ := obj["mimeType"].(string)
	path, err := rc.files.Upload(rc.ctx, rc.s3, filename, mimeType, raw)
	if err != nil {
		return nil, &runtimesvc.MaterializeError{Code: runtimesvc.RpcErrServerError, Message: "upload unavailable at " + ptr}
	}
	return path, nil
}

func (rc *rewriterCtx) outboundRewriter(format string, value any, ptr string) (any, *runtimesvc.MaterializeError) {
	if format == "agent-dir" {
		return nil, &runtimesvc.MaterializeError{Code: runtimesvc.RpcErrInvalidParams, Message: "directory paths not supported across MCP boundaries at " + ptr}
	}
	path, ok := value.(string)
	if !ok || path == "" {
		return value, nil
	}
	file, err := rc.files.Resolve(rc.ctx, path)
	if err != nil {
		return nil, &runtimesvc.MaterializeError{Code: runtimesvc.RpcErrServerError, Message: "output file unavailable at " + ptr}
	}
	info, ct, err := rc.s3.HeadObject(rc.ctx, file.S3Key)
	if err != nil {
		return nil, &runtimesvc.MaterializeError{Code: runtimesvc.RpcErrServerError, Message: "output file unavailable at " + ptr}
	}
	name := info.Metadata["filename"]
	if name == "" {
		name = filepath.Base(file.Relative)
	}
	if _, err := rc.files.Resolve(rc.ctx, path); err != nil {
		return nil, &runtimesvc.MaterializeError{Code: runtimesvc.RpcErrServerError, Message: "output file unavailable at " + ptr}
	}
	url, err := rc.s3.PublicPresignGetURL(rc.ctx, file.S3Key, presignedURLTTL)
	if err != nil {
		return nil, &runtimesvc.MaterializeError{Code: runtimesvc.RpcErrServerError, Message: "output file unavailable at " + ptr}
	}
	rc.extraContent = append(rc.extraContent, map[string]any{"type": "resource_link", "uri": url, "name": name, "mimeType": ct,
		"_meta": map[string]any{"airlock.run/size": info.Size, "airlock.run/downloadExpiresAt": time.Now().Add(presignedURLTTL).UTC().Format(time.RFC3339)}})
	return file.Relative, nil
}
