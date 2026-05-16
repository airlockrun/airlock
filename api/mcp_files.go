package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/storage"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Boundary materializer for FilePath/DirPath tool args + results at the
// MCP server endpoint. Tool authors declare `agentsdk.FilePath` Go-side
// (rendered as JSON Schema `format: "agent-file"`); the schema-driven
// walker here translates between the agent's local path-string view and
// what callers send / expect:
//
//   - A2A (sibling agent): copy across per-agent S3 buckets.
//   - External MCP (user/anon/oauth): inbound = decode inline base64 into
//     S3; outbound = emit MCP resource_link content blocks (with
//     _meta.airlock.run/downloadUrl presigned URL for large files).
//
// DirPath args/results are always rejected with a structured -32602
// error — copying directory trees is unbounded.

const (
	// maxInlineResourceBytes caps inline base64 uploads + the threshold
	// at which outbound resource_link blocks gain a presigned downloadUrl
	// rather than expecting clients to call resources/read for the bytes.
	maxInlineResourceBytes = 10 * 1024 * 1024 // 10 MiB

	// presignedURLTTL is how long the resource_link _meta downloadUrl
	// remains valid. One hour is enough for human "click to download"
	// flows and short enough that grant revocation propagates quickly.
	presignedURLTTL = 1 * time.Hour
)

// materializeError carries a JSON-RPC error code + human-readable
// message back to the dispatcher. Caller wraps via writeJSONRPCError.
type materializeError struct {
	Code    int
	Message string
}

// rewriterCtx threads dependencies + per-call state through the schema
// walker. extraContent accumulates resource_link blocks for external
// principals; A2A leaves it empty (path rewrites happen in-place).
//
// scopeKey labels the destination sub-path inside __incoming/ so the
// callee's CheckFileAccess can gate reads to the originating context.
// For non-prompt tool calls it's "run-<callerRunID>"; for prompt() with
// a caller-supplied conversation it's "conv-<conversationID>".
type rewriterCtx struct {
	ctx          context.Context
	s3           *storage.S3Client
	logger       *zap.Logger
	target       dbq.Agent
	targetID     uuid.UUID
	callerSlug   string // caller agent's slug (A2A only); used for siblings/<slug>/ dst
	scopeKey     string // "run-<uuid>" or "conv-<uuid>"; chosen by caller of newRewriterCtx
	principal    MCPPrincipal
	extraContent []map[string]any
}

func newRewriterCtx(ctx context.Context, s3 *storage.S3Client, logger *zap.Logger, target dbq.Agent, principal MCPPrincipal, callerSlug, scopeKey string) *rewriterCtx {
	return &rewriterCtx{
		ctx:        ctx,
		s3:         s3,
		logger:     logger,
		target:     target,
		targetID:   uuid.UUID(target.ID.Bytes),
		callerSlug: callerSlug,
		scopeKey:   scopeKey,
		principal:  principal,
	}
}

// incomingDir / siblingsDir mirror agentsdk.reservedIncomingPath /
// reservedSiblingsPath. We don't import agentsdk just for the string
// constants — keeping these airlock-side as `const` documents the
// expected paths and decouples the wire shape from agentsdk versioning.
const (
	incomingDir = "__incoming"
	siblingsDir = "siblings"
)

// scopeKeyForCaller picks the __incoming/ sub-path scope for an
// inbound tool-call. Non-prompt tool calls always scope by the
// caller's run ID (ParentRunID for agent callers; the caller's run on
// the client's side carries this in the X-Run-ID header propagated to
// MCPPrincipal.ParentRunID). For prompt() with a caller-supplied
// conversation, use scopeKeyForConversation instead.
func scopeKeyForCaller(principal MCPPrincipal) string {
	if principal.Kind == MCPPrincipalAgent && principal.ParentRunID != uuid.Nil {
		return "run-" + principal.ParentRunID.String()
	}
	if principal.ParentRunID != uuid.Nil {
		return "run-" + principal.ParentRunID.String()
	}
	// External callers (anon / user / oauth) without a server-tracked
	// run still need an isolation key. UserID gives per-user isolation;
	// for anon (UserID = Nil) we fall back to a per-request UUID, which
	// means an anon caller can't reference its earlier uploaded file in
	// a subsequent call — acceptable since anon has no session anyway.
	if principal.UserID != uuid.Nil {
		return "user-" + principal.UserID.String()
	}
	return "anon-" + uuid.NewString()
}

// scopeKeyForConversation labels inbound files for a prompt() call
// where the caller supplied a validated conversationId. Files persist
// across A2A turns within the same conversation.
func scopeKeyForConversation(conversationID string) string {
	return "conv-" + conversationID
}

// materializeInbound rewrites tool-call args before forwarding to the
// agent container. No-op (fast path) when the input schema has no
// agent-file / agent-dir markers anywhere.
func materializeInbound(rc *rewriterCtx, args json.RawMessage, schemaRaw []byte) (json.RawMessage, *materializeError) {
	schema, err := parseSchema(schemaRaw)
	if err != nil || !schemaHasAgentMarker(schema) {
		return args, nil
	}
	var val any
	if len(args) > 0 {
		if err := json.Unmarshal(args, &val); err != nil {
			return nil, &materializeError{Code: rpcErrInvalidParams, Message: "decode args: " + err.Error()}
		}
	}
	rew, mErr := walkSchema(val, schema, "", rc.inboundRewriter)
	if mErr != nil {
		return nil, mErr
	}
	out, jerr := json.Marshal(rew)
	if jerr != nil {
		return nil, &materializeError{Code: rpcErrInternal, Message: "encode args: " + jerr.Error()}
	}
	return out, nil
}

// materializeOutbound rewrites a tool's JSON result before returning to
// the caller. Side effect: appends resource_link blocks to
// rc.extraContent for external principals.
func materializeOutbound(rc *rewriterCtx, body []byte, schemaRaw []byte) ([]byte, *materializeError) {
	schema, err := parseSchema(schemaRaw)
	if err != nil || !schemaHasAgentMarker(schema) {
		return body, nil
	}
	var val any
	if len(body) > 0 {
		if err := json.Unmarshal(body, &val); err != nil {
			// Body isn't JSON-shaped (e.g. plain text). Skip; the result
			// passes through unchanged.
			return body, nil
		}
	}
	rew, mErr := walkSchema(val, schema, "", rc.outboundRewriter)
	if mErr != nil {
		return nil, mErr
	}
	out, jerr := json.Marshal(rew)
	if jerr != nil {
		return nil, &materializeError{Code: rpcErrInternal, Message: "encode result: " + jerr.Error()}
	}
	return out, nil
}

// --- Walker ---

// walkSchema traverses value in parallel with schema. At each leaf where
// schema declares format=agent-file or agent-dir, fn is called. ptr is a
// dotted JSON pointer for error messages.
func walkSchema(value any, schema map[string]any, ptr string, fn func(format string, v any, ptr string) (any, *materializeError)) (any, *materializeError) {
	if schema == nil {
		return value, nil
	}
	// goai/schema emits nullable as {anyOf: [T, {type:"null"}]} — pick T
	// when the value is non-null so format markers carry through.
	if anyOf, ok := schema["anyOf"].([]any); ok && len(anyOf) == 2 && value != nil {
		for _, alt := range anyOf {
			altMap, _ := alt.(map[string]any)
			if t, _ := altMap["type"].(string); t != "null" {
				schema = altMap
				break
			}
		}
	}

	format, _ := schema["format"].(string)
	schemaType, _ := schema["type"].(string)

	if format == "agent-file" || format == "agent-dir" {
		if value == nil {
			return value, nil
		}
		return fn(format, value, ptr)
	}

	switch schemaType {
	case "object":
		m, ok := value.(map[string]any)
		if !ok {
			return value, nil
		}
		props, _ := schema["properties"].(map[string]any)
		for name, propRaw := range props {
			propSchema, _ := propRaw.(map[string]any)
			if v, has := m[name]; has {
				rew, err := walkSchema(v, propSchema, ptr+"."+name, fn)
				if err != nil {
					return nil, err
				}
				m[name] = rew
			}
		}
		return m, nil
	case "array":
		arr, ok := value.([]any)
		if !ok {
			return value, nil
		}
		itemSchema, _ := schema["items"].(map[string]any)
		for i, item := range arr {
			rew, err := walkSchema(item, itemSchema, fmt.Sprintf("%s[%d]", ptr, i), fn)
			if err != nil {
				return nil, err
			}
			arr[i] = rew
		}
		return arr, nil
	}
	return value, nil
}

// --- Inbound (caller → agent) ---

func (rc *rewriterCtx) inboundRewriter(format string, val any, ptr string) (any, *materializeError) {
	if format == "agent-dir" {
		return nil, &materializeError{
			Code:    rpcErrInvalidParams,
			Message: "directory paths not supported across MCP boundaries (at " + ptr + "); restructure as []FilePath to pass a fixed set of files",
		}
	}

	// String value → path. Either A2A caller bucket path or external
	// already-uploaded path.
	if str, ok := val.(string); ok {
		cleaned, err := storage.CleanAgentPath(str)
		if err != nil {
			return nil, &materializeError{
				Code:    rpcErrInvalidParams,
				Message: "invalid file path at " + ptr + ": " + err.Error(),
			}
		}
		if rc.principal.Kind == MCPPrincipalAgent {
			// A2A: copy from caller's bucket to callee's __incoming/<scope>/.
			srcKey := "agents/" + rc.principal.CallerAgentID.String() + "/" + cleaned
			dstPath := incomingDir + "/" + rc.scopeKey + "/" + uuid.NewString() + "-" + filepath.Base(cleaned)
			dstKey := "agents/" + rc.targetID.String() + "/" + dstPath
			if err := rc.s3.CopyObject(rc.ctx, srcKey, dstKey); err != nil {
				return nil, &materializeError{
					Code:    rpcErrServerError,
					Message: "copy across agents at " + ptr + ": " + err.Error(),
				}
			}
			return dstPath, nil
		}
		// External / web: path is whatever the caller already had in
		// this agent's bucket (e.g. previously uploaded via the chat UI
		// or returned by an earlier resources/list call). Leave as-is.
		return cleaned, nil
	}

	// Object value → inline base64 upload {filename, mimeType, data}.
	obj, ok := val.(map[string]any)
	if !ok {
		return nil, &materializeError{
			Code:    rpcErrInvalidParams,
			Message: "agent-file at " + ptr + " must be a path string or {filename, mimeType, data}",
		}
	}
	data, _ := obj["data"].(string)
	if data == "" {
		return nil, &materializeError{
			Code:    rpcErrInvalidParams,
			Message: "agent-file object at " + ptr + " missing 'data' (base64 bytes)",
		}
	}
	filename, _ := obj["filename"].(string)
	if filename == "" {
		filename = "upload.bin"
	}
	mimeType, _ := obj["mimeType"].(string)

	raw, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, &materializeError{
			Code:    rpcErrInvalidParams,
			Message: "agent-file at " + ptr + ": invalid base64: " + err.Error(),
		}
	}
	if len(raw) > maxInlineResourceBytes {
		return nil, &materializeError{
			Code:    rpcErrInvalidParams,
			Message: fmt.Sprintf("agent-file at %s exceeds %d bytes inline cap; use the web UI for large uploads", ptr, maxInlineResourceBytes),
		}
	}

	// External inbound uploads share the __incoming/<scope>/ namespace
	// with A2A — the scope check in CheckFileAccess gates reads to the
	// originating run/conversation, so anonymous and cross-caller
	// traffic stays isolated.
	dstPath := incomingDir + "/" + rc.scopeKey + "/" + uuid.NewString() + "-" + safeFilename(filename)
	dstKey := "agents/" + rc.targetID.String() + "/" + dstPath
	meta := map[string]string{"filename": filename}
	if mimeType != "" {
		meta["content-type"] = mimeType
	}
	if err := rc.s3.PutObjectWithMetadata(rc.ctx, dstKey, bytes.NewReader(raw), int64(len(raw)), meta); err != nil {
		return nil, &materializeError{
			Code:    rpcErrServerError,
			Message: "upload at " + ptr + ": " + err.Error(),
		}
	}
	return dstPath, nil
}

// --- Outbound (agent → caller) ---

func (rc *rewriterCtx) outboundRewriter(format string, val any, ptr string) (any, *materializeError) {
	if format == "agent-dir" {
		return nil, &materializeError{
			Code:    rpcErrInvalidParams,
			Message: "tool returned a directory path at " + ptr + "; not supported across MCP boundaries",
		}
	}
	str, ok := val.(string)
	if !ok || str == "" {
		return val, nil
	}
	cleaned, err := storage.CleanAgentPath(str)
	if err != nil {
		rc.logger.Warn("mcp: agent returned invalid file path",
			zap.String("ptr", ptr), zap.String("path", str), zap.Error(err))
		return "<invalid path>", nil
	}
	srcKey := "agents/" + rc.targetID.String() + "/" + cleaned

	if rc.principal.Kind == MCPPrincipalAgent {
		// A2A: copy callee's file → caller's siblings/<callee-slug>/<path>.
		// Caller's runtime sees a string path it can readFile() against.
		dstPath := siblingsDir + "/" + rc.target.Slug + "/" + cleaned
		dstKey := "agents/" + rc.principal.CallerAgentID.String() + "/" + dstPath
		if err := rc.s3.CopyObject(rc.ctx, srcKey, dstKey); err != nil {
			rc.logger.Warn("mcp: a2a result copy",
				zap.Error(err), zap.String("src", srcKey), zap.String("dst", dstKey))
			return "<copy failed>", nil
		}
		return dstPath, nil
	}

	// External (user/anon/oauth): build a resource_link content block so
	// the client knows the result file exists and can resources/read it.
	// Leave the original path string in the result body — clients see
	// both: the inline path (parseable by app code) and the link (for UI).
	info, ct, err := rc.s3.HeadObject(rc.ctx, srcKey)
	if err != nil {
		rc.logger.Warn("mcp: head returned file",
			zap.String("key", srcKey), zap.Error(err))
		return "<file missing>", nil
	}
	name := info.Metadata["filename"]
	if name == "" {
		name = filepath.Base(cleaned)
	}
	meta := map[string]any{
		"airlock.run/size": info.Size,
	}
	// For files exceeding the inline cap, attach a presigned URL so
	// clients that can't slurp 10MB+ blobs via resources/read still have
	// a way to fetch the bytes.
	if info.Size > int64(maxInlineResourceBytes) {
		url, perr := rc.s3.PublicPresignGetURL(rc.ctx, srcKey, presignedURLTTL)
		if perr == nil {
			meta["airlock.run/downloadUrl"] = url
			meta["airlock.run/downloadExpiresAt"] = time.Now().Add(presignedURLTTL).UTC().Format(time.RFC3339)
		} else {
			rc.logger.Warn("mcp: presign download URL", zap.Error(perr))
		}
	}
	block := map[string]any{
		"type":     "resource_link",
		"uri":      "agent://" + cleaned,
		"name":     name,
		"mimeType": ct,
		"_meta":    meta,
	}
	rc.extraContent = append(rc.extraContent, block)
	return val, nil
}

// --- Helpers ---

// parseSchema returns the schema as a parsed map. Empty / unparseable
// schemas yield (nil, nil) so callers can fast-path through.
func parseSchema(raw []byte) (map[string]any, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// schemaHasAgentMarker walks the schema tree once looking for any
// format=agent-file or agent-dir marker. Lets us skip the full
// args/result walk for the common no-FilePath tool.
func schemaHasAgentMarker(schema map[string]any) bool {
	if schema == nil {
		return false
	}
	if f, _ := schema["format"].(string); f == "agent-file" || f == "agent-dir" {
		return true
	}
	if props, ok := schema["properties"].(map[string]any); ok {
		for _, v := range props {
			if m, ok := v.(map[string]any); ok && schemaHasAgentMarker(m) {
				return true
			}
		}
	}
	if items, ok := schema["items"].(map[string]any); ok {
		if schemaHasAgentMarker(items) {
			return true
		}
	}
	if anyOf, ok := schema["anyOf"].([]any); ok {
		for _, alt := range anyOf {
			if m, ok := alt.(map[string]any); ok && schemaHasAgentMarker(m) {
				return true
			}
		}
	}
	return false
}

// materializePromptFiles handles the `prompt` meta-tool's `files`
// field. The schema-driven walker doesn't apply here because FileInfo
// isn't a FilePath — it's a struct with explicit metadata fields. Two
// shapes accepted:
//
//   - Legacy {path, filename, contentType, size} — caller already
//     uploaded the file. For A2A, copy from caller's bucket to callee's
//     __incoming/<scope>/ and rewrite path; for external, leave as-is
//     (the caller is the chat user and the path was uploaded via the
//     web upload endpoint).
//   - New inline {filename, mimeType, data} (base64) — external MCP
//     upload. Decode, S3 PUT to callee's __incoming/<scope>/, build
//     FileInfo with the new path.
//
// scopeKey is the sub-path inside __incoming/: "conv-<uuid>" when the
// caller supplied (and we validated) a conversation, or
// "run-<callerRunID>" otherwise. CheckFileAccess on the callee gates
// reads against this scope, isolating files across callers.
//
// Rejected for agent principal: inline shape (an agent calling a
// sibling should pass an existing path, not embed bytes — round-tripping
// through base64 wastes the cross-bucket copy fast-path).
func (s *MCPServer) materializePromptFiles(ctx context.Context, h *agentHandler, q *dbq.Queries, target dbq.Agent, principal MCPPrincipal, scopeKey string, raws []json.RawMessage) ([]agentsdk.FileInfo, *materializeError) {
	if len(raws) == 0 {
		return nil, nil
	}
	out := make([]agentsdk.FileInfo, 0, len(raws))
	targetID := uuid.UUID(target.ID.Bytes)
	for i, raw := range raws {
		var probe map[string]any
		if err := json.Unmarshal(raw, &probe); err != nil {
			return nil, &materializeError{Code: rpcErrInvalidParams, Message: fmt.Sprintf("files[%d]: decode: %s", i, err)}
		}
		// Inline shape: presence of `data` (base64) wins.
		if dataStr, ok := probe["data"].(string); ok && dataStr != "" {
			if principal.Kind == MCPPrincipalAgent {
				return nil, &materializeError{Code: rpcErrInvalidParams, Message: fmt.Sprintf("files[%d]: agent callers must pass {path, ...}, not inline {data, ...}", i)}
			}
			filename, _ := probe["filename"].(string)
			if filename == "" {
				filename = "upload.bin"
			}
			mimeType, _ := probe["mimeType"].(string)
			rawBytes, err := base64.StdEncoding.DecodeString(dataStr)
			if err != nil {
				return nil, &materializeError{Code: rpcErrInvalidParams, Message: fmt.Sprintf("files[%d]: invalid base64: %s", i, err)}
			}
			if len(rawBytes) > maxInlineResourceBytes {
				return nil, &materializeError{Code: rpcErrInvalidParams, Message: fmt.Sprintf("files[%d] exceeds %d-byte inline cap", i, maxInlineResourceBytes)}
			}
			dstPath := incomingDir + "/" + scopeKey + "/" + uuid.NewString() + "-" + safeFilename(filename)
			dstKey := "agents/" + targetID.String() + "/" + dstPath
			meta := map[string]string{"filename": filename}
			if mimeType != "" {
				meta["content-type"] = mimeType
			}
			if err := h.s3.PutObjectWithMetadata(ctx, dstKey, bytes.NewReader(rawBytes), int64(len(rawBytes)), meta); err != nil {
				return nil, &materializeError{Code: rpcErrServerError, Message: fmt.Sprintf("files[%d]: upload: %s", i, err)}
			}
			out = append(out, agentsdk.FileInfo{
				Path:        dstPath,
				Filename:    filename,
				ContentType: mimeType,
				Size:        int64(len(rawBytes)),
			})
			continue
		}
		// Legacy path-bearing shape.
		var fi agentsdk.FileInfo
		if err := json.Unmarshal(raw, &fi); err != nil {
			return nil, &materializeError{Code: rpcErrInvalidParams, Message: fmt.Sprintf("files[%d]: decode FileInfo: %s", i, err)}
		}
		if fi.Path == "" {
			return nil, &materializeError{Code: rpcErrInvalidParams, Message: fmt.Sprintf("files[%d]: path is required (or send inline {filename, mimeType, data})", i)}
		}
		cleaned, err := storage.CleanAgentPath(fi.Path)
		if err != nil {
			return nil, &materializeError{Code: rpcErrInvalidParams, Message: fmt.Sprintf("files[%d]: invalid path: %s", i, err)}
		}
		if principal.Kind == MCPPrincipalAgent && principal.CallerAgentID != uuid.Nil {
			// A2A: copy from caller's bucket to callee's __incoming/<scope>/.
			srcKey := "agents/" + principal.CallerAgentID.String() + "/" + cleaned
			dstPath := incomingDir + "/" + scopeKey + "/" + uuid.NewString() + "-" + filepath.Base(cleaned)
			dstKey := "agents/" + targetID.String() + "/" + dstPath
			if err := h.s3.CopyObject(ctx, srcKey, dstKey); err != nil {
				return nil, &materializeError{Code: rpcErrServerError, Message: fmt.Sprintf("files[%d]: cross-agent copy: %s", i, err)}
			}
			fi.Path = dstPath
		} else {
			fi.Path = cleaned
		}
		out = append(out, fi)
	}
	return out, nil
}

// safeFilename strips path separators + a few hostile characters so a
// caller can't inject "../" into the S3 key via the filename field.
// We already UUID-prefix the destination, but defense-in-depth keeps
// the key readable in logs/UI.
func safeFilename(name string) string {
	name = filepath.Base(name)
	name = strings.ReplaceAll(name, "\x00", "")
	name = strings.ReplaceAll(name, "/", "_")
	name = strings.ReplaceAll(name, "\\", "_")
	if name == "" || name == "." || name == ".." {
		return "file.bin"
	}
	return name
}
