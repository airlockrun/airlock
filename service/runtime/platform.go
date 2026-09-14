package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/airlockrun/agentsdk/capability"
	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/builder"
	"github.com/airlockrun/airlock/db/dbq"
	agentstorage "github.com/airlockrun/airlock/service/agentstorage"
	"github.com/airlockrun/airlock/service/systemchat"
	"github.com/airlockrun/goai/tool"
	"github.com/airlockrun/sol/websearch"
	"github.com/google/uuid"
)

// InvokePlatform receives only broker-authorized definitions and host attribution.
// Resource credentials and MCP negotiation stay in their existing backing services.
func (h *Service) InvokePlatform(ctx context.Context, scope wire.RuntimeContext, definition capability.Definition, input json.RawMessage) (tool.Result, error) {
	var err error
	scope, err = h.admittedContext(ctx, scope)
	if err != nil {
		return tool.Result{}, err
	}
	agentID, err := uuid.Parse(scope.AgentID)
	if err != nil {
		return tool.Result{}, err
	}
	runID, err := uuid.Parse(scope.RunID)
	if err != nil {
		return tool.Result{}, err
	}
	encode := func(v any, err error) (tool.Result, error) {
		if err != nil {
			return tool.Result{}, err
		}
		data, err := json.Marshal(v)
		return tool.Result{Output: string(data)}, err
	}
	switch definition.Path.Kind() {
	case capability.Connection:
		var req capability.ConnectionRequestInput
		if err := json.Unmarshal(input, &req); err != nil {
			return tool.Result{}, err
		}
		body, ok := req.Body.(string)
		if req.Body != nil && !ok {
			if definition.Path.CanonicalOperation() != "request_json" {
				return tool.Result{}, errors.New("raw connection body must be a string")
			}
			data, err := json.Marshal(req.Body)
			if err != nil {
				return tool.Result{}, err
			}
			body = string(data)
		}
		response, err := h.RequestConnection(ctx, agentID, definition.Path.CanonicalNamespace(), wire.ProxyRequest{Method: req.Method, Path: req.Path, Headers: req.Headers, Body: body})
		if err != nil {
			return tool.Result{}, err
		}
		if definition.Path.CanonicalOperation() == "request_json" {
			if response.StatusCode < 200 || response.StatusCode >= 300 {
				return tool.Result{}, fmt.Errorf("connection returned HTTP %d", response.StatusCode)
			}
			if !json.Valid(response.Body) {
				return tool.Result{}, errors.New("connection returned invalid JSON")
			}
			return tool.Result{Output: string(response.Body)}, nil
		}
		return encode(map[string]any{"status": response.StatusCode, "headers": response.Headers, "body": string(response.Body)}, nil)
	case capability.MCP:
		return encode(h.CallMCPTool(ctx, agentID, definition.Path.CanonicalNamespace(), wire.MCPToolCallRequest{Tool: definition.Path.CanonicalOperation(), Arguments: input}))
	case capability.Topic:
		convID, err := uuid.Parse(scope.ConversationID)
		if err != nil {
			return tool.Result{}, errors.New("topic subscriptions require a conversation")
		}
		q := dbq.New(h.db.Pool())
		topic, err := q.GetTopicBySlug(ctx, dbq.GetTopicBySlugParams{AgentID: toPgUUID(agentID), Slug: definition.Path.CanonicalNamespace()})
		if err != nil {
			return tool.Result{}, err
		}
		if definition.Path.CanonicalOperation() == "subscribe" {
			err = q.SubscribeTopic(ctx, dbq.SubscribeTopicParams{ConversationID: toPgUUID(convID), TopicID: topic.ID})
		} else {
			err = q.UnsubscribeTopic(ctx, dbq.UnsubscribeTopicParams{ConversationID: toPgUUID(convID), TopicID: topic.ID})
		}
		return encode(map[string]bool{"ok": err == nil}, err)
	case capability.Air:
		switch definition.Path.CanonicalOperation() {
		case "http_request":
			var req wire.HTTPRequest
			if err := json.Unmarshal(input, &req); err != nil {
				return tool.Result{}, err
			}
			req.RunID = scope.RunID
			return encode(h.RuntimeHTTP(ctx, scope, req))
		case "analyze_image", "transcribe_audio", "generate_image", "speak", "embed":
			return h.RuntimeMedia(ctx, scope, definition.Path.CanonicalOperation(), input)
		case "request_upgrade":
			var req capability.RequestUpgradeInput
			if err := json.Unmarshal(input, &req); err != nil {
				return tool.Result{}, err
			}
			if req.Description == "" {
				return tool.Result{}, errors.New("upgrade description is required")
			}
			origin, err := systemchat.CaptureHostedAsyncOrigin(ctx, dbq.New(h.db.Pool()), agentID, runID)
			if err != nil {
				return tool.Result{}, err
			}
			if err := h.builder.AcquireUpgradeLock(ctx, scope.AgentID); err != nil {
				return tool.Result{}, err
			}
			upgrade := builder.UpgradeInput{ChatOriginID: origin, AgentID: scope.AgentID, Reason: "llm_request", Description: req.Description, ConversationID: scope.ConversationID}
			if scope.Caller.User != nil {
				userID, err := uuid.Parse(scope.Caller.User.ID)
				if err != nil {
					return tool.Result{}, err
				}
				upgrade.InitiatorUserID = toPgUUID(userID)
			}
			go h.builder.RunUpgrade(context.Background(), upgrade)
			return encode(map[string]bool{"accepted": true}, nil)
		case "web_search":
			var req capability.WebSearchInput
			if err := json.Unmarshal(input, &req); err != nil {
				return tool.Result{}, err
			}
			if req.Query == "" {
				return tool.Result{}, errors.New("query is required")
			}
			client, err := ResolveSearchClient(ctx, h.db, h.encryptor, h.logger, scope.AgentID, "")
			if err != nil {
				return tool.Result{}, err
			}
			return encode(client.Search(ctx, websearch.Request{Query: req.Query, Count: req.Count}))
		case "file_share_url":
			var req capability.FileShareURLInput
			if err := json.Unmarshal(input, &req); err != nil {
				return tool.Result{}, err
			}
			file, err := h.files.ResolveForRuntime(ctx, scope, req.Path, agentstorage.OperationRead)
			if err != nil {
				return tool.Result{}, err
			}
			ttl := req.ExpiresInMinutes
			if ttl <= 0 {
				ttl = 60
			}
			if ttl > 1440 {
				ttl = 1440
			}
			url, err := h.s3.PublicPresignGetURL(ctx, file.S3Key, time.Duration(ttl)*time.Minute)
			return encode(map[string]string{"url": url}, err)
		case "attach_to_context":
			var req capability.PathInput
			if err := json.Unmarshal(input, &req); err != nil {
				return tool.Result{}, err
			}
			file, err := h.files.ResolveForRuntime(ctx, scope, req.Path, agentstorage.OperationRead)
			if err != nil {
				return tool.Result{}, err
			}
			_, mimeType, err := h.s3.HeadObject(ctx, file.S3Key)
			if err != nil {
				return tool.Result{}, err
			}
			marked, err := dbq.New(h.db.Pool()).MarkRuntimeAttachment(ctx, dbq.MarkRuntimeAttachmentParams{RunID: toPgUUID(runID), Path: file.Relative})
			if err != nil {
				return tool.Result{}, err
			}
			if marked == 0 {
				return tool.Result{Output: "Already attached " + file.Relative}, nil
			}
			return tool.Result{Output: "Attached " + file.Relative, Attachments: []tool.Attachment{{Data: "s3ref:" + file.Relative, MimeType: mimeType, Filename: filepath.Base(file.Relative)}}}, nil
		case "output":
			var req capability.OutputInput
			if err := json.Unmarshal(input, &req); err != nil {
				return tool.Result{}, err
			}
			convID, err := uuid.Parse(scope.ConversationID)
			if err != nil {
				return tool.Result{}, errors.New("output requires a conversation")
			}
			for i := range req.Parts {
				part := &req.Parts[i]
				wire.ResolveDisplayPart(part)
				if part.Type != "image" && part.Type != "file" && part.Type != "audio" && part.Type != "video" {
					return tool.Result{}, errors.New("output is media-only")
				}
				if part.URL != "" && part.Source == "" && len(part.Data) == 0 {
					url, err := h.httpNetwork.ParseURL(part.URL)
					if err != nil {
						return tool.Result{}, err
					}
					part.URL = url.String()
					continue
				}
				if len(part.Data) > 0 {
					if part.Source != "" || part.URL != "" || len(part.Data) > 25<<20 {
						return tool.Result{}, errors.New("invalid inline media")
					}
					name := part.Filename
					if name == "" {
						name = "file"
					}
					if !ValidMediaFilename(name) {
						return tool.Result{}, errors.New("invalid media filename")
					}
					key := "agents/" + scope.AgentID + "/media/" + uuid.NewString() + "/" + name
					if err := h.s3.PutObjectStream(ctx, key, bytes.NewReader(part.Data), int64(len(part.Data)), part.MimeType); err != nil {
						return tool.Result{}, err
					}
					part.Source, part.Data = key, nil
					continue
				}
				if part.Source == "" || part.URL != "" {
					return tool.Result{}, errors.New("a media source is required")
				}
				file, err := h.files.ResolveForRuntime(ctx, scope, part.Source, agentstorage.OperationRead)
				if err != nil {
					return tool.Result{}, err
				}
				name := part.Filename
				if name == "" {
					name = filepath.Base(file.Relative)
				}
				if !ValidMediaFilename(name) {
					return tool.Result{}, errors.New("invalid media filename")
				}
				key := "agents/" + scope.AgentID + "/media/" + uuid.NewString() + "/" + name
				if err := h.s3.CopyObject(ctx, file.S3Key, key); err != nil {
					return tool.Result{}, err
				}
				part.Source = key
			}
			err = PostToConversation(ctx, PostDeps{DB: h.db, PubSub: h.pubsub, BridgeMgr: h.bridgeMgr, S3: h.s3, Logger: h.logger}, PostOpts{AgentID: agentID, ConversationID: convID, RunID: runID, Role: "assistant", Parts: req.Parts, Ephemeral: true})
			return encode(map[string]bool{"ok": err == nil}, err)
		}
	}
	return tool.Result{}, fmt.Errorf("platform capability %s is unavailable", strings.TrimSpace(definition.Path.ID()))
}
