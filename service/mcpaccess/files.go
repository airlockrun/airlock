package mcpaccess

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/airlockrun/airlock/service/agentstorage"
	"github.com/airlockrun/airlock/storage"
	"github.com/google/uuid"
)

func (s *Service) fileCaller(ctx context.Context, principal Principal, targetID, runID uuid.UUID) (agentstorage.Caller, dbq.Run, error) {
	p, access, err := s.authorize(ctx, principal, targetID)
	if err != nil {
		return agentstorage.Caller{}, dbq.Run{}, err
	}
	caller := agentstorage.Caller{Principal: p, Access: access, UserID: p.UserID}
	if runID == uuid.Nil {
		return caller, dbq.Run{}, nil
	}
	run, err := dbq.New(s.db.Pool()).GetRunByIDAndAgent(ctx, dbq.GetRunByIDAndAgentParams{ID: pgID(runID), AgentID: pgID(targetID)})
	if err != nil || run.TriggerType != "mcp" || run.CallerUserID != pgID(p.UserID) {
		return agentstorage.Caller{}, dbq.Run{}, service.ErrForbidden
	}
	origin, err := dbq.New(s.db.Pool()).GetRunOrigin(ctx, pgID(runID))
	if err != nil || origin.AgentID != pgID(targetID) || origin.Ingress != "mcp" {
		return agentstorage.Caller{}, dbq.Run{}, service.ErrForbidden
	}
	if principal.Kind == Anonymous {
		if origin.Actor != "anonymous" || origin.UserID.Valid {
			return agentstorage.Caller{}, dbq.Run{}, service.ErrForbidden
		}
	} else {
		proof := principal.Identity.Provenance()
		if origin.Actor != "user" || origin.UserID != pgID(proof.UserID) || origin.CredentialProfile != proof.Profile || origin.SessionID != pgID(proof.SessionID) || !origin.AuthEpoch.Valid || origin.AuthEpoch.Int64 != proof.AuthEpoch || origin.ClientID.String != proof.ClientID || origin.Audience.String != proof.Audience {
			return agentstorage.Caller{}, dbq.Run{}, service.ErrForbidden
		}
	}
	if !authz.AccessAtLeast(agentsdk.Access(run.CallerAccess), caller.Access) {
		caller.Access = agentsdk.Access(run.CallerAccess)
	}
	caller.RunID = runID
	if run.CallerConversationID.Valid {
		caller.ConversationID = uuid.UUID(run.CallerConversationID.Bytes)
	}
	return caller, run, nil
}

func (s *Service) ListRoots(ctx context.Context, p Principal, targetID uuid.UUID) ([]agentstorage.ListRoot, error) {
	caller, _, err := s.fileCaller(ctx, p, targetID, uuid.Nil)
	if err != nil {
		return nil, err
	}
	return s.files.ListRoots(ctx, caller, targetID)
}

func (s *Service) FilterList(ctx context.Context, p Principal, targetID uuid.UUID, paths []string) ([]agentstorage.ResolvedPath, error) {
	caller, _, err := s.fileCaller(ctx, p, targetID, uuid.Nil)
	if err != nil {
		return nil, err
	}
	return s.files.FilterList(ctx, caller, targetID, paths)
}

func (s *Service) ResolveFile(ctx context.Context, p Principal, targetID uuid.UUID, path string) (agentstorage.ResolvedPath, error) {
	caller, _, err := s.fileCaller(ctx, p, targetID, uuid.Nil)
	if err != nil {
		return agentstorage.ResolvedPath{}, err
	}
	return s.files.Resolve(ctx, caller, targetID, path, agentstorage.OperationRead)
}

// RunFiles is an exact-run handle minted only by CallTool. In particular an
// anonymous caller cannot obtain another request's conversation or file scope.
type RunFiles struct {
	service         *Service
	principal       Principal
	targetID, runID uuid.UUID
}

func (f *RunFiles) Resolve(ctx context.Context, path string) (agentstorage.ResolvedPath, error) {
	caller, run, err := f.service.fileCaller(ctx, f.principal, f.targetID, f.runID)
	if err != nil {
		return agentstorage.ResolvedPath{}, err
	}
	if run.Status != "running" && run.Status != "success" {
		return agentstorage.ResolvedPath{}, service.ErrForbidden
	}
	return f.service.files.Resolve(ctx, caller, f.targetID, path, agentstorage.OperationRead)
}

func (f *RunFiles) Upload(ctx context.Context, s3 *storage.S3Client, filename, mimeType string, data []byte) (string, error) {
	if s3 == nil {
		panic("mcpaccess: object storage is required")
	}
	caller, run, err := f.service.fileCaller(ctx, f.principal, f.targetID, f.runID)
	if err != nil {
		return "", err
	}
	if run.Status != "running" {
		return "", service.ErrForbidden
	}
	if len(data) > 10<<20 {
		return "", service.ErrInvalidInput
	}
	scope := "user-" + caller.UserID.String()
	if f.principal.Kind == Anonymous {
		if caller.ConversationID == uuid.Nil {
			return "", service.ErrForbidden
		}
		scope = "conv-" + caller.ConversationID.String()
	}
	name := filepath.Base(filename)
	name = strings.NewReplacer("\x00", "", "/", "_", "\\", "_").Replace(name)
	if name == "" || name == "." || name == ".." {
		name = "file.bin"
	}
	path := "__incoming/" + scope + "/" + uuid.NewString() + "-" + name
	meta := map[string]string{"filename": filename}
	if mimeType != "" {
		meta["content-type"] = mimeType
	}
	if err := s3.PutObjectWithMetadata(ctx, "agents/"+f.targetID.String()+"/"+path, bytes.NewReader(data), int64(len(data)), meta); err != nil {
		return "", err
	}
	return path, nil
}
