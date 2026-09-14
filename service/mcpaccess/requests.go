package mcpaccess

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/airlockrun/airlock/service/capabilities"
	"github.com/airlockrun/goai/tool"
	"github.com/google/uuid"
)

func NormalizeRequestID(raw json.RawMessage) ([]byte, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value any
	if err := d.Decode(&value); err != nil {
		return nil, err
	}
	if d.Decode(new(any)) != io.EOF {
		return nil, service.ErrInvalidInput
	}
	switch value.(type) {
	case string, json.Number:
		return json.Marshal(value)
	default:
		return nil, service.ErrInvalidInput
	}
}

// requestIdentity isolates first-party sessions and OAuth clients, including
// account epochs so a credential reset cannot inherit active cancellation rights.
func requestIdentity(p Principal) string {
	proof := p.Identity.Provenance()
	key, _ := json.Marshal([]any{proof.Profile, proof.UserID, proof.SessionID, proof.ClientID, proof.AuthEpoch})
	return string(key)
}

// CallTool owns reservation, activation, live cancellation and cleanup. The
// callback receives a server-created run, never a caller-selected run identity.
func (s *Service) CallTool(ctx context.Context, principal Principal, targetID uuid.UUID, requestID json.RawMessage, name string, input json.RawMessage, runtime Runtime, platform capabilities.Platform, prepare func(context.Context, *RunFiles, json.RawMessage) (json.RawMessage, error)) (result tool.Result, runID uuid.UUID, callErr error) {
	if runtime == nil || platform == nil || prepare == nil {
		panic("mcpaccess: runtime, platform and preparation callback are required")
	}
	p, _, err := s.authorize(ctx, principal, targetID)
	if err != nil {
		return tool.Result{}, uuid.Nil, err
	}
	if _, err := s.Tool(ctx, principal, targetID, name); err != nil {
		return tool.Result{}, uuid.Nil, err
	}
	id, err := NormalizeRequestID(requestID)
	if err != nil {
		return tool.Result{}, uuid.Nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	q := dbq.New(s.db.Pool())
	identity, owner := "", uuid.New()
	authenticated := principal.Kind != Anonymous
	if authenticated {
		identity = requestIdentity(principal)
		rows, err := q.ReserveMCPRequest(ctx, dbq.ReserveMCPRequestParams{TargetAgentID: pgID(targetID), PrincipalIdentity: identity, RequestID: id, OwnerToken: pgID(owner)})
		if err != nil {
			return tool.Result{}, uuid.Nil, err
		}
		if rows != 1 {
			return tool.Result{}, uuid.Nil, errors.New("request id is already active")
		}
	}
	var watched chan struct{}
	defer func() {
		cancel()
		if watched != nil {
			<-watched
		}
		if authenticated {
			cleanup, end := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer end()
			// The opaque owner token authorizes cleanup even after credential revocation.
			callErr = errors.Join(callErr, q.ReleaseMCPRequest(cleanup, dbq.ReleaseMCPRequestParams{TargetAgentID: pgID(targetID), PrincipalIdentity: identity, RequestID: id, OwnerToken: pgID(owner)}))
		}
	}()
	if err := runtime.EnsureRuntime(ctx, targetID); err != nil {
		return tool.Result{}, uuid.Nil, err
	}
	broker := capabilities.New(s.db, runtime, platform)
	result, runID, invokeErr := broker.CallTool(ctx, p, targetID, name, input, func(run dbq.Run, input json.RawMessage) (json.RawMessage, error) {
		runID := uuid.UUID(run.ID.Bytes)
		if _, _, err := s.authorize(ctx, principal, targetID); err != nil {
			return nil, err
		}
		if authenticated {
			if _, _, err := s.fileCaller(ctx, principal, targetID, runID); err != nil {
				return nil, err
			}
			rows, err := q.ActivateMCPRequest(ctx, dbq.ActivateMCPRequestParams{TargetAgentID: pgID(targetID), PrincipalIdentity: identity, RequestID: id, OwnerToken: pgID(owner), RunID: run.ID})
			if err != nil {
				return nil, err
			}
			if rows != 1 {
				return nil, context.Canceled
			}
		}
		watched = make(chan struct{})
		go func() {
			defer close(watched)
			ticker := time.NewTicker(250 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if _, err := s.Tool(ctx, principal, targetID, name); err != nil {
						cancel()
						return
					}
					if authenticated {
						_, err := q.GetMCPActiveRequest(ctx, dbq.GetMCPActiveRequestParams{TargetAgentID: pgID(targetID), PrincipalIdentity: identity, RequestID: id, RunID: run.ID})
						if err != nil {
							cancel()
							return
						}
					}
				}
			}
		}()
		return prepare(ctx, &RunFiles{service: s, principal: principal, targetID: targetID, runID: runID}, input)
	})
	if invokeErr == nil {
		if _, err := s.Tool(ctx, principal, targetID, name); err != nil {
			return tool.Result{}, runID, err
		}
		if authenticated {
			if _, err := q.GetMCPActiveRequest(ctx, dbq.GetMCPActiveRequestParams{TargetAgentID: pgID(targetID), PrincipalIdentity: identity, RequestID: id, RunID: pgID(runID)}); err != nil {
				return tool.Result{}, runID, context.Canceled
			}
		}
	}
	return result, runID, invokeErr
}

type Runtime interface {
	capabilities.AppInvoker
	EnsureRuntime(context.Context, uuid.UUID) error
}

// Cancel consumes only the caller's live target-bound request. Deletion is the
// durable cancellation signal; the request owner observes it on any replica.
func (s *Service) Cancel(ctx context.Context, principal Principal, targetID uuid.UUID, requestID json.RawMessage) error {
	if _, _, err := s.authorize(ctx, principal, targetID); err != nil {
		return err
	}
	if principal.Kind == Anonymous {
		return service.ErrForbidden
	}
	id, err := NormalizeRequestID(requestID)
	if err != nil {
		return err
	}
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	identity := requestIdentity(principal)
	request, err := q.LockMCPRequest(ctx, dbq.LockMCPRequestParams{TargetAgentID: pgID(targetID), PrincipalIdentity: identity, RequestID: id})
	if err != nil {
		return err
	}
	if request.RunID.Valid {
		if _, _, err := s.fileCaller(ctx, principal, targetID, uuid.UUID(request.RunID.Bytes)); err != nil {
			return err
		}
	}
	if err := q.ReleaseMCPRequest(ctx, dbq.ReleaseMCPRequestParams{TargetAgentID: pgID(targetID), PrincipalIdentity: identity, RequestID: id, OwnerToken: request.OwnerToken}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
