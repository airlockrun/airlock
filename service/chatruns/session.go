package chatruns

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/airlockrun/agentsdk/agentruntime"

	"github.com/airlockrun/airlock/attachref"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/storage"
	"github.com/airlockrun/sol/session"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

type SessionCodec struct {
	Normalize func(pgtype.UUID, []dbq.AgentMessage) ([]dbq.AgentMessage, error)
	Decode    func(dbq.AgentMessage) session.Message
	Store     func(context.Context, *dbq.Queries, pgtype.UUID, pgtype.UUID, string, session.Message) (pgtype.UUID, error)
	Cleanup   func(context.Context, string, pgtype.UUID, pgtype.UUID)
}

// NewSession creates a store for one host-owned run. Every database transaction
// locks the lease before the conversation and checks the history revision.
func NewSession(database *db.DB, s3 *storage.S3Client, agentID, conversationID, runID, ownerToken uuid.UUID, source string, codec SessionCodec) session.SessionStore {
	if agentID == uuid.Nil || conversationID == uuid.Nil || runID == uuid.Nil || ownerToken == uuid.Nil {
		panic("runtime session: scoped IDs are required")
	}
	if database == nil || s3 == nil || codec.Normalize == nil || codec.Decode == nil || codec.Store == nil || codec.Cleanup == nil {
		panic("runtime session: database, storage and codec are required")
	}
	return &runtimeSession{db: database, s3: s3, codec: codec, agentID: agentID, conversationID: conversationID, runID: runID, ownerToken: ownerToken, source: source}
}

type runtimeSession struct {
	db                                         *db.DB
	s3                                         *storage.S3Client
	codec                                      SessionCodec
	agentID, conversationID, runID, ownerToken uuid.UUID
	source                                     string
	revision                                   int64
	loaded                                     bool
	task                                       bool
}

func (s *runtimeSession) transaction(ctx context.Context) (pgx.Tx, *dbq.Queries, error) {
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return nil, nil, err
	}
	q := dbq.New(tx)
	// Task maintenance and cancellation take this lock before task/lease rows.
	// Taking it first also serializes checkpoint, transcript and compaction writes.
	if s.task {
		if err := q.LockAgentTaskScheduler(ctx); err != nil {
			tx.Rollback(ctx)
			return nil, nil, err
		}
	}
	conversationID, err := q.LockConversationRunLease(ctx, dbq.LockConversationRunLeaseParams{RunID: pgID(s.runID), OwnerToken: pgID(s.ownerToken)})
	if err == nil && conversationID != pgID(s.conversationID) {
		err = errors.New("runtime session: conversation scope mismatch")
	}
	if err == nil {
		_, err = q.GetConversationByIDAndAgentForUpdate(ctx, dbq.GetConversationByIDAndAgentForUpdateParams{ID: pgID(s.conversationID), AgentID: pgID(s.agentID)})
	}
	if err != nil {
		tx.Rollback(ctx)
		return nil, nil, err
	}
	return tx, q, nil
}

func (s *runtimeSession) Load(ctx context.Context) ([]session.Message, error) {
	tx, q, err := s.transaction(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	rows, err := q.ListSessionMessagesByConversation(ctx, pgID(s.conversationID))
	if err != nil {
		return nil, err
	}
	rows, err = s.codec.Normalize(pgID(s.conversationID), rows)
	if err != nil {
		return nil, err
	}
	result := make([]session.Message, 0, len(rows))
	for _, row := range rows {
		result = append(result, s.codec.Decode(row))
	}
	revision, err := q.GetSessionContextRevision(ctx, pgID(s.conversationID))
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	s.revision, s.loaded = revision, true
	return result, nil
}

func (s *runtimeSession) Append(ctx context.Context, messages []session.Message) error {
	return s.write(ctx, messages, false, 0, nil)
}
func (s *runtimeSession) Compact(ctx context.Context, summary []session.Message, tokensFreed int) error {
	if len(summary) == 0 {
		return errors.New("runtime session: compaction summary is required")
	}
	return s.write(ctx, summary, true, tokensFreed, nil)
}

func (s *runtimeSession) write(ctx context.Context, messages []session.Message, compact bool, tokensFreed int, checkpoint *agentruntime.Checkpoint) error {
	if !s.loaded {
		return errors.New("runtime session: load is required before writing")
	}
	if err := attachref.ResolveForStorage(ctx, s.s3, s.agentID, messages); err != nil {
		return err
	}
	tx, q, err := s.transaction(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	current, err := q.GetSessionContextRevision(ctx, pgID(s.conversationID))
	if err != nil {
		return err
	}
	if checkpoint != nil {
		call, err := q.GetAgentTaskCall(ctx, pgID(s.runID))
		if err != nil {
			return err
		}
		if checkpoint.Version != 1 || checkpoint.ContractHash != call.ContractHash || call.SessionID != pgID(s.conversationID) || call.OwnerToken != pgID(s.ownerToken) {
			return errors.New("agent checkpoint scope mismatch")
		}
		raw, err := json.Marshal(checkpoint)
		if err != nil {
			return err
		}
		if checkpoint.Revision == call.CheckpointRevision {
			matches, err := q.AgentTaskCheckpointMatches(ctx, dbq.AgentTaskCheckpointMatchesParams{ID: call.ID, Checkpoint: raw})
			if err != nil {
				return err
			}
			if !matches {
				return errors.New("agent checkpoint revision conflict")
			}
			s.revision = current
			return tx.Commit(ctx)
		}
		if checkpoint.Revision != call.CheckpointRevision+1 {
			return errors.New("agent checkpoint revision conflict")
		}
		n, err := q.SaveAgentTaskCheckpoint(ctx, dbq.SaveAgentTaskCheckpointParams{ID: call.ID, OwnerToken: call.OwnerToken, Revision: call.CheckpointRevision, Checkpoint: raw})
		if err != nil {
			return err
		}
		if n != 1 {
			return errors.New("agent checkpoint ownership lost")
		}
	}
	if current != s.revision {
		return errors.New("runtime session: revision conflict")
	}
	source := s.source
	if compact {
		source = "compaction"
		parts, err := json.Marshal([]map[string]any{{"type": "checkpoint", "kind": "compact", "tokensFreed": tokensFreed}})
		if err != nil {
			return err
		}
		if _, err := q.CreateMessage(ctx, dbq.CreateMessageParams{ConversationID: pgID(s.conversationID), RunID: pgID(s.runID), Role: "system", Source: "checkpoint", Parts: parts}); err != nil {
			return err
		}
	}
	var first pgtype.UUID
	for i, msg := range messages {
		id, err := s.codec.Store(ctx, q, pgID(s.conversationID), pgID(s.runID), source, msg)
		if err != nil {
			return err
		}
		if i == 0 {
			first = id
		}
	}
	if compact {
		if !first.Valid {
			return errors.New("runtime session: missing compaction anchor")
		}
		if err := q.SetConversationCheckpoint(ctx, dbq.SetConversationCheckpointParams{ConversationID: pgID(s.conversationID), CheckpointMessageID: first}); err != nil {
			return err
		}
	}
	revision, err := q.GetSessionContextRevision(ctx, pgID(s.conversationID))
	if err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	s.revision = revision
	if compact {
		s.codec.Cleanup(ctx, s.agentID.String(), pgID(s.conversationID), first)
	}
	return nil
}

// NewAgentSession uses the conversation history codec and adds an atomic task
// journal. Checkpoint.Append and the journal revision commit in the same tx.
func NewAgentSession(database *db.DB, s3 *storage.S3Client, agentID, conversationID, runID, ownerToken uuid.UUID, codec SessionCodec) agentruntime.Store {
	s := NewSession(database, s3, agentID, conversationID, runID, ownerToken, "application", codec).(*runtimeSession)
	s.task = true
	return s
}

func (s *runtimeSession) LoadCheckpoint(ctx context.Context) (*agentruntime.Checkpoint, error) {
	tx, q, err := s.transaction(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	call, err := q.GetAgentTaskCall(ctx, pgID(s.runID))
	if err != nil {
		return nil, err
	}
	if call.CheckpointRevision == 0 && len(call.Checkpoint) == 0 {
		return nil, nil
	}
	var cp agentruntime.Checkpoint
	if err := json.Unmarshal(call.Checkpoint, &cp); err != nil {
		return nil, err
	}
	if cp.Revision != call.CheckpointRevision || cp.ContractHash != call.ContractHash {
		return nil, errors.New("invalid durable checkpoint identity")
	}
	return &cp, nil
}

func (s *runtimeSession) SaveCheckpoint(ctx context.Context, cp *agentruntime.Checkpoint) error {
	if cp == nil {
		return errors.New("agent checkpoint is required")
	}
	if !s.loaded {
		if _, err := s.Load(ctx); err != nil {
			return err
		}
	}
	return s.write(ctx, cp.Append, false, 0, cp)
}
