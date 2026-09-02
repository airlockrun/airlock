// Package connectorartifacts owns operator access to same-repository connector
// builds and the cross-replica retention sweep for their object storage.
package connectorartifacts

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

const downloadTTL = 5 * time.Minute
const deletionLease = 5 * time.Minute

type objectStore interface {
	PublicPresignDownloadURL(context.Context, string, string, time.Duration) (string, error)
	DeleteObjects(context.Context, ...string) (int, error)
}

type Service struct {
	db     *db.DB
	store  objectStore
	logger *zap.Logger
}

func New(database *db.DB, store objectStore, logger *zap.Logger) *Service {
	if database == nil || store == nil || logger == nil {
		panic("connectorartifacts: nil dependency")
	}
	return &Service{db: database, store: store, logger: logger}
}

type File struct {
	ID               uuid.UUID
	Platform         string
	Filename         string
	Digest           string
	SizeBytes        int64
	NoticesDigest    string
	NoticesSizeBytes int64
}

type ArtifactSet struct {
	ID                  uuid.UUID
	BuildID             uuid.UUID
	ConnectorSlug       string
	SourceRef           string
	Kind                string
	ContractID          string
	Name                string
	Description         string
	ArtifactVersion     string
	ArtifactDigest      string
	ProtocolMajor       int32
	ProtocolMinor       int32
	Features            []string
	ServiceMode         string
	InterfaceDescriptor []byte
	InterfaceHash       string
	SettingsSchema      []byte
	CreatedAt           time.Time
	Files               []File
}

type Download struct {
	URL       string
	Filename  string
	Digest    string
	SizeBytes int64
	ExpiresAt time.Time
}

func pg(id uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: id, Valid: true} }

// List returns successful, retained artifact sets that fully satisfy the
// named connector need. Agent-admin authorization applies before discovery.
func (s *Service) List(ctx context.Context, principal authz.Principal, agentID uuid.UUID, needSlug string) ([]ArtifactSet, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, principal, authz.ConnectorArtifactView, agentID); err != nil {
		return nil, err
	}
	rows, err := q.ListCompatibleConnectorArtifactFiles(ctx, dbq.ListCompatibleConnectorArtifactFilesParams{
		AgentID: pg(agentID), NeedSlug: needSlug,
	})
	if err != nil {
		return nil, err
	}
	sets := make([]ArtifactSet, 0)
	index := make(map[uuid.UUID]int)
	for _, row := range rows {
		id := uuid.UUID(row.ID.Bytes)
		position, ok := index[id]
		if !ok {
			position = len(sets)
			index[id] = position
			sets = append(sets, ArtifactSet{
				ID: id, BuildID: uuid.UUID(row.BuildID.Bytes), ConnectorSlug: row.ConnectorSlug,
				SourceRef: row.SourceRef, Kind: row.Kind, ContractID: row.ContractID,
				Name: row.Name, Description: row.Description, ArtifactVersion: row.ArtifactVersion,
				ArtifactDigest: row.ArtifactDigest,
				ProtocolMajor:  row.ProtocolMajor, ProtocolMinor: row.ProtocolMinor,
				Features: row.Features, ServiceMode: row.ServiceMode.String, InterfaceDescriptor: row.InterfaceDescriptor,
				InterfaceHash: row.InterfaceHash, SettingsSchema: row.SettingsSchema,
				CreatedAt: row.CreatedAt.Time,
			})
		}
		sets[position].Files = append(sets[position].Files, File{
			ID: uuid.UUID(row.FileID.Bytes), Platform: row.Platform, Filename: row.Filename,
			Digest: row.Digest, SizeBytes: row.SizeBytes, NoticesDigest: row.NoticesDigest,
			NoticesSizeBytes: row.NoticesSizeBytes,
		})
	}
	return sets, nil
}

// DownloadURL authorizes the need and artifact relationship before issuing a
// short-lived URL. notices selects the platform-specific dependency notice.
func (s *Service) DownloadURL(ctx context.Context, principal authz.Principal, agentID uuid.UUID, needSlug string, artifactFileID uuid.UUID, notices bool) (Download, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, principal, authz.ConnectorArtifactView, agentID); err != nil {
		return Download{}, err
	}
	row, err := q.GetCompatibleConnectorArtifactDownload(ctx, dbq.GetCompatibleConnectorArtifactDownloadParams{
		AgentID: pg(agentID), NeedSlug: needSlug, ArtifactFileID: pg(artifactFileID),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Download{}, service.ErrNotFound
	}
	if err != nil {
		return Download{}, err
	}
	key, filename, digest, size := row.ObjectKey, row.Filename, row.Digest, row.SizeBytes
	if notices {
		key, filename, digest, size = row.NoticesObjectKey, row.Filename+".THIRD_PARTY_NOTICES.md", row.NoticesDigest, row.NoticesSizeBytes
	}
	url, err := s.store.PublicPresignDownloadURL(ctx, key, filename, downloadTTL)
	if err != nil {
		return Download{}, fmt.Errorf("presign connector artifact: %w", err)
	}
	return Download{URL: url, Filename: filename, Digest: digest, SizeBytes: size, ExpiresAt: time.Now().UTC().Add(downloadTTL)}, nil
}

// Sweep applies retention and removes expired, unreferenced digest objects.
// A session advisory lock makes concurrent replicas collapse to one sweep.
func (s *Service) Sweep(ctx context.Context) error {
	lock, acquired, err := s.db.TryAcquireAdvisoryLock(ctx, "connector-artifact-gc")
	if err != nil {
		return err
	}
	if !acquired {
		return nil
	}
	defer lock.Unlock()
	q := dbq.New(s.db.Pool())
	if err := q.RefreshConnectorArtifactRetention(ctx); err != nil {
		return fmt.Errorf("refresh connector artifact retention: %w", err)
	}
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())
	qtx := dbq.New(tx)
	if _, err := qtx.QueueUnreferencedConnectorArtifactBlobs(ctx); err != nil {
		return fmt.Errorf("queue connector artifact blobs: %w", err)
	}
	if _, err := qtx.DeleteExpiredConnectorArtifactSets(ctx); err != nil {
		return fmt.Errorf("delete connector artifact sets: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	for {
		blob, err := q.ClaimConnectorArtifactBlobDeletion(ctx, int32(deletionLease.Seconds()))
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("claim connector artifact deletion: %w", err)
		}
		if _, err := s.store.DeleteObjects(ctx, blob.ObjectKey); err != nil {
			_, _ = q.ReleaseConnectorArtifactBlobDeletion(ctx, dbq.ReleaseConnectorArtifactBlobDeletionParams{
				DeletionError: pgtype.Text{String: "object storage deletion failed", Valid: true}, Digest: blob.Digest, DeletionToken: blob.DeletionToken,
			})
			return fmt.Errorf("delete connector artifact object: %w", err)
		}
		removed, err := q.FinishConnectorArtifactBlobDeletion(ctx, dbq.FinishConnectorArtifactBlobDeletionParams{Digest: blob.Digest, DeletionToken: blob.DeletionToken})
		if err != nil || removed != 1 {
			if err == nil {
				err = errors.New("connector artifact deletion lease expired")
			}
			return err
		}
	}
}

func (s *Service) Run(ctx context.Context) error {
	if err := s.Sweep(ctx); err != nil {
		s.logger.Error("connector artifact retention failed", zap.Error(err))
	}
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := s.Sweep(ctx); err != nil {
				s.logger.Error("connector artifact retention failed", zap.Error(err))
			}
		}
	}
}
