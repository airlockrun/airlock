// Package connectormaintenance reconciles durable connector lifecycle state.
package connectormaintenance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/airlockrun/agentsdk/connector/protocol"
	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	connectororchestrationsvc "github.com/airlockrun/airlock/service/connectororchestration"
	"github.com/airlockrun/airlock/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

const (
	batchSize         = 100
	heartbeatTimeout  = 2 * time.Minute
	sweepPeriod       = 5 * time.Second
	finalizationLease = time.Hour
)

type Worker struct {
	db            *db.DB
	orchestration *connectororchestrationsvc.Service
	s3            transferStore
	logger        *zap.Logger
}

type transferStore interface {
	AbortMultipartUpload(context.Context, string, string) error
	ListMultipartParts(context.Context, string, string) ([]storage.MultipartPart, error)
	CompleteMultipartUpload(context.Context, string, string, []storage.CompletedPart) error
	ConditionalCopyObject(context.Context, string, string, string, string, bool) error
	PutObjectWithMetadata(context.Context, string, io.Reader, int64, map[string]string) error
	HeadObject(context.Context, string) (storage.ObjectInfo, string, error)
	GetObject(context.Context, string) (io.ReadCloser, error)
	DeleteObject(context.Context, string) error
}

func New(database *db.DB, orchestration *connectororchestrationsvc.Service, s3 transferStore, logger *zap.Logger) *Worker {
	if database == nil || orchestration == nil || s3 == nil || logger == nil {
		panic("connectormaintenance: nil dependency")
	}
	return &Worker{db: database, orchestration: orchestration, s3: s3, logger: logger}
}

func (w *Worker) Run(ctx context.Context) error {
	ticker := time.NewTicker(sweepPeriod)
	defer ticker.Stop()
	for {
		w.sweep(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (w *Worker) sweep(ctx context.Context) {
	q := dbq.New(w.db.Pool())
	if _, err := q.MarkStaleConnectorsOffline(ctx, dbq.MarkStaleConnectorsOfflineParams{
		Cutoff: pgtype.Timestamptz{Time: time.Now().Add(-heartbeatTimeout), Valid: true},
		Lim:    batchSize,
	}); err != nil {
		w.logger.Error("mark stale connectors offline", zap.Error(err))
	}
	if _, err := q.ExpireConnectorJobAttempts(ctx, batchSize); err != nil {
		w.logger.Error("expire connector job attempts", zap.Error(err))
	}
	_, err := q.FinalizeCancelledConnectorJobs(ctx, batchSize)
	if err != nil {
		w.logger.Error("finalize cancelled connector jobs", zap.Error(err))
	}
	_, err = q.FailExpiredConnectorJobs(ctx, batchSize)
	if err != nil {
		w.logger.Error("fail expired connector jobs", zap.Error(err))
	}
	if _, err := q.FailExpiredConnectorFinalizations(ctx, batchSize); err != nil {
		w.logger.Error("fail expired connector finalizations", zap.Error(err))
	}
	if _, err := q.DeleteExpiredHostEnrollments(ctx, batchSize); err != nil {
		w.logger.Error("delete expired host enrollments", zap.Error(err))
	}
	if _, err := q.CleanupHostEnrollmentAttempts(ctx); err != nil {
		w.logger.Error("clean host enrollment attempts", zap.Error(err))
	}
	if _, err := q.ExpireHostManagementAttempts(ctx, batchSize); err != nil {
		w.logger.Error("expire host management attempts", zap.Error(err))
	}
	if _, err := q.FailExpiredHostManagementJobs(ctx, batchSize); err != nil {
		w.logger.Error("fail expired host management jobs", zap.Error(err))
	}
	w.finalizeTransfers(ctx, q)
	w.cleanupTransfers(ctx, q)
	if _, err := q.DeleteRetainedConnectorJobs(ctx, batchSize); err != nil {
		w.logger.Error("delete retained connector jobs", zap.Error(err))
	}
	if _, err := q.DeleteRetainedHostManagementJobs(ctx, batchSize); err != nil {
		w.logger.Error("delete retained host management jobs", zap.Error(err))
	}
	if _, err := q.DeleteTerminalTombstonedConnectorNeedReservations(ctx); err != nil {
		w.logger.Error("release tombstoned connector need reservations", zap.Error(err))
	}
	if _, err := q.DeleteTombstonedConnectorNeeds(ctx, batchSize); err != nil {
		w.logger.Error("delete tombstoned connector needs", zap.Error(err))
	}
	if _, err := q.DeleteRevokedConnectors(ctx, batchSize); err != nil {
		w.logger.Error("delete revoked connectors", zap.Error(err))
	}
	ids, err := q.ClaimActiveConnectorOrchestrationsForMaintenance(ctx, batchSize)
	if err != nil {
		w.logger.Error("list active connector orchestrations", zap.Error(err))
		return
	}
	for _, id := range ids {
		if _, err := w.orchestration.AdvanceSystem(ctx, uuid.UUID(id.Bytes)); err != nil {
			w.logger.Error("advance connector orchestration", zap.String("orchestration_id", uuid.UUID(id.Bytes).String()), zap.Error(err))
		}
	}
}

func (w *Worker) finalizeTransfers(ctx context.Context, q *dbq.Queries) {
	for range batchSize {
		transfer, err := q.ClaimConnectorExportFinalization(ctx, int32(finalizationLease.Seconds()))
		if errors.Is(err, pgx.ErrNoRows) {
			return
		}
		if err != nil {
			w.logger.Error("claim connector export finalization", zap.Error(err))
			return
		}
		w.finalizeTransfer(ctx, q, transfer)
	}
}

func (w *Worker) finalizeTransfer(ctx context.Context, q *dbq.Queries, transfer dbq.ConnectorTransfer) {
	claimed, err := decodeClaimedParts(transfer)
	if err != nil {
		w.failFinalization(ctx, q, transfer, "invalid_output", err.Error(), "")
		return
	}
	authoritative, err := w.s3.ListMultipartParts(ctx, transfer.ObjectKey, transfer.MultipartUploadID.String)
	if err != nil {
		if storage.IsNoSuchUpload(err) {
			w.finishPublishedTransfer(ctx, q, transfer)
			return
		}
		w.releaseFinalization(ctx, q, transfer, err)
		return
	}
	if err := validateAuthoritativeParts(transfer, claimed, authoritative); err != nil {
		w.failFinalization(ctx, q, transfer, "invalid_parts", err.Error(), "")
		return
	}
	if transfer.ActualSize.Int64 == 0 {
		if !w.renewFinalization(ctx, q, transfer) {
			return
		}
		if err := w.s3.AbortMultipartUpload(ctx, transfer.ObjectKey, transfer.MultipartUploadID.String); err != nil && !storage.IsNoSuchUpload(err) {
			w.releaseFinalization(ctx, q, transfer, err)
			return
		}
		metadata := map[string]string{"filename": path.Base(transfer.DestinationPath), "airlock-transfer": uuid.UUID(transfer.TransferMarker.Bytes).String(), "content-type": "application/octet-stream"}
		if !w.renewFinalization(ctx, q, transfer) {
			return
		}
		if err := w.s3.PutObjectWithMetadata(ctx, transfer.ObjectKey, bytes.NewReader(nil), 0, metadata); err != nil {
			w.deferFinalization(ctx, q, transfer, err)
			return
		}
	} else {
		parts := make([]storage.CompletedPart, len(authoritative))
		for i, part := range authoritative {
			parts[i] = storage.CompletedPart{Number: part.Number, ETag: part.ETag}
		}
		if !w.renewFinalization(ctx, q, transfer) {
			return
		}
		if err := w.s3.CompleteMultipartUpload(ctx, transfer.ObjectKey, transfer.MultipartUploadID.String, parts); err != nil {
			if storage.IsNoSuchUpload(err) {
				w.finishPublishedTransfer(ctx, q, transfer)
				return
			}
			w.deferFinalization(ctx, q, transfer, err)
			return
		}
	}
	w.finishPublishedTransfer(ctx, q, transfer)
}

func (w *Worker) finishPublishedTransfer(ctx context.Context, q *dbq.Queries, transfer dbq.ConnectorTransfer) {
	staging, _, deterministic, err := w.validatePublishedObject(ctx, q, transfer, transfer.ObjectKey)
	if err != nil {
		if deterministic {
			w.failFinalization(ctx, q, transfer, "integrity_error", err.Error(), transfer.ObjectKey)
		} else {
			w.deferFinalization(ctx, q, transfer, err)
		}
		return
	}
	if !w.renewFinalization(ctx, q, transfer) {
		return
	}
	err = w.s3.ConditionalCopyObject(ctx, transfer.ObjectKey, transfer.DestinationObjectKey, staging.ETag, transfer.DestinationEtag.String, transfer.DestinationExisted)
	if err != nil {
		info, _, headErr := w.s3.HeadObject(ctx, transfer.DestinationObjectKey)
		if headErr != nil || info.Metadata["airlock-transfer"] != uuid.UUID(transfer.TransferMarker.Bytes).String() {
			if storage.IsPreconditionFailed(err) {
				w.failFinalization(ctx, q, transfer, "destination_conflict", "export destination changed while the transfer was running", "")
			} else {
				w.deferFinalization(ctx, q, transfer, err)
			}
			return
		}
	}
	info, contentType, deterministic, err := w.validatePublishedObject(ctx, q, transfer, transfer.DestinationObjectKey)
	if err != nil {
		if deterministic {
			w.failFinalization(ctx, q, transfer, "integrity_error", err.Error(), transfer.DestinationObjectKey)
		} else {
			w.deferFinalization(ctx, q, transfer, err)
		}
		return
	}
	filename := path.Base(transfer.DestinationPath)
	if value := info.Metadata["filename"]; value != "" {
		filename = value
	}
	output, err := json.Marshal(wire.FileInfo{Path: transfer.DestinationPath, Filename: filename, ContentType: contentType, Size: info.Size, LastModified: info.LastModified})
	if err != nil {
		w.failFinalization(ctx, q, transfer, "invalid_output", err.Error(), transfer.DestinationObjectKey)
		return
	}
	_, err = q.FinishConnectorExportFinalization(ctx, dbq.FinishConnectorExportFinalizationParams{
		OutputPayload: output, JobID: transfer.JobID, FinalizationToken: transfer.FinalizationToken, AttemptToken: transfer.FinalizationAttemptToken,
	})
	if err != nil {
		w.deferFinalization(ctx, q, transfer, err)
	}
}

func (w *Worker) validatePublishedObject(ctx context.Context, q *dbq.Queries, transfer dbq.ConnectorTransfer, objectKey string) (storage.ObjectInfo, string, bool, error) {
	info, contentType, err := w.s3.HeadObject(ctx, objectKey)
	if err != nil {
		return storage.ObjectInfo{}, "", storage.IsNotFound(err), err
	}
	if info.Metadata["airlock-transfer"] != uuid.UUID(transfer.TransferMarker.Bytes).String() {
		return storage.ObjectInfo{}, "", true, errors.New("exported object marker mismatch")
	}
	if !transfer.ActualSize.Valid || info.Size != transfer.ActualSize.Int64 || info.Size > transfer.MaximumSize {
		return storage.ObjectInfo{}, "", true, errors.New("exported object size mismatch")
	}
	reader, err := w.s3.GetObject(ctx, objectKey)
	if err != nil {
		return storage.ObjectInfo{}, "", storage.IsNotFound(err), err
	}
	hasher := sha256.New()
	limited := io.LimitReader(reader, transfer.MaximumSize+1)
	buffer := make([]byte, 1<<20)
	var written int64
	nextRenewal := time.Now().Add(30 * time.Second)
	var copyErr error
	for {
		count, readErr := limited.Read(buffer)
		if count > 0 {
			written += int64(count)
			_, _ = hasher.Write(buffer[:count])
		}
		if time.Now().After(nextRenewal) {
			affected, renewErr := q.RenewConnectorExportFinalizationLease(ctx, dbq.RenewConnectorExportFinalizationLeaseParams{
				LeaseSeconds: int32(finalizationLease.Seconds()), JobID: transfer.JobID, FinalizationToken: transfer.FinalizationToken,
			})
			if renewErr != nil || affected != 1 {
				if renewErr == nil {
					renewErr = errors.New("connector export finalization lease is stale")
				}
				copyErr = renewErr
				break
			}
			nextRenewal = time.Now().Add(30 * time.Second)
		}
		if readErr != nil {
			if !errors.Is(readErr, io.EOF) {
				copyErr = readErr
			}
			break
		}
	}
	closeErr := reader.Close()
	if copyErr != nil || closeErr != nil {
		return storage.ObjectInfo{}, "", false, errors.Join(copyErr, closeErr)
	}
	if written > transfer.MaximumSize || written != info.Size {
		return storage.ObjectInfo{}, "", true, errors.New("exported object exceeds its size grant")
	}
	if !transfer.ActualSha256.Valid || hex.EncodeToString(hasher.Sum(nil)) != transfer.ActualSha256.String {
		return storage.ObjectInfo{}, "", true, errors.New("exported object checksum mismatch")
	}
	return info, contentType, false, nil
}

func (w *Worker) failFinalization(ctx context.Context, q *dbq.Queries, transfer dbq.ConnectorTransfer, code, message, deleteKey string) {
	if deleteKey != "" {
		if !w.renewFinalization(ctx, q, transfer) {
			return
		}
		if err := w.deleteOwnedObject(ctx, transfer, deleteKey); err != nil {
			w.deferFinalization(ctx, q, transfer, err)
			return
		}
	}
	if _, err := q.FailConnectorExportFinalization(ctx, dbq.FailConnectorExportFinalizationParams{
		ErrorCode: pgtype.Text{String: code, Valid: true}, ErrorMessage: pgtype.Text{String: message, Valid: true},
		JobID: transfer.JobID, FinalizationToken: transfer.FinalizationToken, AttemptToken: transfer.FinalizationAttemptToken,
	}); err != nil {
		if deleteKey != "" {
			w.deferFinalization(ctx, q, transfer, err)
		} else {
			w.releaseFinalization(ctx, q, transfer, err)
		}
	}
}

func (w *Worker) deleteOwnedObject(ctx context.Context, transfer dbq.ConnectorTransfer, objectKey string) error {
	info, _, err := w.s3.HeadObject(ctx, objectKey)
	if storage.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Metadata["airlock-transfer"] != uuid.UUID(transfer.TransferMarker.Bytes).String() {
		return nil
	}
	return w.s3.DeleteObject(ctx, objectKey)
}

func (w *Worker) releaseFinalization(ctx context.Context, q *dbq.Queries, transfer dbq.ConnectorTransfer, cause error) {
	w.logger.Warn("release connector export finalization after storage error", zap.String("job_id", uuid.UUID(transfer.JobID.Bytes).String()), zap.Error(cause))
	if _, err := q.ReleaseConnectorExportFinalization(ctx, dbq.ReleaseConnectorExportFinalizationParams{
		ErrorMessage: pgtype.Text{String: "object storage temporarily unavailable", Valid: true}, JobID: transfer.JobID, FinalizationToken: transfer.FinalizationToken,
	}); err != nil {
		w.logger.Error("release connector export finalization", zap.String("job_id", uuid.UUID(transfer.JobID.Bytes).String()), zap.Error(err))
	}
}

func (w *Worker) deferFinalization(ctx context.Context, q *dbq.Queries, transfer dbq.ConnectorTransfer, cause error) {
	w.logger.Warn("defer connector export finalization after storage error", zap.String("job_id", uuid.UUID(transfer.JobID.Bytes).String()), zap.Error(cause))
	if _, err := q.DeferConnectorExportFinalization(ctx, dbq.DeferConnectorExportFinalizationParams{
		RetrySeconds: 5, ErrorMessage: pgtype.Text{String: "object storage temporarily unavailable", Valid: true}, JobID: transfer.JobID, FinalizationToken: transfer.FinalizationToken,
	}); err != nil {
		w.logger.Error("defer connector export finalization", zap.String("job_id", uuid.UUID(transfer.JobID.Bytes).String()), zap.Error(err))
	}
}

func (w *Worker) renewFinalization(ctx context.Context, q *dbq.Queries, transfer dbq.ConnectorTransfer) bool {
	affected, err := q.RenewConnectorExportFinalizationLease(ctx, dbq.RenewConnectorExportFinalizationLeaseParams{
		LeaseSeconds: int32(finalizationLease.Seconds()), JobID: transfer.JobID, FinalizationToken: transfer.FinalizationToken,
	})
	if err != nil || affected != 1 {
		if err == nil {
			err = errors.New("connector export finalization lease is stale")
		}
		w.logger.Warn("lost connector export finalization lease", zap.String("job_id", uuid.UUID(transfer.JobID.Bytes).String()), zap.Error(err))
		return false
	}
	return true
}

func decodeClaimedParts(transfer dbq.ConnectorTransfer) ([]protocol.UploadedPart, error) {
	var parts []protocol.UploadedPart
	if err := json.Unmarshal(transfer.MultipartParts, &parts); err != nil {
		return nil, errors.New("connector export part metadata is invalid")
	}
	return parts, nil
}

func validateAuthoritativeParts(transfer dbq.ConnectorTransfer, claimed []protocol.UploadedPart, authoritative []storage.MultipartPart) error {
	if !transfer.ActualSize.Valid || transfer.ActualSize.Int64 < 0 || transfer.ActualSize.Int64 > transfer.MaximumSize || !transfer.ActualSha256.Valid {
		return errors.New("connector export result bounds are invalid")
	}
	sort.Slice(authoritative, func(i, j int) bool { return authoritative[i].Number < authoritative[j].Number })
	sort.Slice(claimed, func(i, j int) bool { return claimed[i].Number < claimed[j].Number })
	if len(authoritative) != len(claimed) || len(authoritative) > int(transfer.MultipartPartCount.Int32) {
		return errors.New("S3 multipart part count does not match connector output")
	}
	var total int64
	for i, part := range authoritative {
		claim := claimed[i]
		if part.Number != i+1 || claim.Number != part.Number || canonicalETag(claim.ETag) == "" || canonicalETag(claim.ETag) != canonicalETag(part.ETag) || claim.Size != part.Size || part.Size <= 0 || part.Size > transfer.MultipartPartSize.Int64 {
			return errors.New("S3 multipart ETag or size does not match connector output")
		}
		if i < len(authoritative)-1 && part.Size != transfer.MultipartPartSize.Int64 {
			return errors.New("S3 multipart upload has a short non-final part")
		}
		if part.Size > transfer.MaximumSize-total {
			return errors.New("S3 multipart upload exceeds its size grant")
		}
		total += part.Size
	}
	if total != transfer.ActualSize.Int64 {
		return errors.New("S3 multipart size does not match connector output")
	}
	if total == 0 && (len(authoritative) != 0 || transfer.ActualSha256.String != hex.EncodeToString(sha256.New().Sum(nil))) {
		return errors.New("empty connector export metadata is invalid")
	}
	return nil
}

func canonicalETag(value string) string {
	return strings.Trim(strings.TrimSpace(value), `"`)
}

func (w *Worker) cleanupTransfers(ctx context.Context, q *dbq.Queries) {
	for range batchSize {
		transfer, err := q.ClaimConnectorTransferCleanup(ctx, 60)
		if errors.Is(err, pgx.ErrNoRows) {
			return
		}
		if err != nil {
			w.logger.Error("claim connector transfer cleanup", zap.Error(err))
			return
		}
		renewed, err := q.RenewConnectorTransferCleanupLease(ctx, dbq.RenewConnectorTransferCleanupLeaseParams{
			LeaseSeconds: 60, JobID: transfer.JobID, CleanupToken: transfer.CleanupToken,
		})
		if err != nil || renewed != 1 {
			if err == nil {
				err = errors.New("connector transfer cleanup lease is stale")
			}
			w.logger.Warn("lost connector transfer cleanup lease", zap.String("job_id", uuid.UUID(transfer.JobID.Bytes).String()), zap.Error(err))
			continue
		}
		if transfer.Direction == "export" {
			if transfer.State != "completed" {
				err = w.s3.AbortMultipartUpload(ctx, transfer.ObjectKey, transfer.MultipartUploadID.String)
				if storage.IsNoSuchUpload(err) {
					err = nil
				}
			}
			if err == nil {
				err = w.deleteOwnedObject(ctx, transfer, transfer.ObjectKey)
			}
			if err == nil && transfer.CleanupDestination {
				err = w.deleteOwnedObject(ctx, transfer, transfer.DestinationObjectKey)
			}
		}
		if err != nil {
			w.logger.Warn("connector transfer object cleanup failed", zap.String("job_id", uuid.UUID(transfer.JobID.Bytes).String()), zap.Error(err))
			_, releaseErr := q.ReleaseConnectorTransferCleanup(ctx, dbq.ReleaseConnectorTransferCleanupParams{
				JobID: transfer.JobID, CleanupToken: transfer.CleanupToken,
				ErrorMessage: pgtype.Text{String: "object storage cleanup temporarily unavailable", Valid: true},
			})
			if releaseErr != nil {
				w.logger.Error("release connector transfer cleanup", zap.Error(releaseErr))
			}
			continue
		}
		scrubbed, err := q.ScrubClaimedConnectorTransferGrant(ctx, dbq.ScrubClaimedConnectorTransferGrantParams{JobID: transfer.JobID, CleanupToken: transfer.CleanupToken})
		if err != nil || scrubbed != 1 {
			if err == nil {
				err = errors.New("connector transfer grant was not scrubbed")
			}
			w.logger.Error("scrub connector transfer grant", zap.Error(err))
			_, _ = q.ReleaseConnectorTransferCleanup(ctx, dbq.ReleaseConnectorTransferCleanupParams{JobID: transfer.JobID, CleanupToken: transfer.CleanupToken, ErrorMessage: pgtype.Text{String: "transfer grant cleanup temporarily unavailable", Valid: true}})
			continue
		}
		if _, err := q.DeleteClaimedConnectorTransfer(ctx, dbq.DeleteClaimedConnectorTransferParams{JobID: transfer.JobID, CleanupToken: transfer.CleanupToken}); err != nil {
			w.logger.Error("delete connector transfer metadata", zap.Error(err))
		}
	}
}
