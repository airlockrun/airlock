// Package connectordirectories authorizes and dispatches connector directory
// operations and owns direct agent-storage transfer finalization.
package connectordirectories

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/agentsdk/connector/protocol"
	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	agentstoragesvc "github.com/airlockrun/airlock/service/agentstorage"
	connectorjobssvc "github.com/airlockrun/airlock/service/connectorjobs"
	connectorssvc "github.com/airlockrun/airlock/service/connectors"
	"github.com/airlockrun/airlock/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

const (
	operationTimeout    = 2 * time.Minute
	transferTimeout     = 15 * time.Minute
	transferPartSize    = int64(protocol.MaxTransferPartBytes)
	transferPartCount   = 512
	maximumTransferSize = transferPartSize * transferPartCount
	transferRetention   = 24 * time.Hour
)

type Service struct {
	db    *db.DB
	jobs  *connectorjobssvc.Service
	files *agentstoragesvc.Service
	s3    *storage.S3Client
}

type transferRecord struct {
	runID                uuid.UUID
	direction            string
	sourcePath           string
	destinationPath      string
	objectKey            string
	destinationObjectKey string
	destinationExisted   bool
	destinationETag      string
	marker               uuid.UUID
	storageOrigin        string
	overwrite            bool
	maximumSize          int64
	expectedSize         int64
	expectedSHA256       string
	uploadID             string
	partSize             int64
	partCount            int
	parts                json.RawMessage
	grantExpiresAt       time.Time
}

func New(database *db.DB, jobs *connectorjobssvc.Service, files *agentstoragesvc.Service, s3 *storage.S3Client) *Service {
	if database == nil || jobs == nil || files == nil || s3 == nil {
		panic("connectordirectories: nil dependency")
	}
	return &Service{db: database, jobs: jobs, files: files, s3: s3}
}

func (s *Service) List(ctx context.Context, agentID uuid.UUID, need, directory string, request protocol.DirectoryListRequest) (protocol.DirectoryListResponse, error) {
	var result protocol.DirectoryListResponse
	err := s.call(ctx, agentID, need, directory, protocol.JobKindDirectoryList, request, &result, nil)
	return result, err
}

func (s *Service) Stat(ctx context.Context, agentID uuid.UUID, need, directory, filePath string) (protocol.DirectoryEntry, error) {
	var result protocol.DirectoryEntry
	err := s.call(ctx, agentID, need, directory, protocol.JobKindDirectoryStat, map[string]string{"path": filePath}, &result, nil)
	return result, err
}

func (s *Service) Read(ctx context.Context, agentID uuid.UUID, need, directory string, request protocol.DirectoryReadRequest) (protocol.DirectoryReadResponse, error) {
	var result protocol.DirectoryReadResponse
	err := s.call(ctx, agentID, need, directory, protocol.JobKindDirectoryRead, request, &result, nil)
	return result, err
}

func (s *Service) Write(ctx context.Context, agentID uuid.UUID, need, directory string, request protocol.DirectoryWriteRequest) (protocol.DirectoryEntry, error) {
	var result protocol.DirectoryEntry
	err := s.call(ctx, agentID, need, directory, protocol.JobKindDirectoryWrite, request, &result, nil)
	return result, err
}

func (s *Service) Delete(ctx context.Context, agentID uuid.UUID, need, directory, filePath string) error {
	var result struct{}
	return s.call(ctx, agentID, need, directory, protocol.JobKindDirectoryDelete, map[string]string{"path": filePath}, &result, nil)
}

func (s *Service) Move(ctx context.Context, agentID uuid.UUID, need, directory string, request protocol.DirectoryMoveRequest) error {
	var result struct{}
	return s.call(ctx, agentID, need, directory, protocol.JobKindDirectoryMove, request, &result, nil)
}

func (s *Service) Import(ctx context.Context, agentID, runID uuid.UUID, need, directory string, request agentsdk.ConnectorImportRequest) (protocol.DirectoryEntry, error) {
	if err := s.authorize(ctx, agentID, need, directory, protocol.JobKindDirectoryImport); err != nil {
		return protocol.DirectoryEntry{}, err
	}
	if err := s.requireRunningRun(ctx, agentID, runID); err != nil {
		return protocol.DirectoryEntry{}, err
	}
	resolved, err := s.files.ResolveForRun(ctx, agentID, runID, string(request.Source), agentstoragesvc.OperationRead)
	if err != nil {
		return protocol.DirectoryEntry{}, err
	}
	info, _, err := s.s3.HeadObject(ctx, resolved.S3Key)
	if err != nil {
		return protocol.DirectoryEntry{}, service.ErrNotFound
	}
	if info.Size > maximumTransferSize {
		return protocol.DirectoryEntry{}, service.Detail(service.ErrInvalidInput, "import source exceeds %d bytes", maximumTransferSize)
	}
	digest, hashedSize, err := s.objectSHA256(ctx, resolved.S3Key, maximumTransferSize)
	if err != nil {
		return protocol.DirectoryEntry{}, fmt.Errorf("hash import source: %w", err)
	}
	if hashedSize != info.Size {
		return protocol.DirectoryEntry{}, service.Detail(service.ErrConflict, "import source changed while the transfer grant was prepared")
	}
	deadline := time.Now().UTC().Add(transferTimeout)
	grantURL, err := s.s3.PublicPresignGetURL(ctx, resolved.S3Key, transferTimeout)
	if err != nil {
		return protocol.DirectoryEntry{}, fmt.Errorf("presign import source: %w", err)
	}
	origin, err := transferOrigin(grantURL)
	if err != nil {
		return protocol.DirectoryEntry{}, err
	}
	maximum := info.Size
	if maximum == 0 {
		maximum = 1
	}
	input := protocol.DirectoryImportRequest{
		Path: request.Path, Overwrite: request.Overwrite,
		Grant: protocol.TransferGrant{URL: grantURL, ExpiresAt: deadline, MaximumSize: maximum, ExpectedSize: info.Size, ExpectedSHA256: digest},
	}
	record := &transferRecord{
		runID: runID, direction: "import", sourcePath: string(request.Source), destinationPath: request.Path,
		objectKey: resolved.S3Key, marker: uuid.New(), storageOrigin: origin, overwrite: request.Overwrite,
		maximumSize: maximum, expectedSize: info.Size, expectedSHA256: digest, grantExpiresAt: deadline,
	}
	var result protocol.DirectoryEntry
	err = s.callWithDeadline(ctx, agentID, need, directory, protocol.JobKindDirectoryImport, input, &result, record, deadline, func() {})
	return result, err
}

func (s *Service) Export(ctx context.Context, agentID, runID uuid.UUID, need, directory string, request agentsdk.ConnectorExportRequest) (wire.FileInfo, error) {
	if err := s.authorize(ctx, agentID, need, directory, protocol.JobKindDirectoryExport); err != nil {
		return wire.FileInfo{}, err
	}
	if err := s.requireRunningRun(ctx, agentID, runID); err != nil {
		return wire.FileInfo{}, err
	}
	resolved, err := s.files.ResolveForRun(ctx, agentID, runID, string(request.Destination), agentstoragesvc.OperationWrite)
	if err != nil {
		return wire.FileInfo{}, err
	}
	deadline := time.Now().UTC().Add(transferTimeout)
	marker := uuid.New()
	destinationExisted := false
	destinationETag := ""
	if destinationInfo, _, headErr := s.s3.HeadObject(ctx, resolved.S3Key); headErr == nil {
		destinationExisted, destinationETag = true, destinationInfo.ETag
	} else if !storage.IsNotFound(headErr) {
		return wire.FileInfo{}, fmt.Errorf("inspect export destination: %w", headErr)
	}
	stagingKey := "connector-transfer-staging/" + agentID.String() + "/" + marker.String()
	uploadID, err := s.s3.CreateMultipartUpload(ctx, stagingKey, "application/octet-stream", map[string]string{"filename": path.Base(resolved.Relative), "airlock-transfer": marker.String()})
	if err != nil {
		return wire.FileInfo{}, fmt.Errorf("create export upload: %w", err)
	}
	abort := true
	defer func() {
		if abort {
			_ = s.s3.AbortMultipartUpload(context.WithoutCancel(ctx), stagingKey, uploadID)
		}
	}()
	parts := make([]protocol.UploadPartGrant, transferPartCount)
	for i := range parts {
		partURL, err := s.s3.PublicPresignUploadPart(ctx, stagingKey, uploadID, i+1, transferTimeout)
		if err != nil {
			return wire.FileInfo{}, fmt.Errorf("presign export part: %w", err)
		}
		parts[i] = protocol.UploadPartGrant{Number: i + 1, URL: partURL}
	}
	origin, err := transferOrigin(parts[0].URL)
	if err != nil {
		return wire.FileInfo{}, err
	}
	input := protocol.DirectoryExportRequest{
		Path: request.Path, PartSize: transferPartSize, Parts: parts,
		Grant: protocol.TransferGrant{URL: parts[0].URL, ExpiresAt: deadline, MaximumSize: maximumTransferSize},
	}
	grants, err := json.Marshal(parts)
	if err != nil {
		return wire.FileInfo{}, err
	}
	record := &transferRecord{
		runID: runID, direction: "export", sourcePath: request.Path, destinationPath: string(request.Destination),
		objectKey: stagingKey, destinationObjectKey: resolved.S3Key, destinationExisted: destinationExisted,
		destinationETag: destinationETag, marker: marker, storageOrigin: origin, overwrite: true,
		maximumSize: maximumTransferSize, uploadID: uploadID, partSize: transferPartSize,
		partCount: transferPartCount, parts: grants, grantExpiresAt: deadline,
	}
	var result wire.FileInfo
	err = s.callWithDeadline(ctx, agentID, need, directory, protocol.JobKindDirectoryExport, input, &result, record, deadline, func() {
		abort = false
	})
	return result, err
}

func (s *Service) authorize(ctx context.Context, agentID uuid.UUID, needSlug, directory string, kind protocol.JobKind) error {
	bound, err := dbq.New(s.db.Pool()).ResolveBoundConnector(ctx, dbq.ResolveBoundConnectorParams{AgentID: pg(agentID), Slug: needSlug})
	if errors.Is(err, pgx.ErrNoRows) {
		return service.Detail(service.ErrNotFound, "connector need %q is not bound", needSlug)
	}
	if err != nil {
		return err
	}
	if bound.Readiness != "ready" {
		return service.Detail(service.ErrConflict, "bound connector is not ready")
	}
	_, err = authorizeDirectory(bound.NeedSpec, bound.InterfaceDescriptor, directory, kind)
	return err
}

func (s *Service) requireRunningRun(ctx context.Context, agentID, runID uuid.UUID) error {
	run, err := dbq.New(s.db.Pool()).GetRunByIDAndAgent(ctx, dbq.GetRunByIDAndAgentParams{ID: pg(runID), AgentID: pg(agentID)})
	if errors.Is(err, pgx.ErrNoRows) || err == nil && run.Status != "running" {
		return service.Detail(service.ErrConflict, "connector storage transfer requires a currently running run")
	}
	return err
}

func (s *Service) call(ctx context.Context, agentID uuid.UUID, need, directory string, kind protocol.JobKind, input, output any, transfer *transferRecord) error {
	return s.callWithDeadline(ctx, agentID, need, directory, kind, input, output, transfer, time.Now().UTC().Add(operationTimeout), func() {})
}

func (s *Service) callWithDeadline(ctx context.Context, agentID uuid.UUID, need, directory string, kind protocol.JobKind, input, output any, transfer *transferRecord, deadline time.Time, onCommitted func()) error {
	payload, err := json.Marshal(input)
	if err != nil {
		return err
	}
	if len(payload) == 0 || len(payload) > protocol.MaxJobPayloadBytes {
		return service.Detail(service.ErrInvalidInput, "connector directory input exceeds %d bytes", protocol.MaxJobPayloadBytes)
	}
	job, err := s.enqueue(ctx, agentID, need, directory, kind, payload, transfer, deadline)
	if err != nil {
		return err
	}
	onCommitted()
	jobID := uuid.UUID(job.ID.Bytes)
	job, err = s.jobs.Wait(ctx, agentID, jobID)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			_, _ = s.jobs.Cancel(context.WithoutCancel(ctx), agentID, jobID)
		}
		return err
	}
	if job.Status != "succeeded" {
		message := "connector directory operation failed"
		if job.ErrorMessage.Valid {
			message = job.ErrorMessage.String
		}
		return service.Detail(service.ErrConflict, "%s", message)
	}
	return strictDecode(job.OutputPayload, output)
}

func (s *Service) enqueue(ctx context.Context, agentID uuid.UUID, needSlug, directory string, kind protocol.JobKind, input json.RawMessage, transfer *transferRecord, deadline time.Time) (dbq.ConnectorJob, error) {
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return dbq.ConnectorJob{}, err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	bound, err := q.ResolveBoundConnector(ctx, dbq.ResolveBoundConnectorParams{AgentID: pg(agentID), Slug: needSlug})
	if errors.Is(err, pgx.ErrNoRows) {
		return dbq.ConnectorJob{}, service.Detail(service.ErrNotFound, "connector need %q is not bound", needSlug)
	}
	if err != nil {
		return dbq.ConnectorJob{}, err
	}
	if bound.Readiness != "ready" {
		return dbq.ConnectorJob{}, service.Detail(service.ErrConflict, "bound connector is not ready")
	}
	required, err := authorizeDirectory(bound.NeedSpec, bound.InterfaceDescriptor, directory, kind)
	if err != nil {
		return dbq.ConnectorJob{}, err
	}
	if transfer != nil && !contains(bound.StorageOrigins, transfer.storageOrigin) {
		return dbq.ConnectorJob{}, service.Detail(service.ErrForbidden, "transfer origin is not configured for this connector")
	}
	jobID := uuid.New()
	requestID := uuid.New()
	idempotencyKey := uuid.New()
	requestSum := sha256.Sum256(bytes.Join([][]byte{[]byte(kind), []byte(directory), input}, []byte{0}))
	job, err := q.InsertConnectorJob(ctx, dbq.InsertConnectorJobParams{
		ID: pg(jobID), ConnectorID: bound.ID, AgentID: pg(agentID), NeedID: bound.NeedID, RequestID: pg(requestID),
		OperationKind: string(kind), OperationName: directory, OperationRevision: required.Revision, Mode: "unary",
		InputSchemaHash: strings.Repeat("0", 64), OutputSchemaHash: strings.Repeat("0", 64),
		InputPayload: input, RequestHash: hex.EncodeToString(requestSum[:]), Status: "queued",
		IdempotencyKey: pg(idempotencyKey), DeadlineAt: timestamp(deadline),
	})
	if err != nil {
		return dbq.ConnectorJob{}, err
	}
	if transfer != nil {
		if _, err := q.LockRunningRunForConnectorTransfer(ctx, dbq.LockRunningRunForConnectorTransferParams{ID: pg(transfer.runID), AgentID: pg(agentID)}); errors.Is(err, pgx.ErrNoRows) {
			return dbq.ConnectorJob{}, service.Detail(service.ErrConflict, "connector storage transfer requires a currently running run")
		} else if err != nil {
			return dbq.ConnectorJob{}, err
		}
		params := dbq.InsertConnectorTransferParams{
			JobID: job.ID, RunID: pg(transfer.runID), Direction: transfer.direction,
			SourcePath: transfer.sourcePath, DestinationPath: transfer.destinationPath,
			ObjectKey: transfer.objectKey, DestinationObjectKey: transfer.destinationObjectKey,
			DestinationExisted: transfer.destinationExisted, TransferMarker: pg(transfer.marker), StorageOrigin: transfer.storageOrigin, Overwrite: transfer.overwrite,
			MaximumSize: transfer.maximumSize, ExpectedSize: transfer.expectedSize,
			GrantExpiresAt: timestamp(transfer.grantExpiresAt), DeadlineAt: timestamp(deadline), CleanupAfter: timestamp(deadline.Add(transferRetention)),
		}
		if params.DestinationObjectKey == "" {
			params.DestinationObjectKey = transfer.objectKey
		}
		if transfer.destinationETag != "" {
			params.DestinationEtag = text(transfer.destinationETag)
		}
		if transfer.expectedSHA256 != "" {
			params.ExpectedSha256 = text(transfer.expectedSHA256)
		}
		if transfer.direction == "export" {
			params.MultipartUploadID = text(transfer.uploadID)
			params.MultipartPartSize = pgtype.Int8{Int64: transfer.partSize, Valid: true}
			params.MultipartPartCount = pgtype.Int4{Int32: int32(transfer.partCount), Valid: true}
			params.MultipartParts = transfer.parts
		}
		if _, err := q.InsertConnectorTransfer(ctx, params); err != nil {
			var constraint *pgconn.PgError
			if errors.As(err, &constraint) && constraint.Code == "23505" && constraint.ConstraintName == "connector_transfers_active_destination_key" {
				return dbq.ConnectorJob{}, service.Detail(service.ErrConflict, "another connector export is already writing this destination")
			}
			return dbq.ConnectorJob{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return dbq.ConnectorJob{}, err
	}
	return job, nil
}

func authorizeDirectory(needRaw, descriptorRaw []byte, name string, kind protocol.JobKind) (connectorssvc.Directory, error) {
	need, err := connectorssvc.ParseNeedSpec(needRaw)
	if err != nil {
		return connectorssvc.Directory{}, service.Detail(service.ErrConflict, "%v", err)
	}
	descriptor, err := connectorssvc.ParseDescriptor(descriptorRaw)
	if err != nil {
		return connectorssvc.Directory{}, service.Detail(service.ErrConflict, "bound connector has not published a valid interface")
	}
	if err := connectorssvc.Compatible(need, descriptor); err != nil {
		return connectorssvc.Directory{}, service.Detail(service.ErrConflict, "%v", err)
	}
	for _, directory := range need.Directories {
		if directory.Name != name {
			continue
		}
		allowed := directory.Write
		switch kind {
		case protocol.JobKindDirectoryList:
			allowed = directory.List
		case protocol.JobKindDirectoryStat, protocol.JobKindDirectoryRead, protocol.JobKindDirectoryExport:
			allowed = directory.Read
		case protocol.JobKindDirectoryWrite, protocol.JobKindDirectoryDelete, protocol.JobKindDirectoryMove, protocol.JobKindDirectoryImport:
		default:
			return connectorssvc.Directory{}, service.Detail(service.ErrInvalidInput, "unsupported connector directory operation %q", kind)
		}
		if !allowed {
			return connectorssvc.Directory{}, service.Detail(service.ErrForbidden, "connector directory operation was not declared by the agent need")
		}
		return directory, nil
	}
	return connectorssvc.Directory{}, service.Detail(service.ErrForbidden, "connector directory %q was not declared by the agent need", name)
}

// Complete validates directory results and durably accepts export finalization.
func (s *Service) Complete(ctx context.Context, connectorID, jobID, attemptToken uuid.UUID, succeeded bool, output json.RawMessage, errorCode, errorMessage string) (dbq.ConnectorJob, error) {
	job, err := dbq.New(s.db.Pool()).GetConnectorJob(ctx, pg(jobID))
	if errors.Is(err, pgx.ErrNoRows) || err == nil && uuid.UUID(job.ConnectorID.Bytes) != connectorID {
		return dbq.ConnectorJob{}, service.ErrNotFound
	}
	if err != nil {
		return dbq.ConnectorJob{}, err
	}
	if succeeded {
		if err := validateDirectoryOutput(protocol.JobKind(job.OperationKind), output); err != nil {
			return dbq.ConnectorJob{}, err
		}
	}
	if job.OperationKind == string(protocol.JobKindDirectoryExport) {
		if succeeded {
			return s.acceptExport(ctx, connectorID, jobID, attemptToken, output)
		}
	}
	return s.jobs.Complete(ctx, connectorID, jobID, attemptToken, succeeded, output, errorCode, errorMessage)
}

func (s *Service) acceptExport(ctx context.Context, connectorID, jobID, attemptToken uuid.UUID, raw json.RawMessage) (dbq.ConnectorJob, error) {
	var response protocol.DirectoryExportResponse
	if err := strictDecode(raw, &response); err != nil {
		return dbq.ConnectorJob{}, service.Detail(service.ErrInvalidInput, "invalid connector export result")
	}
	partsJSON, err := json.Marshal(response.Parts)
	if err != nil {
		return dbq.ConnectorJob{}, err
	}
	q := dbq.New(s.db.Pool())
	transfer, err := q.GetConnectorTransfer(ctx, pg(jobID))
	if err != nil {
		return dbq.ConnectorJob{}, err
	}
	if _, err := validateUploadedParts(response, transfer); err != nil {
		return dbq.ConnectorJob{}, service.Detail(service.ErrInvalidInput, "%s", err)
	}
	_, err = q.AcceptConnectorExportCompletion(ctx, dbq.AcceptConnectorExportCompletionParams{
		ActualSize: pgtype.Int8{Int64: response.Size, Valid: true}, ActualSha256: text(response.SHA256), MultipartParts: partsJSON,
		JobID: pg(jobID), AttemptToken: pg(attemptToken), ConnectorID: pg(connectorID),
		FinalizationDeadlineAt: timestamp(time.Now().UTC().Add(time.Hour)),
	})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return dbq.ConnectorJob{}, err
	}
	job, getErr := q.GetConnectorJob(ctx, pg(jobID))
	if getErr != nil {
		return dbq.ConnectorJob{}, getErr
	}
	if err == nil {
		return job, nil
	}
	transfer, getErr = q.GetConnectorTransfer(ctx, pg(jobID))
	if getErr != nil {
		return dbq.ConnectorJob{}, getErr
	}
	if uuid.UUID(job.ConnectorID.Bytes) == connectorID && transfer.FinalizationAttemptToken.Valid && uuid.UUID(transfer.FinalizationAttemptToken.Bytes) == attemptToken &&
		transfer.ActualSize.Valid && transfer.ActualSize.Int64 == response.Size && transfer.ActualSha256.Valid && transfer.ActualSha256.String == response.SHA256 &&
		jsonEqual(transfer.MultipartParts, partsJSON) && (transfer.State == "completing" || transfer.State == "finalizing" || transfer.State == "completed") {
		return job, nil
	}
	return dbq.ConnectorJob{}, service.Detail(service.ErrConflict, "connector job lease is stale or export result changed")
}

func validateUploadedParts(response protocol.DirectoryExportResponse, transfer dbq.ConnectorTransfer) ([]storage.CompletedPart, error) {
	if response.Size < 0 || response.Size > transfer.MaximumSize || !validSHA256(response.SHA256) {
		return nil, errors.New("connector export size or checksum is invalid")
	}
	if response.Size == 0 {
		if len(response.Parts) != 0 || response.SHA256 != hex.EncodeToString(sha256.New().Sum(nil)) {
			return nil, errors.New("empty connector export metadata is invalid")
		}
		return []storage.CompletedPart{}, nil
	}
	if len(response.Parts) == 0 || len(response.Parts) > int(transfer.MultipartPartCount.Int32) {
		return nil, errors.New("connector export part count is invalid")
	}
	parts := append([]protocol.UploadedPart(nil), response.Parts...)
	sort.Slice(parts, func(i, j int) bool { return parts[i].Number < parts[j].Number })
	completed := make([]storage.CompletedPart, len(parts))
	var total int64
	for i, part := range parts {
		if part.Number != i+1 || part.ETag == "" || len(part.ETag) > 256 || strings.ContainsAny(part.ETag, "\r\n") || part.Size <= 0 || part.Size > transfer.MultipartPartSize.Int64 {
			return nil, errors.New("connector export part metadata is invalid")
		}
		if i < len(parts)-1 && part.Size != transfer.MultipartPartSize.Int64 {
			return nil, errors.New("connector export has a short non-final part")
		}
		total += part.Size
		completed[i] = storage.CompletedPart{Number: part.Number, ETag: part.ETag}
	}
	if total != response.Size {
		return nil, errors.New("connector export part sizes do not match the result size")
	}
	return completed, nil
}

func validateDirectoryOutput(kind protocol.JobKind, raw json.RawMessage) error {
	if len(raw) == 0 || len(raw) > protocol.MaxJobPayloadBytes || !json.Valid(raw) {
		return service.Detail(service.ErrInvalidInput, "connector directory output is invalid or too large")
	}
	switch kind {
	case protocol.JobKindDirectoryList:
		var result protocol.DirectoryListResponse
		if err := strictDecode(raw, &result); err != nil || len(result.Entries) > 1000 || len(result.NextCursor) > 4096 {
			return service.Detail(service.ErrInvalidInput, "connector directory output does not match its protocol type")
		}
		for _, entry := range result.Entries {
			if !validDirectoryEntry(entry) {
				return service.Detail(service.ErrInvalidInput, "connector directory output contains invalid entry metadata")
			}
		}
		return nil
	case protocol.JobKindDirectoryRead:
		var result protocol.DirectoryReadResponse
		if err := strictDecode(raw, &result); err != nil || !validDirectoryEntry(result.Entry) || len(result.Data) > protocol.MaxInlineFileBytes {
			return service.Detail(service.ErrInvalidInput, "connector directory read output is invalid")
		}
		return nil
	case protocol.JobKindDirectoryStat, protocol.JobKindDirectoryWrite, protocol.JobKindDirectoryImport:
		var result protocol.DirectoryEntry
		if err := strictDecode(raw, &result); err != nil || !validDirectoryEntry(result) {
			return service.Detail(service.ErrInvalidInput, "connector directory entry output is invalid")
		}
		return nil
	case protocol.JobKindDirectoryDelete, protocol.JobKindDirectoryMove:
		var result struct{}
		if err := strictDecode(raw, &result); err != nil {
			return service.Detail(service.ErrInvalidInput, "connector directory output does not match its protocol type")
		}
		return nil
	case protocol.JobKindDirectoryExport:
		var result protocol.DirectoryExportResponse
		if err := strictDecode(raw, &result); err != nil {
			return service.Detail(service.ErrInvalidInput, "connector directory output does not match its protocol type")
		}
		return nil
	default:
		return nil
	}
}

func validDirectoryEntry(entry protocol.DirectoryEntry) bool {
	return entry.Path != "" && len(entry.Path) <= 4096 && entry.Name != "" && len(entry.Name) <= 1024 &&
		entry.Size >= 0 && entry.Mode <= 0o777 && len(entry.ContentType) <= 256 && !entry.ModifiedAt.IsZero()
}

func (s *Service) objectSHA256(ctx context.Context, key string, maximum int64) (string, int64, error) {
	reader, err := s.s3.GetObject(ctx, key)
	if err != nil {
		return "", 0, err
	}
	defer reader.Close()
	hasher := sha256.New()
	written, err := io.Copy(hasher, io.LimitReader(reader, maximum+1))
	if err != nil {
		return "", 0, err
	}
	if written > maximum {
		return "", written, service.Detail(service.ErrInvalidInput, "storage object exceeds %d bytes", maximum)
	}
	return hex.EncodeToString(hasher.Sum(nil)), written, nil
}

func jsonEqual(a, b []byte) bool {
	var left, right any
	return json.Unmarshal(a, &left) == nil && json.Unmarshal(b, &right) == nil && reflect.DeepEqual(left, right)
}

func transferOrigin(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return "", service.Detail(service.ErrConflict, "storage did not issue an activation-approved HTTPS transfer URL")
	}
	return "https://" + strings.ToLower(parsed.Host), nil
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func strictDecode(raw []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	return nil
}

func validSHA256(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == hex.EncodeToString(decoded)
}

func pg(id uuid.UUID) pgtype.UUID   { return pgtype.UUID{Bytes: id, Valid: true} }
func text(value string) pgtype.Text { return pgtype.Text{String: value, Valid: true} }
func timestamp(value time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: value, Valid: true}
}
