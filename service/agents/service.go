// Package agents owns the agent-lifecycle business logic: create,
// configure, build/upgrade/rollback, start/stop/suspend, list/get
// detail, and the per-agent git-remote bindings.
package agents

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/agentsdk/sourcebundle"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/builder"
	"github.com/airlockrun/airlock/container"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/secrets"
	"github.com/airlockrun/airlock/service"
	modelssvc "github.com/airlockrun/airlock/service/models"
	"github.com/airlockrun/airlock/trigger"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// BridgeStopper is the subset of *trigger.BridgeManager Delete uses.
type BridgeStopper interface {
	TeardownBridge(id uuid.UUID)
	RemoveBridge(id uuid.UUID)
}

type Service struct {
	db         *db.DB
	builder    *builder.BuildService
	dispatcher *trigger.Dispatcher
	containers container.ContainerManager
	bridgeMgr  BridgeStopper
	secrets    secrets.Store
	logger     *zap.Logger
}

func New(d *db.DB, build *builder.BuildService, dispatcher *trigger.Dispatcher, containers container.ContainerManager, bridgeMgr BridgeStopper, secretStore secrets.Store, logger *zap.Logger) *Service {
	if d == nil {
		panic("agents: db is required")
	}
	if build == nil {
		panic("agents: builder is required")
	}
	if dispatcher == nil {
		panic("agents: dispatcher is required")
	}
	if containers == nil {
		panic("agents: container manager is required")
	}
	if bridgeMgr == nil {
		panic("agents: bridge manager is required")
	}
	if secretStore == nil {
		panic("agents: secrets store is required")
	}
	if logger == nil {
		panic("agents: logger is required")
	}
	return &Service{
		db: d, builder: build, dispatcher: dispatcher,
		containers: containers, bridgeMgr: bridgeMgr, secrets: secretStore, logger: logger,
	}
}

// --- types ---

// CreateRequest is the input to Create — mirrors CreateAgentRequest but
// in plain Go.
type CreateRequest struct {
	Name             string
	Slug             string
	Description      string
	BuildModel       string
	BuildProviderID  string
	ExecModel        string
	ExecProviderID   string
	Instructions     string
	GitRemoteURL     string
	GitCredentialID  string
	GitDefaultBranch string
	GitMode          string
	SkipInitialBuild bool
	// SystemConversationID, when set (system-agent create_agent path),
	// routes the build-completion outcome back to that conversation.
	SystemConversationID string
}

// UpdateRequest mirrors UpdateAgentRequest. Pointer fields express
// "unset → keep existing".
type UpdateRequest struct {
	Name    *string
	Slug    *string
	AutoFix *bool
}

// ListItem is one row from List plus the live container-running flag
// and the caller's effective access on this agent.
//
// YourAccess is "admin" / "user" / "public" (see agentsdk.Access),
// resolved from agent_grants at list time. It exists so any caller —
// web UI, A2A, the in-airlock system agent — can decide locally which
// per-agent actions to offer without re-authorizing each one.
type ListItem struct {
	Agent      dbq.Agent       `json:"agent"`
	Running    bool            `json:"running"`
	YourAccess agentsdk.Access `json:"your_access"`
	// OwnerName is the agent owner principal's display name (user display name
	// or group name); IsOwner is true when the caller owns the agent (the owner
	// principal is in the caller's grantee set).
	OwnerName string `json:"owner_name"`
	IsOwner   bool   `json:"is_owner"`
}

// Detail is the Get response payload — the agent plus the per-agent
// resource lists the agent-detail page renders. YourAccess mirrors
// ListItem.YourAccess so callers don't need a second lookup.
type Detail struct {
	Agent       dbq.Agent                              `json:"agent"`
	Running     bool                                   `json:"running"`
	IsOwner     bool                                   `json:"is_owner"`
	YourAccess  agentsdk.Access                        `json:"your_access"`
	Connections []dbq.ListConnectionNeedsByAgentRow    `json:"connections"`
	Webhooks    []dbq.ListWebhooksByAgentWithStatusRow `json:"webhooks"`
	Schedules   []dbq.ListSchedulesWithNextFireRow     `json:"schedules"`
	Routes      []dbq.AgentRoute                       `json:"routes"`
}

// FireScheduleResult is the output of FireSchedule — the run ID for the SPA to
// subscribe to.
type FireScheduleResult struct {
	RunID uuid.UUID
}

// GitConfig is the read-side view of the agent's external git binding.
type GitConfig struct {
	RemoteURL      string
	CredentialID   string // empty when not connected
	CredentialName string
	DefaultBranch  string
	WebhookSecret  string
	LastSyncedRef  string
	Mode           string
}

// ConnectGitRequest is the input to ConnectGit.
type ConnectGitRequest struct {
	RemoteURL     string
	CredentialID  string
	DefaultBranch string
	Mode          string
}

const (
	sourceUploadMaxFiles             = 10000
	sourceUploadMaxUncompressedBytes = 100 << 20 // 100 MiB
)

var (
	ErrSourcePreconditionRequired = errors.New("source precondition required")
	ErrSourceStateMismatch        = errors.New("source state mismatch")
)

const (
	GitModeReadWrite  = "read_write"
	GitModeReadOnly   = "read_only"
	GitModeImportOnce = "import_once"
)

// --- helpers ---

var agentSlugRe = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

func validAgentSlug(s string) bool {
	if len(s) < 2 || len(s) > 63 {
		return false
	}
	return agentSlugRe.MatchString(s)
}

func parseOptionalProviderID(s string) (pgtype.UUID, error) {
	if s == "" {
		return pgtype.UUID{}, nil
	}
	id, err := uuid.Parse(s)
	if err != nil {
		return pgtype.UUID{}, err
	}
	return pgtype.UUID{Bytes: id, Valid: true}, nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// broadcastSiblingChange triggers a /refresh on every active agent
// except changedAgentID — used after create/update/delete so peer agents
// pick up the new agent_<slug> binding without restarting.
func (s *Service) broadcastSiblingChange(ctx context.Context, changedAgentID uuid.UUID) {
	q := dbq.New(s.db.Pool())
	rows, err := q.ListActiveAgentIDs(ctx)
	if err != nil {
		s.logger.Error("broadcast: list active agents", zap.Error(err))
		return
	}
	var wg sync.WaitGroup
	for _, r := range rows {
		id := uuid.UUID(r.Bytes)
		if id == changedAgentID {
			continue
		}
		wg.Add(1)
		go func(target uuid.UUID) {
			defer wg.Done()
			rctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := s.dispatcher.RefreshAgent(rctx, target); err != nil {
				s.logger.Warn("broadcast: refresh failed",
					zap.String("agent_id", target.String()), zap.Error(err))
			}
		}(id)
	}
	wg.Wait()
}

// --- methods ---

// Create creates an agent row (status=draft), records explicit per-agent
// model overrides if provided, auto-adds the creator as agent-admin, and
// kicks off the async build pipeline. Returns the freshly-inserted row;
// the build runs in a background goroutine and reports state via
// agent_builds + the runtime WebSocket.
func (s *Service) Create(ctx context.Context, p authz.Principal, req CreateRequest) (dbq.Agent, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.TenantAgentCreate, uuid.Nil); err != nil {
		return dbq.Agent{}, service.Detail(err, "creating agents requires manager role")
	}
	if req.Name == "" {
		return dbq.Agent{}, service.Detail(service.ErrInvalidInput, "name is required")
	}
	if req.Slug == "" {
		return dbq.Agent{}, service.Detail(service.ErrInvalidInput, "slug is required")
	}
	buildProviderFK, err := parseOptionalProviderID(req.BuildProviderID)
	if err != nil {
		return dbq.Agent{}, service.Detail(service.ErrInvalidInput, "invalid build_provider_id: %s", err.Error())
	}
	if (req.BuildModel != "") != buildProviderFK.Valid {
		return dbq.Agent{}, service.Detail(service.ErrInvalidInput, "build_model and build_provider_id must be set or unset together")
	}
	execProviderFK, err := parseOptionalProviderID(req.ExecProviderID)
	if err != nil {
		return dbq.Agent{}, service.Detail(service.ErrInvalidInput, "invalid exec_provider_id: %s", err.Error())
	}
	if (req.ExecModel != "") != execProviderFK.Valid {
		return dbq.Agent{}, service.Detail(service.ErrInvalidInput, "exec_model and exec_provider_id must be set or unset together")
	}
	if err := modelssvc.CheckEntitled(ctx, q, p, buildProviderFK, req.BuildModel); err != nil {
		return dbq.Agent{}, err
	}
	if err := modelssvc.CheckEntitled(ctx, q, p, execProviderFK, req.ExecModel); err != nil {
		return dbq.Agent{}, err
	}
	var gitCredFK pgtype.UUID
	gitRemoteURL := req.GitRemoteURL
	gitMode := strings.TrimSpace(req.GitMode)
	gitBranch := strings.TrimSpace(req.GitDefaultBranch)
	if gitBranch == "" {
		gitBranch = "main"
	}
	// importFromRemote: the remote already has code on the target branch, so
	// adopt it instead of scaffolding + pushing a fresh agent over it.
	importFromRemote := false
	remoteHeadSHA := ""
	if req.GitRemoteURL != "" {
		switch gitMode {
		case GitModeReadWrite, GitModeReadOnly, GitModeImportOnce:
		default:
			return dbq.Agent{}, service.Detail(service.ErrInvalidInput, "git_mode must be read_write, read_only, or import_once")
		}
		if req.SkipInitialBuild {
			return dbq.Agent{}, service.Detail(service.ErrInvalidInput, "skip_initial_build cannot be combined with git_remote_url")
		}
		// Normalize/validate the scheme here too — the connect path did but
		// create didn't, which is how SSH remotes (unusable with a PAT) slipped
		// through and failed at push time.
		normalized, nerr := normalizeGitRemoteURL(req.GitRemoteURL)
		if nerr != nil {
			return dbq.Agent{}, service.Detail(service.ErrInvalidInput, "%s", nerr.Error())
		}
		gitRemoteURL = normalized
		if req.GitCredentialID == "" {
			return dbq.Agent{}, service.Detail(service.ErrInvalidInput, "git_credential_id is required when git_remote_url is set")
		}
		credID, err := uuid.Parse(req.GitCredentialID)
		if err != nil {
			return dbq.Agent{}, service.Detail(service.ErrInvalidInput, "invalid git_credential_id")
		}
		cred, err := q.GetGitCredential(ctx, pgtype.UUID{Bytes: credID, Valid: true})
		if err != nil {
			return dbq.Agent{}, service.Detail(service.ErrNotFound, "git credential not found")
		}
		if uuid.UUID(cred.UserID.Bytes) != p.UserID {
			return dbq.Agent{}, service.Detail(service.ErrForbidden, "git credential does not belong to you")
		}
		gitCredFK = pgtype.UUID{Bytes: credID, Valid: true}
		// Validate reachability up front (bad URL/token fails create, not the
		// build) and detect empty→mirror vs populated→import.
		state, ierr := s.builder.InspectRemote(ctx, gitRemoteURL, gitBranch, gitCredFK)
		if ierr != nil {
			s.logger.Warn("git create: inspect remote", zap.Error(ierr))
			return dbq.Agent{}, service.Detail(service.ErrInvalidInput, "could not access %s with the selected credential — verify the URL and that the token has repo access", gitRemoteURL)
		}
		// A populated remote is imported regardless of which branch holds the
		// code — adopt the remote's default branch when the requested one is
		// absent (a repo on "master" must not fall through to scaffold+push).
		importFromRemote = !state.Empty
		if state.Empty && gitMode != GitModeReadWrite {
			return dbq.Agent{}, service.Detail(service.ErrInvalidInput, "git remote has no code to import; read_only and import_once require a populated repository")
		}
		if importFromRemote {
			if b := state.ImportBranch(gitBranch); b != "" {
				gitBranch = b
			}
			if state.HasBranch {
				remoteHeadSHA = state.HeadSHA
			} else {
				remoteHeadSHA = state.DefaultHeadSHA
			}
		}
		if gitMode == GitModeReadWrite {
			if err := s.builder.ValidateRemoteWrite(ctx, gitRemoteURL, gitBranch, gitCredFK, state.Empty); err != nil {
				return dbq.Agent{}, service.Detail(service.ErrInvalidInput, "read_write Git requires a credential that can push %s: %s", gitBranch, err.Error())
			}
		}
	} else if gitMode != "" {
		return dbq.Agent{}, service.Detail(service.ErrInvalidInput, "git_mode requires git_remote_url")
	}
	agent, err := q.CreateAgent(ctx, dbq.CreateAgentParams{
		Name:             req.Name,
		Slug:             req.Slug,
		OwnerPrincipalID: pgtype.UUID{Bytes: p.UserID, Valid: true},
		Description:      req.Description,
		Config:           []byte("{}"),
	})
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return dbq.Agent{}, service.Detail(service.ErrConflict, "agent slug already exists")
		}
		s.logger.Error("create agent", zap.Error(err))
		return dbq.Agent{}, err
	}
	if req.BuildModel != "" || req.ExecModel != "" {
		_ = q.UpdateAgentModels(ctx, dbq.UpdateAgentModelsParams{
			ID:              agent.ID,
			BuildProviderID: buildProviderFK,
			BuildModel:      req.BuildModel,
			ExecProviderID:  execProviderFK,
			ExecModel:       req.ExecModel,
		})
		agent.BuildProviderID = buildProviderFK
		agent.BuildModel = req.BuildModel
		agent.ExecProviderID = execProviderFK
		agent.ExecModel = req.ExecModel
	}
	_ = q.UpsertAgentGrant(ctx, dbq.UpsertAgentGrantParams{
		AgentID:   agent.ID,
		GranteeID: pgtype.UUID{Bytes: p.UserID, Valid: true},
		Role:      "admin",
	})
	agentIDStr := uuid.UUID(agent.ID.Bytes).String()

	// Import: the remote already has code, so connect + clone it in now
	// (synchronously, like a clone — a failure rolls the create back cleanly),
	// then build the imported HEAD below with SkipScaffold. An empty remote
	// falls through to the scaffold build, which mirrors the new agent to it.
	if importFromRemote {
		if gitMode != GitModeImportOnce {
			secret, err := randomHex(32)
			if err != nil {
				_ = q.DeleteAgent(ctx, agent.ID)
				return dbq.Agent{}, err
			}
			storedSecret, err := s.secrets.Put(ctx, gitWebhookSecretRef(uuid.UUID(agent.ID.Bytes)), secret)
			if err != nil {
				_ = q.DeleteAgent(ctx, agent.ID)
				return dbq.Agent{}, err
			}
			if err := q.ConnectAgentGit(ctx, dbq.ConnectAgentGitParams{
				ID:               agent.ID,
				GitRemoteUrl:     gitRemoteURL,
				GitCredentialID:  gitCredFK,
				GitDefaultBranch: gitBranch,
				GitWebhookSecret: storedSecret,
				GitMode:          gitMode,
			}); err != nil {
				_ = q.DeleteAgent(ctx, agent.ID)
				s.logger.Error("git create import: connect", zap.Error(err))
				return dbq.Agent{}, err
			}
		}
		if err := s.builder.CloneRemoteIntoAgent(ctx, agentIDStr, gitRemoteURL, gitBranch, gitCredFK); err != nil {
			_ = q.DeleteAgent(ctx, agent.ID)
			s.logger.Error("git create import: clone", zap.String("agent", agentIDStr), zap.Error(err))
			return dbq.Agent{}, service.Detail(service.ErrInvalidInput, "failed to import repository: %s", err.Error())
		}
		if gitMode != GitModeImportOnce && remoteHeadSHA != "" {
			_ = q.UpdateAgentGitLastSyncedRef(ctx, dbq.UpdateAgentGitLastSyncedRefParams{
				ID:               agent.ID,
				GitLastSyncedRef: remoteHeadSHA,
			})
		}
	}

	if req.SkipInitialBuild {
		return agent, nil
	}

	go func() {
		in := builder.BuildInput{
			AgentID:              agentIDStr,
			Name:                 req.Name,
			Slug:                 req.Slug,
			OwnerPrincipalID:     p.UserID.String(),
			InitiatorUserID:      pgUserID(p),
			BuildProviderID:      buildProviderFK,
			BuildModel:           req.BuildModel,
			SystemConversationID: req.SystemConversationID,
		}
		if importFromRemote {
			// Build the cloned HEAD as-is: no scaffold over it, no codegen.
			in.SkipScaffold = true
		} else {
			// Scaffold a fresh agent; Phase C2 mirrors it to the (empty) remote.
			in.Instructions = req.Instructions
			in.GitRemoteURL = gitRemoteURL
			in.GitCredentialID = gitCredFK
			in.GitDefaultBranch = gitBranch
			in.GitMode = gitMode
		}
		_ = s.builder.Build(context.Background(), in)
	}()
	return agent, nil
}

// SourceState returns the canonical content state of the agent's internal HEAD.
func (s *Service) SourceState(ctx context.Context, p authz.Principal, agentID uuid.UUID) (string, error) {
	q := dbq.New(s.db.Pool())
	if _, err := q.GetAgentByID(ctx, pgtype.UUID{Bytes: agentID, Valid: true}); err != nil {
		return "", service.ErrNotFound
	}
	if err := authz.Authorize(ctx, q, p, authz.AgentBuildManage, agentID); err != nil {
		return "", err
	}
	lock, err := s.builder.AcquireSourceLock(ctx, agentID.String())
	if err != nil {
		return "", err
	}
	defer lock.Unlock()
	return sourceState(s.builder.AgentRepoPath(agentID.String()))
}

// DownloadSource writes the canonical source archive and returns its state.
func (s *Service) DownloadSource(ctx context.Context, p authz.Principal, agentID uuid.UUID, w io.Writer) (string, error) {
	q := dbq.New(s.db.Pool())
	if _, err := q.GetAgentByID(ctx, pgtype.UUID{Bytes: agentID, Valid: true}); err != nil {
		return "", service.ErrNotFound
	}
	if err := authz.Authorize(ctx, q, p, authz.AgentBuildManage, agentID); err != nil {
		return "", err
	}
	lock, err := s.builder.AcquireSourceLock(ctx, agentID.String())
	if err != nil {
		return "", err
	}
	defer lock.Unlock()
	repoPath := s.builder.AgentRepoPath(agentID.String())
	state, err := sourceState(repoPath)
	if err != nil {
		return "", err
	}
	if state == "" {
		return "", service.Detail(service.ErrConflict, "agent has no source yet")
	}
	writtenState, err := sourcebundle.WriteArchive(w, repoPath)
	if err != nil {
		return "", fmt.Errorf("archive source: %w", err)
	}
	if writtenState != state {
		return "", fmt.Errorf("source changed while archiving: %s != %s", writtenState, state)
	}
	return state, nil
}

// UploadSource replaces an agent's internal source tree with a gzipped tar
// archive and starts a build from that committed source. expectedState is the
// state last observed by the caller; force explicitly bypasses that check.
func (s *Service) UploadSource(ctx context.Context, p authz.Principal, agentID uuid.UUID, archive io.Reader, expectedState, rawCommitMessage string, force bool) (string, error) {
	q := dbq.New(s.db.Pool())
	agent, err := q.GetAgentByID(ctx, pgtype.UUID{Bytes: agentID, Valid: true})
	if err != nil {
		return "", service.ErrNotFound
	}
	if err := authz.Authorize(ctx, q, p, authz.AgentBuildManage, agentID); err != nil {
		return "", err
	}
	commitMessage, err := sourceCommitMessage(rawCommitMessage)
	if err != nil {
		return "", service.Detail(service.ErrInvalidInput, "%s", err)
	}
	if agent.Status == "building" {
		return "", service.Detail(service.ErrConflict, "agent is already building")
	}
	if agent.GitMode == GitModeReadOnly {
		return "", service.Detail(service.ErrConflict, "agent uses read-only Git; push source changes to the connected repository")
	}
	lock, err := s.builder.AcquireSourceLock(ctx, agentID.String())
	if err != nil {
		return "", err
	}
	defer lock.Unlock()

	workDir, err := os.MkdirTemp("", "airlock-source-*")
	if err != nil {
		return "", fmt.Errorf("create source temp dir: %w", err)
	}
	defer os.RemoveAll(workDir)

	if err := extractSourceArchive(archive, workDir); err != nil {
		return "", err
	}
	if _, err := os.Stat(filepath.Join(workDir, "go.mod")); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", service.Detail(service.ErrInvalidInput, "source archive must contain go.mod at the root")
		}
		return "", fmt.Errorf("stat go.mod: %w", err)
	}

	agentIDStr := agentID.String()
	repoPath := s.builder.AgentRepoPath(agentIDStr)
	uploadedState, err := sourcebundle.Digest(workDir)
	if err != nil {
		return "", err
	}
	currentState, err := sourceState(repoPath)
	if err != nil {
		return "", err
	}
	if !force {
		switch {
		case currentState != "" && expectedState == "":
			return "", ErrSourcePreconditionRequired
		case expectedState != currentState:
			return "", ErrSourceStateMismatch
		}
	}
	if currentState != "" && uploadedState == currentState {
		return currentState, nil
	}

	initialBuild := agent.ImageRef == ""
	upgradeLocked := false
	if !initialBuild {
		if err := s.builder.AcquireUpgradeLock(ctx, agentIDStr); err != nil {
			if errors.Is(err, builder.ErrUpgradeInProgress) {
				return "", service.Detail(service.ErrConflict, "agent upgrade is already in progress")
			}
			return "", fmt.Errorf("reserve source deploy build: %w", err)
		}
		upgradeLocked = true
		defer func() {
			if upgradeLocked {
				if err := q.UpdateAgentUpgradeStatus(context.Background(), dbq.UpdateAgentUpgradeStatusParams{
					ID: agent.ID, UpgradeStatus: agent.UpgradeStatus, ErrorMessage: agent.ErrorMessage,
				}); err != nil {
					s.logger.Error("release source deploy upgrade lock", zap.String("agent", agentIDStr), zap.Error(err))
				}
			}
		}()
	}
	if err := builder.InitAgentRepo(s.builder.ReposPath(), agentIDStr); err != nil {
		return "", fmt.Errorf("init agent repo: %w", err)
	}
	if err := sourcebundle.Mirror(workDir, repoPath); err != nil {
		return "", fmt.Errorf("sync source to repo: %w", err)
	}
	if _, _, err := builder.CommitWorktree(repoPath, commitMessage); err != nil {
		return "", fmt.Errorf("commit uploaded source: %w", err)
	}
	newState, err := sourceState(repoPath)
	if err != nil {
		return "", err
	}
	if newState != uploadedState {
		return "", fmt.Errorf("committed source state %s, want %s", newState, uploadedState)
	}

	if initialBuild {
		go func() {
			if err := s.builder.Build(context.Background(), builder.BuildInput{
				AgentID:          agentIDStr,
				Name:             agent.Name,
				Slug:             agent.Slug,
				OwnerPrincipalID: uuid.UUID(agent.OwnerPrincipalID.Bytes).String(),
				InitiatorUserID:  pgUserID(p),
				BuildProviderID:  agent.BuildProviderID,
				BuildModel:       agent.BuildModel,
				SkipScaffold:     true,
				Message:          commitMessage,
			}); err != nil {
				s.logger.Error("source upload build", zap.String("agent", agentIDStr), zap.Error(err))
			}
		}()
	} else {
		go s.builder.RunUpgrade(context.Background(), builder.UpgradeInput{
			AgentID:         agentIDStr,
			InitiatorUserID: pgUserID(p),
			Reason:          "source_deploy",
			Message:         commitMessage,
		})
		upgradeLocked = false
	}
	return newState, nil
}

const maxSourceCommitMessageBytes = 200

func sourceCommitMessage(raw string) (string, error) {
	message := strings.TrimSpace(raw)
	if message == "" {
		return "", errors.New("source commit message is required")
	}
	if strings.ContainsAny(message, "\r\n") {
		return "", errors.New("source commit message must be a single line")
	}
	if len(message) > maxSourceCommitMessageBytes {
		return "", fmt.Errorf("source commit message is %d bytes; maximum is %d", len(message), maxSourceCommitMessageBytes)
	}
	return message, nil
}

func sourceState(repoPath string) (string, error) {
	if _, err := os.Stat(filepath.Join(repoPath, "go.mod")); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	state, err := sourcebundle.Digest(repoPath)
	if err != nil {
		return "", fmt.Errorf("hash source: %w", err)
	}
	return state, nil
}

func extractSourceArchive(r io.Reader, dst string) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return service.Detail(service.ErrInvalidInput, "source upload must be a gzipped tar archive")
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	var files int
	var total int64
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return service.Detail(service.ErrInvalidInput, "read source archive: %s", err.Error())
		}
		rel, skip, err := cleanArchivePath(h.Name)
		if err != nil {
			return err
		}
		if skip {
			continue
		}
		if h.Typeflag != tar.TypeDir {
			files++
			if files > sourceUploadMaxFiles {
				return service.Detail(service.ErrInvalidInput, "source archive contains too many files")
			}
		}
		target := filepath.Join(dst, filepath.FromSlash(rel))
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, h.FileInfo().Mode().Perm()); err != nil {
				return fmt.Errorf("mkdir %s: %w", rel, err)
			}
		case tar.TypeReg, tar.TypeRegA:
			if h.Size < 0 {
				return service.Detail(service.ErrInvalidInput, "source archive contains invalid file size for %s", rel)
			}
			total += h.Size
			if total > sourceUploadMaxUncompressedBytes {
				return service.Detail(service.ErrInvalidInput, "source archive is too large")
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return fmt.Errorf("mkdir parent for %s: %w", rel, err)
			}
			out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, h.FileInfo().Mode().Perm())
			if err != nil {
				return fmt.Errorf("create %s: %w", rel, err)
			}
			_, copyErr := io.Copy(out, tr)
			closeErr := out.Close()
			if copyErr != nil {
				return fmt.Errorf("write %s: %w", rel, copyErr)
			}
			if closeErr != nil {
				return fmt.Errorf("close %s: %w", rel, closeErr)
			}
		default:
			return service.Detail(service.ErrInvalidInput, "source archive contains unsupported entry %s", rel)
		}
	}
}

func cleanArchivePath(name string) (rel string, skip bool, err error) {
	if name == "" || strings.HasPrefix(name, "/") {
		return "", false, service.Detail(service.ErrInvalidInput, "source archive contains invalid path %q", name)
	}
	clean := path.Clean(name)
	if clean == "." || clean == "" {
		return "", true, nil
	}
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return "", false, service.Detail(service.ErrInvalidInput, "source archive contains invalid path %q", name)
	}
	if first := strings.SplitN(clean, "/", 2)[0]; first == ".git" || first == ".airlock" {
		return "", true, nil
	}
	return clean, false, nil
}

// CloneRequest is the input to Clone.
type CloneRequest struct {
	Name string
	Slug string
}

// Clone forks sourceID's code into a new agent owned by the caller. It copies
// the git repo (committed code) plus authored config — description, model-slot
// choices (providers are tenant-wide), emoji, protocol flags — and NOTHING
// else: no DB data, no S3 objects, no secrets, no resource bindings. The clone
// builds fresh (new schema, empty storage) and its first-boot Sync repopulates
// every code-derived declaration. Requires manager tenant role AND membership
// (AccessUser) of the source agent.
func (s *Service) Clone(ctx context.Context, p authz.Principal, sourceID uuid.UUID, req CloneRequest) (dbq.Agent, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.TenantAgentClone, uuid.Nil); err != nil {
		return dbq.Agent{}, service.Detail(err, "cloning agents requires manager role")
	}
	if err := authz.Authorize(ctx, q, p, authz.AgentClone, sourceID); err != nil {
		return dbq.Agent{}, service.Detail(err, "you must be a member of the agent to clone it")
	}
	src, err := q.GetAgentByID(ctx, pgtype.UUID{Bytes: sourceID, Valid: true})
	if err != nil {
		return dbq.Agent{}, service.ErrNotFound
	}
	if req.Name == "" {
		return dbq.Agent{}, service.Detail(service.ErrInvalidInput, "name is required")
	}
	if !validAgentSlug(req.Slug) {
		return dbq.Agent{}, service.Detail(service.ErrInvalidInput, "slug must be 2-63 lowercase kebab-case chars")
	}
	if src.SourceRef == "" {
		return dbq.Agent{}, service.Detail(service.ErrInvalidInput, "source agent has no built code to clone yet")
	}
	for _, pair := range []struct {
		provider pgtype.UUID
		model    string
	}{
		{src.BuildProviderID, src.BuildModel},
		{src.ExecProviderID, src.ExecModel},
		{src.SttProviderID, src.SttModel},
		{src.VisionProviderID, src.VisionModel},
		{src.TtsProviderID, src.TtsModel},
		{src.ImageGenProviderID, src.ImageGenModel},
		{src.EmbeddingProviderID, src.EmbeddingModel},
		{src.SearchProviderID, src.SearchModel},
	} {
		if err := modelssvc.CheckEntitled(ctx, q, p, pair.provider, pair.model); err != nil {
			return dbq.Agent{}, err
		}
	}

	agent, err := q.CreateAgent(ctx, dbq.CreateAgentParams{
		Name:             req.Name,
		Slug:             req.Slug,
		OwnerPrincipalID: pgtype.UUID{Bytes: p.UserID, Valid: true},
		Description:      src.Description,
		Config:           []byte("{}"),
	})
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return dbq.Agent{}, service.Detail(service.ErrConflict, "agent slug already exists")
		}
		s.logger.Error("clone: create agent", zap.Error(err))
		return dbq.Agent{}, err
	}
	// Cloner becomes admin owner (column set at create + the grant).
	_ = q.UpsertAgentGrant(ctx, dbq.UpsertAgentGrantParams{
		AgentID:   agent.ID,
		GranteeID: pgtype.UUID{Bytes: p.UserID, Valid: true},
		Role:      "admin",
	})
	// Authored config: models (tenant-wide providers stay valid), emoji, flags.
	_ = q.UpdateAgentModels(ctx, dbq.UpdateAgentModelsParams{
		ID:              agent.ID,
		BuildProviderID: src.BuildProviderID, BuildModel: src.BuildModel,
		ExecProviderID: src.ExecProviderID, ExecModel: src.ExecModel,
		SttProviderID: src.SttProviderID, SttModel: src.SttModel,
		VisionProviderID: src.VisionProviderID, VisionModel: src.VisionModel,
		TtsProviderID: src.TtsProviderID, TtsModel: src.TtsModel,
		ImageGenProviderID: src.ImageGenProviderID, ImageGenModel: src.ImageGenModel,
		EmbeddingProviderID: src.EmbeddingProviderID, EmbeddingModel: src.EmbeddingModel,
		SearchProviderID: src.SearchProviderID, SearchModel: src.SearchModel,
	})
	_ = q.UpdateAgentEmoji(ctx, dbq.UpdateAgentEmojiParams{ID: agent.ID, Emoji: src.Emoji})
	_ = q.UpdateAgentA2ASettings(ctx, dbq.UpdateAgentA2ASettingsParams{
		ID: agent.ID, McpEnabled: src.McpEnabled, AllowPublicMcp: src.AllowPublicMcp, AllowPublicRoutes: src.AllowPublicRoutes,
	})

	newIDStr := uuid.UUID(agent.ID.Bytes).String()
	// Copy the repo BEFORE build so InitAgentRepo no-ops and the build rebuilds
	// the copied HEAD (empty Instructions ⇒ no codegen). Roll back the row if
	// the copy fails so we never leave a codeless clone.
	if err := builder.CopyAgentRepo(s.builder.ReposPath(), sourceID.String(), newIDStr); err != nil {
		_ = q.DeleteAgent(ctx, agent.ID)
		s.logger.Error("clone: copy repo", zap.Error(err))
		return dbq.Agent{}, service.Detail(service.ErrConflict, "failed to copy agent code: %s", err.Error())
	}
	go func() {
		_ = s.builder.Build(context.Background(), builder.BuildInput{
			AgentID:          newIDStr,
			Name:             req.Name,
			Slug:             req.Slug,
			OwnerPrincipalID: p.UserID.String(),
			BuildProviderID:  src.BuildProviderID,
			BuildModel:       src.BuildModel,
			Instructions:     "",   // rebuild the copied repo; no codegen
			SkipScaffold:     true, // repo is copied in complete — don't clobber it
		})
	}()
	return agent, nil
}

// List returns the agents the caller can access — grant-joined (own + member
// + group-shared), annotated with the live container-running flag. Tenant
// admins do NOT see every agent here: the main page is the caller's working
// set. The all-agents governance surface is ListAll.
func (s *Service) List(ctx context.Context, p authz.Principal) ([]ListItem, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.TenantAgentList, uuid.Nil); err != nil {
		return nil, err
	}
	set := p.GranteeSet()
	grantees := make([]pgtype.UUID, len(set))
	for i, id := range set {
		grantees[i] = pgtype.UUID{Bytes: id, Valid: true}
	}
	agents, err := q.ListAgentsVisibleToUser(ctx, grantees)
	if err != nil {
		s.logger.Error("list agents", zap.Error(err))
		return nil, err
	}
	return s.buildListItems(ctx, q, p, agents), nil
}

// ListAll returns every agent in the tenant — the admin governance surface
// behind Settings. Agents the caller isn't a member of come back with
// YourAccess=public and IsOwner=false, so the UI can offer Claim. Admin-only.
func (s *Service) ListAll(ctx context.Context, p authz.Principal) ([]ListItem, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.TenantAgentListAll, uuid.Nil); err != nil {
		return nil, err
	}
	agents, err := q.ListAgents(ctx)
	if err != nil {
		s.logger.Error("list all agents", zap.Error(err))
		return nil, err
	}
	return s.buildListItems(ctx, q, p, agents), nil
}

// buildListItems decorates raw agent rows with the owner's display name, the
// caller's effective access, the ownership flag, and live running state,
// sorting owner-owned agents first.
func (s *Service) buildListItems(ctx context.Context, q *dbq.Queries, p authz.Principal, agents []dbq.Agent) []ListItem {
	// Owner principal in the caller's grantee set ⇒ they own the agent
	// (directly or via a group). Resolve owner display names in one batch.
	ownsSet := make(map[uuid.UUID]struct{})
	for _, id := range p.GranteeSet() {
		ownsSet[id] = struct{}{}
	}
	ownerNames := make(map[uuid.UUID]string)
	ownerIDs := make([]pgtype.UUID, 0, len(agents))
	seenOwner := make(map[uuid.UUID]struct{})
	for _, a := range agents {
		oid := uuid.UUID(a.OwnerPrincipalID.Bytes)
		if _, ok := seenOwner[oid]; ok || !a.OwnerPrincipalID.Valid {
			continue
		}
		seenOwner[oid] = struct{}{}
		ownerIDs = append(ownerIDs, a.OwnerPrincipalID)
	}
	if len(ownerIDs) > 0 {
		if rows, err := q.ResolvePrincipalNames(ctx, ownerIDs); err != nil {
			s.logger.Warn("list agents: owner-name lookup failed", zap.Error(err))
		} else {
			for _, r := range rows {
				ownerNames[uuid.UUID(r.ID.Bytes)] = r.Name
			}
		}
	}

	out := make([]ListItem, len(agents))
	ids := make([]uuid.UUID, len(agents))
	for i, a := range agents {
		oid := uuid.UUID(a.OwnerPrincipalID.Bytes)
		_, isOwner := ownsSet[oid]
		out[i] = ListItem{
			Agent:      a,
			YourAccess: p.EffectiveAgentAccess(ctx, q, uuid.UUID(a.ID.Bytes)),
			OwnerName:  ownerNames[oid],
			IsOwner:    a.OwnerPrincipalID.Valid && isOwner,
		}
		ids[i] = uuid.UUID(a.ID.Bytes)
	}
	if len(ids) > 0 {
		if running, err := s.containers.RunningAgents(ctx, ids); err != nil {
			s.logger.Warn("list agents: running-state lookup failed", zap.Error(err))
		} else {
			for i := range out {
				out[i].Running = running[ids[i]]
			}
		}
	}
	// Owner-owned agents first, then the rest. Stable so the underlying
	// created_at-DESC order is preserved within each group.
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].IsOwner && !out[j].IsOwner
	})
	return out
}

// Get returns the member-readable agent detail. Agent-admin collections are
// included only when the caller satisfies their corresponding policy action.
func (s *Service) Get(ctx context.Context, p authz.Principal, agentID uuid.UUID) (Detail, error) {
	q := dbq.New(s.db.Pool())
	pgID := pgtype.UUID{Bytes: agentID, Valid: true}
	agent, err := q.GetAgentByID(ctx, pgID)
	if err != nil {
		return Detail{}, service.ErrNotFound
	}
	if err := authz.Authorize(ctx, q, p, authz.AgentGet, agentID); err != nil {
		return Detail{}, err
	}
	var conns []dbq.ListConnectionNeedsByAgentRow
	if authz.Authorize(ctx, q, p, authz.AgentConnections, agentID) == nil {
		conns, _ = q.ListConnectionNeedsByAgent(ctx, pgID)
	}
	var webhooks []dbq.ListWebhooksByAgentWithStatusRow
	if authz.Authorize(ctx, q, p, authz.AgentWebhooksView, agentID) == nil {
		webhooks, err = q.ListWebhooksByAgentWithStatus(ctx, pgID)
		if err != nil {
			return Detail{}, err
		}
		if err := s.decryptWebhookRows(ctx, webhooks); err != nil {
			return Detail{}, err
		}
	}
	var schedules []dbq.ListSchedulesWithNextFireRow
	if authz.Authorize(ctx, q, p, authz.AgentSchedulesView, agentID) == nil {
		schedules, _ = q.ListSchedulesWithNextFire(ctx, pgID)
	}
	var routes []dbq.AgentRoute
	if authz.Authorize(ctx, q, p, authz.AgentRoutesView, agentID) == nil {
		routes, _ = q.ListRoutesByAgent(ctx, pgID)
	}
	ownerID := uuid.UUID(agent.OwnerPrincipalID.Bytes)
	isOwner := false
	if agent.OwnerPrincipalID.Valid {
		for _, g := range p.GranteeSet() {
			if g == ownerID {
				isOwner = true
				break
			}
		}
	}
	d := Detail{
		Agent:       agent,
		IsOwner:     isOwner,
		YourAccess:  p.EffectiveAgentAccess(ctx, q, agentID),
		Connections: conns,
		Webhooks:    webhooks,
		Schedules:   schedules,
		Routes:      routes,
	}
	if c, gerr := s.containers.GetRunning(ctx, agentID); gerr == nil && c != nil {
		d.Running = true
	}
	return d, nil
}

// Update applies a partial update; each nil field on the request keeps
// the existing value. Name/slug changes trigger an async sibling
// refresh fan-out.
func (s *Service) Update(ctx context.Context, p authz.Principal, agentID uuid.UUID, req UpdateRequest) (dbq.Agent, error) {
	q := dbq.New(s.db.Pool())
	agent, err := q.GetAgentByID(ctx, pgtype.UUID{Bytes: agentID, Valid: true})
	if err != nil {
		return dbq.Agent{}, service.ErrNotFound
	}
	if err := authz.Authorize(ctx, q, p, authz.AgentUpdate, agentID); err != nil {
		return dbq.Agent{}, err
	}
	autoFix := agent.AutoFix
	if req.AutoFix != nil {
		autoFix = *req.AutoFix
	}
	name := agent.Name
	if req.Name != nil {
		name = strings.TrimSpace(*req.Name)
		if name == "" {
			return dbq.Agent{}, service.Detail(service.ErrInvalidInput, "name cannot be empty")
		}
		if len(name) > 100 {
			return dbq.Agent{}, service.Detail(service.ErrInvalidInput, "name too long (max 100)")
		}
	}
	slug := agent.Slug
	if req.Slug != nil && *req.Slug != agent.Slug {
		slug = *req.Slug
		if !validAgentSlug(slug) {
			return dbq.Agent{}, service.Detail(service.ErrInvalidInput, "slug must be 2–63 chars, lowercase letters/digits separated by single dashes")
		}
	}
	nameChanged := name != agent.Name
	slugChanged := slug != agent.Slug
	updated, err := q.UpdateAgentFields(ctx, dbq.UpdateAgentFieldsParams{
		ID:      pgtype.UUID{Bytes: agentID, Valid: true},
		Name:    name,
		Slug:    slug,
		AutoFix: autoFix,
	})
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return dbq.Agent{}, service.Detail(service.ErrConflict, "agent slug already exists")
		}
		s.logger.Error("update agent", zap.Error(err))
		return dbq.Agent{}, err
	}
	if nameChanged || slugChanged {
		go s.broadcastSiblingChange(context.Background(), agentID)
	}
	return updated, nil
}

// authorizeGovernance permits an operation when the caller has the per-agent
// access (agentAction) or, failing that, the tenant-wide governance action
// (tenantAction) — a tenant admin acting on an agent they're not a member of.
// On denial it returns the agent-axis error so a non-admin still sees the
// membership requirement, not the tenant one.
func authorizeGovernance(ctx context.Context, q *dbq.Queries, p authz.Principal, agentAction, tenantAction authz.Action, agentID uuid.UUID) error {
	err := authz.Authorize(ctx, q, p, agentAction, agentID)
	if err == nil {
		return nil
	}
	if authz.Authorize(ctx, q, p, tenantAction, uuid.Nil) == nil {
		return nil
	}
	return err
}

// Delete cancels in-flight builds, stops bridge pollers, stops the
// container, removes the image, drops the per-agent schema/role,
// removes the local repo, deletes the row (CASCADE handles the rest),
// and broadcasts the sibling change.
func (s *Service) Delete(ctx context.Context, p authz.Principal, agentID uuid.UUID) error {
	q := dbq.New(s.db.Pool())
	agent, err := q.GetAgentByID(ctx, pgtype.UUID{Bytes: agentID, Valid: true})
	if err != nil {
		return service.ErrNotFound
	}
	if err := authorizeGovernance(ctx, q, p, authz.AgentDelete, authz.TenantAgentDeleteAny, agentID); err != nil {
		return err
	}
	if _, err := q.IncrementAgentTokenVersion(ctx, agent.ID); err != nil {
		return fmt.Errorf("revoke agent token before delete: %w", err)
	}
	s.builder.CancelBuildAndWait(agentID.String(), 30*time.Second)
	if bridgeIDs, err := q.ListBridgesByAgentID(ctx, pgtype.UUID{Bytes: agentID, Valid: true}); err == nil {
		for _, bid := range bridgeIDs {
			bridgeUUID, err := uuid.FromBytes(bid.Bytes[:])
			if err != nil {
				continue
			}
			// Teardown first (clears the Telegram menu button) while the row +
			// token still exist; the agent delete below orphans the bridge
			// (agent_id → NULL).
			s.bridgeMgr.TeardownBridge(bridgeUUID)
			s.bridgeMgr.RemoveBridge(bridgeUUID)
		}
	}
	if err := s.containers.StopAgent(ctx, agentID); err != nil {
		return fmt.Errorf("stop agent before delete: %w", err)
	}
	if agent.ImageRef != "" {
		_ = s.containers.RemoveImage(ctx, agent.ImageRef)
	}
	schemaName := "agent_" + strings.ReplaceAll(agentID.String(), "-", "")
	if conn, err := s.db.Pool().Acquire(ctx); err == nil {
		conn.Exec(ctx, fmt.Sprintf("DROP SCHEMA IF EXISTS %s CASCADE", schemaName))
		conn.Exec(ctx, fmt.Sprintf("DROP ROLE IF EXISTS %s", schemaName))
		conn.Release()
	}
	if err := builder.RemoveAgentRepo(s.builder.ReposPath(), agentID.String()); err != nil {
		s.logger.Warn("remove agent repo", zap.Error(err))
	}
	if err := q.DeleteAgent(ctx, pgtype.UUID{Bytes: agentID, Valid: true}); err != nil {
		s.logger.Error("delete agent", zap.Error(err))
		return err
	}
	go s.broadcastSiblingChange(context.Background(), agentID)
	return nil
}

// TransferOwnership hands the agent to newOwnerID. Moves the owner column AND
// the admin grant together, removes the old owner, and unbinds every
// owner-scoped binding — connection/MCP/exec bindings, the git credential, and
// bridges — because the new owner has no access to the old owner's resources.
// The need rows and agent code stay; only the bindings clear. Caller must be
// the current owner or a tenant admin. Env-var values (agent-scoped) and model
// slots (tenant-wide providers) are kept.
func (s *Service) TransferOwnership(ctx context.Context, p authz.Principal, agentID, newOwnerID uuid.UUID) (dbq.Agent, error) {
	q := dbq.New(s.db.Pool())
	agent, err := q.GetAgentByID(ctx, pgtype.UUID{Bytes: agentID, Valid: true})
	if err != nil {
		return dbq.Agent{}, service.ErrNotFound
	}
	oldOwnerID := uuid.UUID(agent.OwnerPrincipalID.Bytes)
	if err := authz.AuthorizeOwnedResource(ctx, q, p, oldOwnerID, authz.TenantAgentTransferAny); err != nil {
		return dbq.Agent{}, err
	}
	if newOwnerID == uuid.Nil {
		return dbq.Agent{}, service.Detail(service.ErrInvalidInput, "new owner is required")
	}
	if newOwnerID == oldOwnerID {
		return dbq.Agent{}, service.Detail(service.ErrInvalidInput, "agent is already owned by that user")
	}
	if _, err := q.GetUserByID(ctx, pgtype.UUID{Bytes: newOwnerID, Valid: true}); err != nil {
		return dbq.Agent{}, service.Detail(service.ErrInvalidInput, "target user not found")
	}

	// Enumerate bridges before the unbind so we can stop their pollers after.
	bridgeIDs, _ := q.ListBridgesByAgentID(ctx, pgtype.UUID{Bytes: agentID, Valid: true})

	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return dbq.Agent{}, err
	}
	defer tx.Rollback(ctx)
	qtx := q.WithTx(tx)
	agent, err = qtx.GetAgentByIDForUpdate(ctx, agent.ID)
	if err != nil {
		return dbq.Agent{}, service.ErrNotFound
	}
	oldOwnerID = uuid.UUID(agent.OwnerPrincipalID.Bytes)
	if err := authz.AuthorizeOwnedResource(ctx, qtx, p, oldOwnerID, authz.TenantAgentTransferAny); err != nil {
		return dbq.Agent{}, err
	}
	if _, err := qtx.LockResourceNeedsByAgent(ctx, agent.ID); err != nil {
		return dbq.Agent{}, err
	}
	newOwnerPG := pgtype.UUID{Bytes: newOwnerID, Valid: true}
	if err := qtx.UpdateAgentOwner(ctx, dbq.UpdateAgentOwnerParams{ID: agent.ID, OwnerPrincipalID: newOwnerPG}); err != nil {
		return dbq.Agent{}, err
	}
	if err := qtx.UpsertAgentGrant(ctx, dbq.UpsertAgentGrantParams{AgentID: agent.ID, GranteeID: newOwnerPG, Role: "admin"}); err != nil {
		return dbq.Agent{}, err
	}
	if err := qtx.DeleteAgentGrant(ctx, dbq.DeleteAgentGrantParams{AgentID: agent.ID, GranteeID: pgtype.UUID{Bytes: oldOwnerID, Valid: true}}); err != nil {
		return dbq.Agent{}, err
	}
	if err := qtx.UnbindAllResourceNeedsByAgent(ctx, agent.ID); err != nil {
		return dbq.Agent{}, err
	}
	if err := qtx.DisconnectAgentGit(ctx, agent.ID); err != nil {
		return dbq.Agent{}, err
	}
	if err := qtx.UnbindBridgesByAgent(ctx, agent.ID); err != nil {
		return dbq.Agent{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return dbq.Agent{}, err
	}

	// Stop the now-detached bridge pollers (row unbind alone leaves them
	// polling with the old owner's token). Best-effort.
	for _, bid := range bridgeIDs {
		if bu, err := uuid.FromBytes(bid.Bytes[:]); err == nil {
			s.bridgeMgr.TeardownBridge(bu)
			s.bridgeMgr.RemoveBridge(bu)
		}
	}

	updated, err := q.GetAgentByID(ctx, agent.ID)
	if err != nil {
		return dbq.Agent{}, err
	}
	return updated, nil
}

// Stop kills the container and flips status to stopped (no auto-resume).
func (s *Service) Stop(ctx context.Context, p authz.Principal, agentID uuid.UUID) error {
	q := dbq.New(s.db.Pool())
	if _, err := q.GetAgentByID(ctx, pgtype.UUID{Bytes: agentID, Valid: true}); err != nil {
		return service.ErrNotFound
	}
	if err := authorizeGovernance(ctx, q, p, authz.AgentLifecycle, authz.TenantAgentLifecycleAny, agentID); err != nil {
		return err
	}
	if _, err := q.StopAgentAndRotateToken(ctx, dbq.StopAgentAndRotateTokenParams{
		ID: pgtype.UUID{Bytes: agentID, Valid: true},
	}); err != nil {
		s.logger.Error("stop and revoke agent", zap.Error(err))
		return err
	}
	if err := s.containers.StopAgent(ctx, agentID); err != nil {
		s.logger.Error("stop agent", zap.Error(err))
		return err
	}
	return nil
}

// Start resumes a stopped agent and ensures its container is up.
// Requires an existing image.
func (s *Service) Start(ctx context.Context, p authz.Principal, agentID uuid.UUID) error {
	q := dbq.New(s.db.Pool())
	agent, err := q.GetAgentByID(ctx, pgtype.UUID{Bytes: agentID, Valid: true})
	if err != nil {
		return service.ErrNotFound
	}
	if err := authorizeGovernance(ctx, q, p, authz.AgentLifecycle, authz.TenantAgentLifecycleAny, agentID); err != nil {
		return err
	}
	if agent.ImageRef == "" {
		return service.Detail(service.ErrInvalidInput, "agent has no image — build it first")
	}
	if agent.Status == "stopped" {
		if err := q.UpdateAgentStatus(ctx, dbq.UpdateAgentStatusParams{
			ID:     pgtype.UUID{Bytes: agentID, Valid: true},
			Status: "active",
		}); err != nil {
			s.logger.Error("flip status to active", zap.Error(err))
			return err
		}
	}
	if _, err := s.dispatcher.EnsureRunning(ctx, agentID); err != nil {
		s.logger.Error("start agent", zap.Error(err))
		return err
	}
	return nil
}

// Suspend kills the container but leaves status=active for auto-resume.
func (s *Service) Suspend(ctx context.Context, p authz.Principal, agentID uuid.UUID) error {
	q := dbq.New(s.db.Pool())
	if _, err := q.GetAgentByID(ctx, pgtype.UUID{Bytes: agentID, Valid: true}); err != nil {
		return service.ErrNotFound
	}
	if err := authorizeGovernance(ctx, q, p, authz.AgentLifecycle, authz.TenantAgentLifecycleAny, agentID); err != nil {
		return err
	}
	if _, err := q.IncrementAgentTokenVersion(ctx, pgtype.UUID{Bytes: agentID, Valid: true}); err != nil {
		s.logger.Error("revoke agent token before suspend", zap.Error(err))
		return err
	}
	if err := s.containers.StopAgent(ctx, agentID); err != nil {
		s.logger.Error("suspend agent", zap.Error(err))
		return err
	}
	return nil
}

// CancelBuild cancels the agent's in-progress build. Requires agent-admin.
func (s *Service) CancelBuild(ctx context.Context, p authz.Principal, agentID uuid.UUID) error {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.AgentBuildManage, agentID); err != nil {
		return err
	}
	if !s.builder.CancelBuild(agentID.String()) {
		return service.Detail(service.ErrConflict, "no build in progress")
	}
	return nil
}

// UpgradeRequest is the input to Upgrade. RunID is optional; if set we
// load full error context from that run so the upgrade goes via the
// auto-fix path.
type UpgradeRequest struct {
	RunID       string
	Description string
	// SystemConversationID is set when the upgrade was triggered from a
	// system-agent conversation (sysagent tool). The builder routes the
	// post-build notification to that conversation instead of an agent
	// conversation. Mutually exclusive with the ConversationID path
	// agents take via /api/agent/upgrade.
	SystemConversationID string
}

// Upgrade kicks off the upgrade pipeline. Admin-gated. Async — returns
// once the upgrade goroutine is queued; the runtime tracks state via
// agent_builds + WebSocket events.
func (s *Service) Upgrade(ctx context.Context, p authz.Principal, agentID uuid.UUID, req UpgradeRequest) error {
	q := dbq.New(s.db.Pool())
	agent, err := q.GetAgentByID(ctx, pgtype.UUID{Bytes: agentID, Valid: true})
	if err != nil {
		return service.ErrNotFound
	}
	if err := authz.Authorize(ctx, q, p, authz.AgentBuildManage, agentID); err != nil {
		return err
	}
	if agent.ImageRef == "" {
		// The agent never built a working image (initial build failed), so
		// there's nothing to upgrade against — route to a fresh build. Carry
		// the user's instruction through as the codegen instruction;
		// otherwise the build re-scaffolds with no instruction, skips codegen
		// entirely, and just rebuilds the (stale/empty) tree.
		go func() {
			_ = s.builder.Build(context.Background(), builder.BuildInput{
				AgentID:          agentID.String(),
				Name:             agent.Name,
				Slug:             agent.Slug,
				OwnerPrincipalID: uuid.UUID(agent.OwnerPrincipalID.Bytes).String(),
				InitiatorUserID:  pgUserID(p),
				BuildProviderID:  agent.BuildProviderID,
				BuildModel:       agent.BuildModel,
				Instructions:     req.Description,
			})
		}()
		return nil
	}
	go func() {
		runID := req.RunID
		if runID == "" {
			runID = uuid.New().String()
		}
		input := builder.UpgradeInput{
			AgentID:              agentID.String(),
			InitiatorUserID:      pgUserID(p),
			RunID:                runID,
			Reason:               "manual",
			Description:          req.Description,
			SystemConversationID: req.SystemConversationID,
		}
		if req.RunID != "" {
			if runUUID, perr := uuid.Parse(req.RunID); perr != nil {
				s.logger.Warn("upgrade: invalid run_id; proceeding as manual upgrade without diagnostics",
					zap.String("agent", agentID.String()), zap.String("run_id", req.RunID), zap.Error(perr))
			} else {
				pgRunID := pgtype.UUID{Bytes: runUUID, Valid: true}
				failedRun, gerr := q.GetRunByID(context.Background(), pgRunID)
				if gerr != nil {
					s.logger.Warn("upgrade: run not found; proceeding as manual upgrade without diagnostics",
						zap.String("agent", agentID.String()), zap.String("run_id", req.RunID), zap.Error(gerr))
				} else {
					input.Reason = "auto_fix"
					input.ErrorMessage = failedRun.ErrorMessage
					input.PanicTrace = failedRun.PanicTrace
					input.InputPayload = string(failedRun.InputPayload)
					input.Actions = string(failedRun.Actions)
					input.Logs = failedRun.StdoutLog
					if msgs, err := q.ListMessagesByRun(context.Background(), pgRunID); err == nil {
						var msgSummaries []string
						for _, m := range msgs {
							msgSummaries = append(msgSummaries, fmt.Sprintf("[%s] %s", m.Role, m.Content))
						}
						input.Messages = strings.Join(msgSummaries, "\n")
					}
				}
			}
		}
		if err := s.builder.AcquireUpgradeLock(context.Background(), agentID.String()); err != nil {
			if !errors.Is(err, builder.ErrUpgradeInProgress) {
				s.logger.Error("upgrade lock failed", zap.String("agent", agentID.String()), zap.Error(err))
			}
			return
		}
		s.builder.RunUpgrade(context.Background(), input)
	}()
	return nil
}

// RollbackRequest is the input to Rollback.
type RollbackRequest struct {
	BuildID        string
	ConversationID string
	// SystemConversationID is set when the rollback was triggered from a
	// system-agent conversation. Mutually exclusive with ConversationID; the
	// builder routes the post-build notification to whichever is set.
	SystemConversationID string
}

// Rollback reverses the agent to a previous completed build's source_ref.
// Same admin gate and async 202 shape as Upgrade.
func (s *Service) Rollback(ctx context.Context, p authz.Principal, agentID uuid.UUID, req RollbackRequest) error {
	if req.BuildID == "" {
		return service.Detail(service.ErrInvalidInput, "build_id is required")
	}
	buildID, err := uuid.Parse(req.BuildID)
	if err != nil {
		return service.Detail(service.ErrInvalidInput, "invalid build_id")
	}
	q := dbq.New(s.db.Pool())
	agent, err := q.GetAgentByID(ctx, pgtype.UUID{Bytes: agentID, Valid: true})
	if err != nil {
		return service.ErrNotFound
	}
	if err := authz.Authorize(ctx, q, p, authz.AgentBuildManage, agentID); err != nil {
		return err
	}
	if agent.ImageRef == "" {
		return service.Detail(service.ErrConflict, "agent has no current build to roll back from")
	}
	target, err := q.GetAgentBuild(ctx, pgtype.UUID{Bytes: buildID, Valid: true})
	if err != nil {
		return service.Detail(service.ErrNotFound, "target build not found")
	}
	if uuid.UUID(target.AgentID.Bytes) != agentID {
		return service.Detail(service.ErrInvalidInput, "target build does not belong to this agent")
	}
	if target.Status != "complete" {
		return service.Detail(service.ErrConflict, "can only roll back to a completed build")
	}
	if target.SourceRef == "" {
		return service.Detail(service.ErrConflict, "target build has no source_ref")
	}
	if target.SourceRef == agent.SourceRef {
		return service.Detail(service.ErrConflict, "target build is the current build")
	}
	go func() {
		if err := s.builder.AcquireUpgradeLock(context.Background(), agentID.String()); err != nil {
			if !errors.Is(err, builder.ErrUpgradeInProgress) {
				s.logger.Error("rollback lock failed", zap.String("agent", agentID.String()), zap.Error(err))
			}
			return
		}
		s.builder.Rollback(context.Background(), builder.RollbackInput{
			AgentID:              agentID.String(),
			InitiatorUserID:      pgUserID(p),
			BuildID:              buildID.String(),
			ConversationID:       req.ConversationID,
			SystemConversationID: req.SystemConversationID,
		})
	}()
	return nil
}

// ListWebhooks returns webhook rows with last-received status. Requires
// agent-admin (webhook config is owner-only).
func (s *Service) ListWebhooks(ctx context.Context, p authz.Principal, agentID uuid.UUID) ([]dbq.ListWebhooksByAgentWithStatusRow, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.AgentWebhooksView, agentID); err != nil {
		return nil, err
	}
	rows, err := q.ListWebhooksByAgentWithStatus(ctx, pgtype.UUID{Bytes: agentID, Valid: true})
	if err != nil {
		s.logger.Error("list webhooks", zap.Error(err))
		return nil, err
	}
	if err := s.decryptWebhookRows(ctx, rows); err != nil {
		return nil, err
	}
	return rows, nil
}

func (s *Service) decryptWebhookRows(ctx context.Context, rows []dbq.ListWebhooksByAgentWithStatusRow) error {
	for i := range rows {
		if rows[i].Secret == "" {
			continue
		}
		webhookID := uuid.UUID(rows[i].ID.Bytes)
		plain, err := s.secrets.Get(ctx, "webhook/"+webhookID.String()+"/secret", rows[i].Secret)
		if err != nil {
			s.logger.Error("decrypt webhook secret for list", zap.String("webhook", webhookID.String()), zap.Error(err))
			return err
		}
		rows[i].Secret = plain
	}
	return nil
}

// ListSchedules returns the agent's schedule handlers (crons + schedules) with
// each one's next pending fire time. Requires agent-admin (config is owner-only).
func (s *Service) ListSchedules(ctx context.Context, p authz.Principal, agentID uuid.UUID) ([]dbq.ListSchedulesWithNextFireRow, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.AgentSchedulesView, agentID); err != nil {
		return nil, err
	}
	rows, err := q.ListSchedulesWithNextFire(ctx, pgtype.UUID{Bytes: agentID, Valid: true})
	if err != nil {
		s.logger.Error("list schedules", zap.Error(err))
		return nil, err
	}
	return rows, nil
}

// ListTools returns the agent's registered tool catalog. Requires agent
// membership (AccessUser).
func (s *Service) ListTools(ctx context.Context, p authz.Principal, agentID uuid.UUID) ([]dbq.AgentTool, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.AgentToolsView, agentID); err != nil {
		return nil, err
	}
	rows, err := q.ListAgentTools(ctx, pgtype.UUID{Bytes: agentID, Valid: true})
	if err != nil {
		s.logger.Error("list tools", zap.Error(err))
		return nil, err
	}
	return rows, nil
}

// FireSchedule manually fires a registered handler (cron or schedule) once and
// returns the run ID after draining the response body. No fire id is passed —
// a manual fire carries no per-instance data. Requires agent-admin.
func (s *Service) FireSchedule(ctx context.Context, p authz.Principal, agentID uuid.UUID, slug string) (FireScheduleResult, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.AgentScheduleFire, agentID); err != nil {
		return FireScheduleResult{}, err
	}
	handler, err := q.GetScheduleHandler(ctx, dbq.GetScheduleHandlerParams{
		AgentID: pgtype.UUID{Bytes: agentID, Valid: true},
		Slug:    slug,
	})
	if err != nil {
		return FireScheduleResult{}, service.ErrNotFound
	}
	timeout := time.Duration(handler.TimeoutMs) * time.Millisecond
	if timeout == 0 {
		timeout = 2 * time.Minute
	}
	rc, runID, err := s.dispatcher.ForwardFire(ctx, agentID, "", slug, timeout)
	if err != nil {
		return FireScheduleResult{}, err
	}
	io.Copy(io.Discard, rc)
	rc.Close()
	return FireScheduleResult{RunID: runID}, nil
}

// ListBuilds returns the agent's build history (latest 50). Requires
// agent membership (AccessUser).
func (s *Service) ListBuilds(ctx context.Context, p authz.Principal, agentID uuid.UUID) ([]dbq.ListAgentBuildsByAgentRow, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.AgentBuildsView, agentID); err != nil {
		return nil, err
	}
	rows, err := q.ListAgentBuildsByAgent(ctx, pgtype.UUID{Bytes: agentID, Valid: true})
	if err != nil {
		s.logger.Error("list builds", zap.Error(err))
		return nil, err
	}
	return rows, nil
}

// GetBuild fetches one agent_build row plus the rollback-target row
// (for source_ref denormalization) if the build is a rollback. The
// second value is nil when the build isn't a rollback or the target row
// can't be loaded.
type BuildWithTarget struct {
	Build  dbq.AgentBuild
	Target *dbq.AgentBuild
}

func (s *Service) GetBuild(ctx context.Context, p authz.Principal, buildID uuid.UUID) (BuildWithTarget, error) {
	q := dbq.New(s.db.Pool())
	b, err := q.GetAgentBuild(ctx, pgtype.UUID{Bytes: buildID, Valid: true})
	if err != nil {
		return BuildWithTarget{}, service.ErrNotFound
	}
	if err := authz.Authorize(ctx, q, p, authz.AgentBuildsView, uuid.UUID(b.AgentID.Bytes)); err != nil {
		return BuildWithTarget{}, err
	}
	out := BuildWithTarget{Build: b}
	if b.RollbackTargetID.Valid {
		if target, err := q.GetAgentBuild(ctx, b.RollbackTargetID); err == nil {
			out.Target = &target
		}
	}
	return out, nil
}

// --- git binding (per-agent external git remote) ---

// ConnectGit binds an external HTTPS git remote to the agent. Stores
// the URL, credential FK, default branch, and a freshly-generated
// HMAC secret for the webhook ingress.
func (s *Service) ConnectGit(ctx context.Context, p authz.Principal, agentID uuid.UUID, req ConnectGitRequest) (GitConfig, error) {
	// Normalize a pasted SSH clone URL to HTTPS and reject anything a PAT
	// can't authenticate — PATs only work over HTTPS (see normalizeGitRemoteURL).
	remote, nerr := normalizeGitRemoteURL(req.RemoteURL)
	if nerr != nil {
		return GitConfig{}, service.Detail(service.ErrInvalidInput, "%s", nerr.Error())
	}
	mode := strings.TrimSpace(req.Mode)
	if mode != GitModeReadWrite && mode != GitModeReadOnly {
		return GitConfig{}, service.Detail(service.ErrInvalidInput, "git_mode must be read_write or read_only")
	}
	credIDStr := strings.TrimSpace(req.CredentialID)
	if credIDStr == "" {
		return GitConfig{}, service.Detail(service.ErrInvalidInput, "git_credential_id is required")
	}
	credID, err := uuid.Parse(credIDStr)
	if err != nil {
		return GitConfig{}, service.Detail(service.ErrInvalidInput, "invalid git_credential_id")
	}
	branch := strings.TrimSpace(req.DefaultBranch)
	if branch == "" {
		branch = "main"
	}
	q := dbq.New(s.db.Pool())
	agent, err := q.GetAgentByID(ctx, pgtype.UUID{Bytes: agentID, Valid: true})
	if err != nil {
		return GitConfig{}, service.ErrNotFound
	}
	if err := authz.Authorize(ctx, q, p, authz.AgentGit, agentID); err != nil {
		return GitConfig{}, err
	}
	cred, err := q.GetGitCredential(ctx, pgtype.UUID{Bytes: credID, Valid: true})
	if err != nil {
		return GitConfig{}, service.Detail(service.ErrNotFound, "credential not found")
	}
	// A git credential is a shareable resource: the caller may bind it if they
	// own it OR hold a bind grant on it (so a credential shared to a group is
	// bindable by its members), not only when they are the owner.
	gitGrants, err := q.ListGitCredentialGrants(ctx, cred.ID)
	if err != nil {
		s.logger.Error("list git credential grants", zap.Error(err))
		return GitConfig{}, err
	}
	grants := make([]authz.Grant, len(gitGrants))
	for i, g := range gitGrants {
		grants[i] = authz.Grant{GranteeID: uuid.UUID(g.GranteeID.Bytes), Capabilities: g.Capabilities}
	}
	if !p.HasResourceCapability(uuid.UUID(cred.UserID.Bytes), grants, authz.CapBind) {
		return GitConfig{}, service.Detail(service.ErrForbidden, "you do not have bind access to this credential")
	}
	// Validate the remote is reachable with the chosen credential before
	// recording it — otherwise a wrong URL or bad/expired token is accepted
	// silently and only surfaces as a confusing push failure on the next build.
	state, err := s.builder.InspectRemote(ctx, remote, branch, pgtype.UUID{Bytes: credID, Valid: true})
	if err != nil {
		s.logger.Warn("git connect: inspect remote", zap.String("agent", agentID.String()), zap.Error(err))
		return GitConfig{}, service.Detail(service.ErrInvalidInput,
			"could not access %s with the selected credential — verify the URL and that the token has repo access", remote)
	}
	if mode == GitModeReadOnly && state.Empty {
		return GitConfig{}, service.Detail(service.ErrInvalidInput, "read_only Git requires a populated repository")
	}
	// Decide what a populated remote means for this agent:
	//   - never-built agent        → import (adopt the remote's code)
	//   - built agent, shared hist. → reconnect (same repo; normal push/pull
	//                                 reconciles — no import, no force)
	//   - built agent, unrelated    → reject (a different repo; on a push
	//                                 conflict the agent would adopt its code)
	// An empty remote always mirrors: the first push just creates the branch.
	// A populated remote is handled on whichever branch holds the code — the
	// requested one when present, else the remote's default.
	effHeadSHA := state.HeadSHA
	importing := false
	if !state.Empty {
		if b := state.ImportBranch(branch); b != "" {
			branch = b
		}
		if !state.HasBranch {
			effHeadSHA = state.DefaultHeadSHA
		}
		if agent.ImageRef == "" || mode == GitModeReadOnly {
			importing = true
		} else {
			shared, herr := s.builder.RemoteSharesHistory(ctx, agentID.String(), remote, branch, pgtype.UUID{Bytes: credID, Valid: true})
			if herr != nil {
				s.logger.Warn("git connect: history check", zap.String("agent", agentID.String()), zap.Error(herr))
				return GitConfig{}, service.Detail(service.ErrInvalidInput, "could not compare %s with the agent's code — try again", remote)
			}
			if !shared {
				return GitConfig{}, service.Detail(service.ErrInvalidInput,
					"%s has commits unrelated to this agent's code — it looks like a different repository. Connect an empty repository or the agent's own repo.", remote)
			}
		}
	}
	if mode == GitModeReadWrite {
		if err := s.builder.ValidateRemoteWrite(ctx, remote, branch, pgtype.UUID{Bytes: credID, Valid: true}, state.Empty); err != nil {
			return GitConfig{}, service.Detail(service.ErrInvalidInput, "read_write Git requires a credential that can push %s: %s", branch, err.Error())
		}
	}
	secret, err := randomHex(32)
	if err != nil {
		s.logger.Error("generate webhook secret", zap.Error(err))
		return GitConfig{}, err
	}
	storedSecret, err := s.secrets.Put(ctx, gitWebhookSecretRef(agentID), secret)
	if err != nil {
		s.logger.Error("encrypt webhook secret", zap.Error(err))
		return GitConfig{}, err
	}
	if err := q.ConnectAgentGit(ctx, dbq.ConnectAgentGitParams{
		ID:               pgtype.UUID{Bytes: agentID, Valid: true},
		GitRemoteUrl:     remote,
		GitCredentialID:  pgtype.UUID{Bytes: credID, Valid: true},
		GitDefaultBranch: branch,
		GitWebhookSecret: storedSecret,
		GitMode:          mode,
	}); err != nil {
		s.logger.Error("connect agent git", zap.Error(err))
		return GitConfig{}, err
	}

	// Import: adopt the populated remote's code into this fresh agent, then
	// build the imported HEAD (SkipScaffold — the repo is complete, exactly as
	// for a clone). An empty remote skips this and just mirrors on next build.
	if importing {
		if err := s.builder.CloneRemoteIntoAgent(ctx, agentID.String(), remote, branch, pgtype.UUID{Bytes: credID, Valid: true}); err != nil {
			_ = q.DisconnectAgentGit(ctx, pgtype.UUID{Bytes: agentID, Valid: true})
			s.logger.Error("git import: clone", zap.String("agent", agentID.String()), zap.Error(err))
			return GitConfig{}, service.Detail(service.ErrInvalidInput, "failed to import repository: %s", err.Error())
		}
		if effHeadSHA != "" {
			// Stamp the imported tip so the git poller doesn't see instant drift.
			_ = q.UpdateAgentGitLastSyncedRef(ctx, dbq.UpdateAgentGitLastSyncedRefParams{
				ID:               pgtype.UUID{Bytes: agentID, Valid: true},
				GitLastSyncedRef: effHeadSHA,
			})
		}
		go func() {
			if err := s.builder.Build(context.Background(), builder.BuildInput{
				AgentID:          agentID.String(),
				Name:             agent.Name,
				Slug:             agent.Slug,
				OwnerPrincipalID: uuid.UUID(agent.OwnerPrincipalID.Bytes).String(),
				BuildProviderID:  agent.BuildProviderID,
				BuildModel:       agent.BuildModel,
				Instructions:     "",   // build the imported HEAD; no codegen
				SkipScaffold:     true, // repo is imported complete — don't clobber it
			}); err != nil {
				s.logger.Error("git import: build", zap.String("agent", agentID.String()), zap.Error(err))
			}
		}()
	}

	return GitConfig{
		RemoteURL:      remote,
		CredentialID:   credID.String(),
		CredentialName: cred.Name,
		DefaultBranch:  branch,
		WebhookSecret:  secret,
		LastSyncedRef:  effHeadSHA,
		Mode:           mode,
	}, nil
}

// DisconnectGit resets the agent to internal-only mode. Local repo + image untouched.
func (s *Service) DisconnectGit(ctx context.Context, p authz.Principal, agentID uuid.UUID) error {
	q := dbq.New(s.db.Pool())
	if _, err := q.GetAgentByID(ctx, pgtype.UUID{Bytes: agentID, Valid: true}); err != nil {
		return service.ErrNotFound
	}
	if err := authz.Authorize(ctx, q, p, authz.AgentGit, agentID); err != nil {
		return err
	}
	if err := q.DisconnectAgentGit(ctx, pgtype.UUID{Bytes: agentID, Valid: true}); err != nil {
		s.logger.Error("disconnect agent git", zap.Error(err))
		return err
	}
	return nil
}

// GetGitConfig returns the current git binding (zero-valued fields when
// not connected). Agent member gate.
func (s *Service) GetGitConfig(ctx context.Context, p authz.Principal, agentID uuid.UUID) (GitConfig, error) {
	q := dbq.New(s.db.Pool())
	if _, err := q.GetAgentByID(ctx, pgtype.UUID{Bytes: agentID, Valid: true}); err != nil {
		return GitConfig{}, service.ErrNotFound
	}
	if err := authz.Authorize(ctx, q, p, authz.AgentGit, agentID); err != nil {
		return GitConfig{}, err
	}
	cfg, err := q.GetAgentGitConfig(ctx, pgtype.UUID{Bytes: agentID, Valid: true})
	if err != nil {
		s.logger.Error("get agent git config", zap.Error(err))
		return GitConfig{}, err
	}
	out := GitConfig{
		RemoteURL:     cfg.GitRemoteUrl,
		DefaultBranch: cfg.GitDefaultBranch,
		LastSyncedRef: cfg.GitLastSyncedRef,
		Mode:          cfg.GitMode,
	}
	if cfg.GitWebhookSecret != "" {
		out.WebhookSecret, err = s.secrets.Get(ctx, gitWebhookSecretRef(agentID), cfg.GitWebhookSecret)
		if err != nil {
			s.logger.Error("decrypt git webhook secret", zap.Error(err))
			return GitConfig{}, err
		}
	}
	if cfg.GitCredentialID.Valid {
		out.CredentialID = uuid.UUID(cfg.GitCredentialID.Bytes).String()
		out.CredentialName = cfg.CredentialName.String
	}
	return out, nil
}

func gitWebhookSecretRef(agentID uuid.UUID) string {
	return "agent/" + agentID.String() + "/git_webhook_secret"
}

// pgUserID converts a principal's user id to a pgtype.UUID, marking it
// invalid for a non-registered principal (uuid.Nil). Used to attribute
// build/upgrade/rollback codegen spend to the initiating user; an invalid
// value lets the builder fall back to the agent owner.
func pgUserID(p authz.Principal) pgtype.UUID {
	return pgtype.UUID{Bytes: p.UserID, Valid: p.UserID != uuid.Nil}
}
