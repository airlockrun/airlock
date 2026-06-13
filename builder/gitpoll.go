package builder

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/airlockrun/airlock/db/dbq"
	"go.uber.org/zap"
)

// GitPollInterval is the cadence at which connected agents are checked
// for new commits on their default branch. Mirrors the OAuth refresh
// cadence; users behind firewalls or on providers without webhook
// support (Bitbucket/Gitea in v1) rely on this loop entirely.
const GitPollInterval = 5 * time.Minute

// RunGitPoll starts the periodic ls-remote loop. Blocks until ctx is
// cancelled. Runs an immediate poll on startup so connected agents whose
// remotes advanced while airlock was down are caught without waiting
// for the first tick.
func (b *BuildService) RunGitPoll(ctx context.Context) {
	b.pollGitOnce(ctx)
	ticker := time.NewTicker(GitPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			b.pollGitOnce(ctx)
		}
	}
}

func (b *BuildService) pollGitOnce(ctx context.Context) {
	q := dbq.New(b.db.Pool())
	rows, err := q.ListAgentsForGitPolling(ctx)
	if err != nil {
		b.logger.Error("list agents for git polling", zap.Error(err))
		return
	}
	for _, row := range rows {
		b.pollOneAgent(ctx, row)
	}
}

func (b *BuildService) pollOneAgent(ctx context.Context, row dbq.ListAgentsForGitPollingRow) {
	agentID := uuidString(row.ID)
	fields := []zap.Field{zap.String("agent", agentID)}

	q := dbq.New(b.db.Pool())
	auth, err := resolveGitAuth(ctx, q, b.encryptor, row.GitCredentialID)
	if err != nil {
		b.logger.Warn("git poll: resolve auth", append(fields, zap.Error(err))...)
		return
	}
	header, err := auth.ExtraHeader(ctx)
	if err != nil {
		b.logger.Warn("git poll: extra header", append(fields, zap.Error(err))...)
		return
	}

	branch := row.GitDefaultBranch
	if branch == "" {
		branch = "main"
	}

	// `git ls-remote --heads <url> <branch>` prints "<sha>\trefs/heads/<branch>".
	repoPath := b.AgentRepoPath(agentID)
	out, err := gitAuthedOutput(ctx, repoPath, header, "ls-remote", "--heads", row.GitRemoteUrl, branch)
	if err != nil {
		b.logger.Warn("git poll: ls-remote", append(fields, zap.Error(err))...)
		return
	}
	remoteSHA := parseLsRemoteFirstSHA(out)
	if remoteSHA == "" {
		// Branch doesn't exist on the remote — log once and move on.
		b.logger.Debug("git poll: remote branch missing", append(fields, zap.String("branch", branch))...)
		return
	}
	if remoteSHA == row.GitLastSyncedRef {
		return // already in sync
	}

	// Drift detected — load full agent and enqueue an upgrade.
	agent, err := q.GetAgentByID(ctx, row.ID)
	if err != nil {
		b.logger.Error("git poll: load agent", append(fields, zap.Error(err))...)
		return
	}
	hash, err := b.PullAgentRepo(ctx, agent)
	if err != nil {
		b.logger.Warn("git poll: pull failed", append(fields, zap.Error(err))...)
		return
	}
	if err := b.AcquireUpgradeLock(ctx, agentID); err != nil {
		if !errors.Is(err, ErrUpgradeInProgress) {
			b.logger.Error("git poll: upgrade lock", append(fields, zap.Error(err))...)
		}
		return
	}
	go b.RunUpgrade(context.Background(), UpgradeInput{
		AgentID: agentID,
		Reason:  "git_poll",
	})
	b.logger.Info("git poll: enqueued upgrade",
		append(fields, zap.String("from", row.GitLastSyncedRef), zap.String("to", hash))...)
}

// gitAuthedOutput is gitAuthed but returns stdout (for ls-remote).
func gitAuthedOutput(_ context.Context, dir, header string, args ...string) (string, error) {
	full := append([]string{"-c", "http.extraheader=" + header}, args...)
	return gitOutput(dir, full...)
}

// parseLsRemoteFirstSHA extracts the SHA from the first line of
// `git ls-remote` output. Returns empty string when there are no lines
// (the branch doesn't exist on the remote).
func parseLsRemoteFirstSHA(out string) string {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Format: "<sha>\trefs/heads/<branch>"
		if tab := strings.IndexByte(line, '\t'); tab > 0 {
			return line[:tab]
		}
	}
	return ""
}
