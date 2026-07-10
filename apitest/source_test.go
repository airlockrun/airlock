package apitest_test

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/airlockrun/agentsdk/sourcebundle"
	"github.com/airlockrun/airlock/apitest"
	"github.com/airlockrun/airlock/builder"
)

func TestAgentSourceStateDownloadAndPrecondition(t *testing.T) {
	h := apitest.Setup(t)
	owner := apitest.CreateUser(t, h, "source-owner", "user")
	token := apitest.IssueUserToken(t, h, owner, "source-owner@apitest.local", "user")
	agentID := apitest.CreateAgent(t, h, apitest.AgentOpts{OwnerID: owner, Slug: "source-agent"})
	repo := h.BuildService.AgentRepoPath(agentID.String())
	if err := builder.InitAgentRepo(h.BuildService.ReposPath(), agentID.String()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "go.mod"), []byte("module source-agent\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := builder.CommitWorktree(repo, "seed source"); err != nil {
		t.Fatal(err)
	}
	state, err := sourcebundle.Digest(repo)
	if err != nil {
		t.Fatal(err)
	}

	path := "/api/v1/agents/" + agentID.String() + "/source"
	head := h.Do(h.NewRequest(http.MethodHead, path, token, nil))
	if head.StatusCode != http.StatusOK {
		t.Fatalf("HEAD status = %d", head.StatusCode)
	}
	if got, _ := strconv.Unquote(head.Header.Get("ETag")); got != state {
		t.Fatalf("HEAD ETag = %q, want %q", got, state)
	}
	head.Body.Close()

	get := h.Do(h.NewRequest(http.MethodGet, path, token, nil))
	if get.StatusCode != http.StatusOK {
		t.Fatalf("GET status = %d", get.StatusCode)
	}
	dst := t.TempDir()
	if err := sourcebundle.ExtractArchive(get.Body, dst); err != nil {
		t.Fatal(err)
	}
	get.Body.Close()
	if got, err := sourcebundle.Digest(dst); err != nil || got != state {
		t.Fatalf("download state = %q, %v; want %q", got, err, state)
	}

	var archive bytes.Buffer
	if _, err := sourcebundle.WriteArchive(&archive, dst); err != nil {
		t.Fatal(err)
	}
	put := h.NewRequest(http.MethodPut, path, token, archive.Bytes())
	put.Header.Set("Content-Type", "application/gzip")
	put.Header.Set("If-Match", `"sha256:stale"`)
	resp := h.Do(put)
	if resp.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("stale PUT status = %d, body=%s", resp.StatusCode, h.ReadBody(resp))
	}
	resp.Body.Close()

	if _, err := h.DB.Pool().Exec(t.Context(), `UPDATE agents SET git_mode='read_only', git_remote_url='https://example.com/agent.git' WHERE id=$1`, agentID); err != nil {
		t.Fatal(err)
	}
	put = h.NewRequest(http.MethodPut, path, token, archive.Bytes())
	put.Header.Set("Content-Type", "application/gzip")
	put.Header.Set("If-Match", strconv.Quote(state))
	resp = h.Do(put)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("read-only PUT status = %d, body=%s", resp.StatusCode, h.ReadBody(resp))
	}
	if body := string(h.ReadBody(resp)); !strings.Contains(body, "read-only Git") {
		t.Fatalf("read-only PUT body = %s", body)
	}
}
