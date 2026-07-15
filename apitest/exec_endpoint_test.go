package apitest_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/apitest"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// TestExecEndpoint_DeclarationUpsertPreservesOperatorConfig drives the
// agent-side sync path: declaring an exec endpoint in the sync batch
// writes the declaration fields but never touches the operator-configured
// host / user / keypair / host-key columns.
//
// This is the load-bearing invariant: a container restart with a
// modified description must NOT wipe the operator's config and force
// them to re-paste authorized_keys.
func TestExecEndpoint_DeclarationUpsertPreservesOperatorConfig(t *testing.T) {
	h := apitest.Setup(t)
	owner := apitest.CreateUser(t, h, "owner", "user")
	agentID := apitest.CreateAgent(t, h, apitest.AgentOpts{OwnerID: owner})
	agentToken := apitest.IssueAgentToken(t, h, agentID)
	ownerToken := apitest.IssueUserToken(t, h, owner, "owner@apitest.local", "user")

	// First declaration from the agent.
	declareExecEndpoint(t, h, agentToken, "ci", wire.ExecEndpointDef{
		Description: "Self-hosted CI runner",
		LLMHint:     "use kick-build",
		Access:      wire.AccessAdmin,
	})

	// Operator configures host / port / user via the admin API. This is
	// the row state we need to survive subsequent re-syncs.
	configureBody := map[string]any{"host": "vps.example.com", "port": 2222, "sshUser": "deploy"}
	resp := h.Do(h.NewRequest(http.MethodPut,
		"/api/v1/agents/"+agentID.String()+"/exec-endpoints/ci",
		ownerToken, asJSON(t, configureBody)))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("configure: status %d, body %s", resp.StatusCode, h.ReadBody(resp))
	}
	resp.Body.Close()

	// Re-declare with a different description and llmHint. This
	// simulates a container restart after the agent author edited
	// main.go.
	declareExecEndpoint(t, h, agentToken, "ci", wire.ExecEndpointDef{
		Description: "Self-hosted CI runner (renamed)",
		LLMHint:     "use kick-build --branch <name>",
		Access:      wire.AccessAdmin,
	})

	q := dbq.New(h.DB.Pool())
	row, err := q.ResolveBoundExecEndpoint(context.Background(), dbq.ResolveBoundExecEndpointParams{
		AgentID: pgUUID(agentID),
		Slug:    "ci",
	})
	if err != nil {
		t.Fatalf("get row: %v", err)
	}

	// Declaration fields updated.
	if row.Description != "Self-hosted CI runner (renamed)" {
		t.Errorf("description = %q, want updated", row.Description)
	}
	if row.LlmHint != "use kick-build --branch <name>" {
		t.Errorf("llm_hint = %q, want updated", row.LlmHint)
	}
	// Operator config preserved.
	if row.Host.String != "vps.example.com" {
		t.Errorf("host = %q, want preserved 'vps.example.com'", row.Host.String)
	}
	if row.Port.Int32 != 2222 {
		t.Errorf("port = %d, want preserved 2222", row.Port.Int32)
	}
	if row.SshUser.String != "deploy" {
		t.Errorf("ssh_user = %q, want preserved 'deploy'", row.SshUser.String)
	}
	if !row.PrivateKeyRef.Valid || row.PrivateKeyRef.String == "" {
		t.Errorf("private_key_ref cleared by re-sync (want preserved)")
	}
	if !row.PublicKeyOpenssh.Valid || row.PublicKeyOpenssh.String == "" {
		t.Errorf("public_key_openssh cleared by re-sync (want preserved)")
	}
}

// TestExecEndpoint_ConfigureGeneratesKeypair asserts that the first
// PUT /api/v1/agents/{id}/exec-endpoints/{slug} mints a fresh ED25519
// keypair (private key encrypted into the secrets store, public key
// stored on the row with a dated comment).
func TestExecEndpoint_ConfigureGeneratesKeypair(t *testing.T) {
	h := apitest.Setup(t)
	owner := apitest.CreateUser(t, h, "owner", "user")
	agentID := apitest.CreateAgent(t, h, apitest.AgentOpts{OwnerID: owner})
	agentToken := apitest.IssueAgentToken(t, h, agentID)
	ownerToken := apitest.IssueUserToken(t, h, owner, "owner@apitest.local", "user")

	declareExecEndpoint(t, h, agentToken, "ci", wire.ExecEndpointDef{
		Description: "Self-hosted CI runner",
		Access:      wire.AccessAdmin,
	})

	resp := h.Do(h.NewRequest(http.MethodPut,
		"/api/v1/agents/"+agentID.String()+"/exec-endpoints/ci",
		ownerToken,
		asJSON(t, map[string]any{"host": "127.0.0.1", "port": 2222, "sshUser": "deploy"})))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("configure: status %d, body %s", resp.StatusCode, h.ReadBody(resp))
	}
	var wrap struct {
		Endpoint struct {
			PublicKeyOpenSSH string `json:"publicKeyOpenssh"`
			PublicKeyComment string `json:"publicKeyComment"`
			Transport        string `json:"transport"`
			Host             string `json:"host"`
			Port             int    `json:"port"`
		} `json:"endpoint"`
	}
	if err := json.Unmarshal(h.ReadBody(resp), &wrap); err != nil {
		t.Fatalf("decode dto: %v", err)
	}
	dto := wrap.Endpoint

	if dto.Transport != "ssh" || dto.Host != "127.0.0.1" || dto.Port != 2222 {
		t.Errorf("configure response %+v has unexpected transport/host/port", dto)
	}
	if !strings.HasPrefix(dto.PublicKeyOpenSSH, "ssh-ed25519 ") {
		t.Errorf("public key shape wrong: %q", dto.PublicKeyOpenSSH)
	}
	if !strings.HasPrefix(dto.PublicKeyComment, "airlock-") {
		t.Errorf("comment doesn't start with 'airlock-': %q", dto.PublicKeyComment)
	}
	// Date stamp at the end (YYYY-MM-DD = 10 chars). Loose check —
	// don't pin the year so the test ages cleanly.
	if len(dto.PublicKeyComment) < len("airlock-XX-YYYY-MM-DD") {
		t.Errorf("comment seems too short to include a date: %q", dto.PublicKeyComment)
	}
}

// TestExecEndpoint_EndToEnd drives the full happy path against a real
// in-process SSH server:
//   - declare from the agent
//   - operator configures host/port/user → keypair generated
//   - SSH test server authorizes that key
//   - agent calls POST /api/agent/exec/{slug} with a command
//   - airlock dials, runs, streams NDJSON envelopes back
//   - assert stdout/stderr/exit + that the host key was TOFU-pinned
func TestExecEndpoint_EndToEnd(t *testing.T) {
	h := apitest.Setup(t)
	sshSrv := apitest.NewSSHTestServer(t)
	sshSrv.HandleCommand("echo hi", func(s *apitest.Session) (int, error) {
		_, _ = io.WriteString(s.Stdout, "hi\n")
		return 0, nil
	})
	sshSrv.HandleCommand("ls -la 'my dir'", func(s *apitest.Session) (int, error) {
		_, _ = io.WriteString(s.Stdout, "drwxr-xr-x 2 user user 4096 May 26 10:00 'my dir'\n")
		return 0, nil
	})
	sshSrv.HandleCommand("exit-7", func(s *apitest.Session) (int, error) {
		_, _ = io.WriteString(s.Stderr, "intentional failure\n")
		return 7, nil
	})

	owner := apitest.CreateUser(t, h, "owner", "user")
	agentID := apitest.CreateAgent(t, h, apitest.AgentOpts{OwnerID: owner})
	agentToken := apitest.IssueAgentToken(t, h, agentID)
	ownerToken := apitest.IssueUserToken(t, h, owner, "owner@apitest.local", "user")

	declareExecEndpoint(t, h, agentToken, "vps", wire.ExecEndpointDef{
		Description: "VPS",
		Access:      wire.AccessAdmin,
	})

	sshHost, sshPort := sshSrv.Addr()
	configResp := h.Do(h.NewRequest(http.MethodPut,
		"/api/v1/agents/"+agentID.String()+"/exec-endpoints/vps",
		ownerToken,
		asJSON(t, map[string]any{"host": sshHost, "port": sshPort, "sshUser": "deploy"})))
	if configResp.StatusCode != http.StatusOK {
		t.Fatalf("configure: status %d, body %s", configResp.StatusCode, h.ReadBody(configResp))
	}
	var wrap struct {
		Endpoint struct {
			PublicKeyOpenSSH string `json:"publicKeyOpenssh"`
		} `json:"endpoint"`
	}
	if err := json.Unmarshal(h.ReadBody(configResp), &wrap); err != nil {
		t.Fatalf("decode dto: %v", err)
	}
	sshSrv.Authorize(wrap.Endpoint.PublicKeyOpenSSH)

	// 1. Successful call — verify NDJSON stdout + exit envelope.
	res := agentExec(t, h, agentToken, "vps", "echo hi", nil)
	if string(res.Stdout) != "hi\n" {
		t.Errorf("stdout = %q, want %q", res.Stdout, "hi\n")
	}
	if res.ExitCode != 0 {
		t.Errorf("exit = %d, want 0", res.ExitCode)
	}

	// 2. Shell quoting — args with spaces must survive intact.
	res = agentExec(t, h, agentToken, "vps", "ls", []string{"-la", "my dir"})
	if !strings.Contains(string(res.Stdout), "my dir") {
		t.Errorf("quoted args lost in transit: stdout = %q", res.Stdout)
	}

	// 3. Non-zero exit + stderr — both surface intact (not as errors).
	res = agentExec(t, h, agentToken, "vps", "exit-7", nil)
	if res.ExitCode != 7 {
		t.Errorf("exit = %d, want 7", res.ExitCode)
	}
	if !strings.Contains(string(res.Stderr), "intentional failure") {
		t.Errorf("stderr lost: %q", res.Stderr)
	}

	// 4. Host key was TOFU-pinned after first connect — DB row carries
	//    the same fingerprint the server presents.
	q := dbq.New(h.DB.Pool())
	row, err := q.ResolveBoundExecEndpoint(context.Background(), dbq.ResolveBoundExecEndpointParams{
		AgentID: pgUUID(agentID),
		Slug:    "vps",
	})
	if err != nil {
		t.Fatalf("get row: %v", err)
	}
	if !row.HostKeyOpenssh.Valid || row.HostKeyOpenssh.String == "" {
		t.Fatal("host key not pinned after successful connect")
	}
	if row.HostKeyOpenssh.String != sshSrv.HostKeyOpenSSH() {
		t.Errorf("pinned host key %q != server host key %q",
			row.HostKeyOpenssh.String, sshSrv.HostKeyOpenSSH())
	}
}

// TestExecEndpoint_UnconfiguredReturns4xx asserts that an exec call
// against an endpoint the operator hasn't configured returns a status
// the SDK classifies as ExecError{Kind: "config"} — either 404
// (slug doesn't exist) or 501 (slug declared but transport empty).
// Both surface identically to the agent author.
func TestExecEndpoint_UnconfiguredReturns4xx(t *testing.T) {
	h := apitest.Setup(t)
	owner := apitest.CreateUser(t, h, "owner", "user")
	agentID := apitest.CreateAgent(t, h, apitest.AgentOpts{OwnerID: owner})
	agentToken := apitest.IssueAgentToken(t, h, agentID)

	// Case 1: slug declared by the agent as a need but never configured by the
	// operator → the resource was never created/bound → 404 (not bound).
	declareExecEndpoint(t, h, agentToken, "vps", wire.ExecEndpointDef{
		Description: "Not yet configured",
		Access:      wire.AccessAdmin,
	})
	resp := h.Do(h.NewRequest(http.MethodPost,
		"/api/agent/exec/vps",
		agentToken,
		asJSON(t, map[string]any{"command": "anything"})))
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("declared-but-unconfigured: status %d, want 404", resp.StatusCode)
		t.Logf("body: %s", h.ReadBody(resp))
	} else {
		resp.Body.Close()
	}

	// Case 2: slug never declared at all → 404.
	resp = h.Do(h.NewRequest(http.MethodPost,
		"/api/agent/exec/nope",
		agentToken,
		asJSON(t, map[string]any{"command": "anything"})))
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("undeclared slug: status %d, want 404", resp.StatusCode)
		t.Logf("body: %s", h.ReadBody(resp))
	} else {
		resp.Body.Close()
	}
}

// TestExecEndpoint_TestConnection drives the operator's "test
// connection" button. Runs `whoami` on the server, returns a structured
// outcome including the stdout the server emitted. Also confirms the
// host key got pinned via this flow (not just via /exec).
func TestExecEndpoint_TestConnection(t *testing.T) {
	h := apitest.Setup(t)
	sshSrv := apitest.NewSSHTestServer(t)
	sshSrv.HandleCommand("whoami", func(s *apitest.Session) (int, error) {
		_, _ = io.WriteString(s.Stdout, "deploy\n")
		return 0, nil
	})

	owner := apitest.CreateUser(t, h, "owner", "user")
	agentID := apitest.CreateAgent(t, h, apitest.AgentOpts{OwnerID: owner})
	agentToken := apitest.IssueAgentToken(t, h, agentID)
	ownerToken := apitest.IssueUserToken(t, h, owner, "owner@apitest.local", "user")

	declareExecEndpoint(t, h, agentToken, "vps", wire.ExecEndpointDef{
		Description: "VPS",
		Access:      wire.AccessAdmin,
	})

	sshHost, sshPort := sshSrv.Addr()
	configResp := h.Do(h.NewRequest(http.MethodPut,
		"/api/v1/agents/"+agentID.String()+"/exec-endpoints/vps",
		ownerToken,
		asJSON(t, map[string]any{"host": sshHost, "port": sshPort, "sshUser": "deploy"})))
	if configResp.StatusCode != http.StatusOK {
		t.Fatalf("configure: %d %s", configResp.StatusCode, h.ReadBody(configResp))
	}
	var wrap struct {
		Endpoint struct {
			PublicKeyOpenSSH string `json:"publicKeyOpenssh"`
		} `json:"endpoint"`
	}
	if err := json.Unmarshal(h.ReadBody(configResp), &wrap); err != nil {
		t.Fatalf("decode: %v", err)
	}
	sshSrv.Authorize(wrap.Endpoint.PublicKeyOpenSSH)

	resp := h.Do(h.NewRequest(http.MethodPost,
		"/api/v1/agents/"+agentID.String()+"/exec-endpoints/vps/test",
		ownerToken, asJSON(t, map[string]any{})))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("test: %d %s", resp.StatusCode, h.ReadBody(resp))
	}
	var testResp struct {
		Result struct {
			OK       bool   `json:"ok"`
			ExitCode int    `json:"exitCode"`
			Stdout   string `json:"stdout"`
			Error    string `json:"error"`
		} `json:"result"`
	}
	if err := json.Unmarshal(h.ReadBody(resp), &testResp); err != nil {
		t.Fatalf("decode test result: %v", err)
	}
	out := testResp.Result
	if !out.OK || out.ExitCode != 0 {
		t.Errorf("test result: ok=%v exit=%d error=%q", out.OK, out.ExitCode, out.Error)
	}
	if !strings.Contains(out.Stdout, "deploy") {
		t.Errorf("stdout %q didn't contain 'deploy'", out.Stdout)
	}
}

// --- helpers ---

// declareExecEndpoint declares an exec endpoint by running an agent sync with
// it in the batch — the only way an agent registers an exec endpoint now that
// the per-slug PUT is gone. A re-sync of the same endpoint preserves the
// operator-configured columns (the UpsertExecEndpointDeclaration ON CONFLICT
// clause).
func declareExecEndpoint(t *testing.T, h *apitest.Harness, agentToken, slug string, def wire.ExecEndpointDef) {
	t.Helper()
	def.Slug = slug
	body := wire.SyncRequest{ExecEndpoints: []wire.ExecEndpointDef{def}}
	resp := h.Do(h.NewRequest(http.MethodPut, "/api/agent/sync", agentToken, asJSON(t, body)))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sync exec-endpoint %s: status %d, body %s",
			slug, resp.StatusCode, h.ReadBody(resp))
	}
	resp.Body.Close()
}

// agentExec drives POST /api/agent/exec/{slug} and parses the NDJSON
// stream into ExecResult-like fields. Stops at the first exit envelope.
func agentExec(t *testing.T, h *apitest.Harness, agentToken, slug, command string, args []string) execResult {
	t.Helper()
	body := map[string]any{"command": command}
	if len(args) > 0 {
		body["args"] = args
	}
	resp := h.Do(h.NewRequest(http.MethodPost,
		"/api/agent/exec/"+slug, agentToken, asJSON(t, body)))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("exec %s: status %d, body %s",
			slug, resp.StatusCode, h.ReadBody(resp))
	}
	defer resp.Body.Close()

	var res execResult
	dec := json.NewDecoder(resp.Body)
	for {
		var env struct {
			Type       string `json:"type"`
			Data       string `json:"data"`
			Code       int    `json:"code"`
			DurationMs int64  `json:"durationMs"`
			Kind       string `json:"kind"`
			Message    string `json:"message"`
		}
		if err := dec.Decode(&env); err != nil {
			if err == io.EOF {
				break
			}
			t.Fatalf("decode ndjson: %v", err)
		}
		switch env.Type {
		case "stdout":
			b, _ := base64.StdEncoding.DecodeString(env.Data)
			res.Stdout = append(res.Stdout, b...)
		case "stderr":
			b, _ := base64.StdEncoding.DecodeString(env.Data)
			res.Stderr = append(res.Stderr, b...)
		case "exit":
			res.ExitCode = env.Code
			res.DurationMs = env.DurationMs
			return res
		case "error":
			t.Fatalf("exec returned error envelope: kind=%s message=%s", env.Kind, env.Message)
		}
	}
	t.Fatalf("exec %s: stream ended without exit envelope", slug)
	return res
}

type execResult struct {
	Stdout     []byte
	Stderr     []byte
	ExitCode   int
	DurationMs int64
}

func asJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// pgUUID converts a uuid.UUID into the pgtype.UUID shape the dbq
// queries expect.
func pgUUID(u uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: u, Valid: true}
}
