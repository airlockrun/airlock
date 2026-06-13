// Package execproxy implements the airlock-side SSH execution path for
// agentsdk.RegisterExecEndpoint. The dialer opens a session against the
// operator-configured target, streams stdout/stderr/exit envelopes back
// over an http.ResponseWriter as NDJSON, and handles host-key TOFU.
//
// Credentials never leave airlock — the private key is decrypted via
// secrets.Store at dial time and the agent process never sees raw key
// material. Operational logs record byte counts only, not payloads.
package execproxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/secrets"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

// Default ceilings — kept as vars so tests can lower them. Production
// callers should treat these as constants.
var (
	// DefaultExecTimeout is the wall-clock cap for a single exec call
	// when the caller doesn't specify ExecCommand.TimeoutMs. SSH dial,
	// auth, command execution, and stream draining all share this
	// budget.
	DefaultExecTimeout = 60 * time.Second

	// MaxExecTimeout is the upper bound — operators can't accidentally
	// allow a single call to hold a session for hours.
	MaxExecTimeout = 10 * time.Minute

	// DialTimeout is how long the TCP+SSH handshake gets before the
	// dialer gives up and returns a transport error.
	DialTimeout = 15 * time.Second

	// StreamChunkBytes is the raw byte count we buffer between reads
	// of session.Stdout/Stderr before base64-encoding and writing one
	// NDJSON envelope. 32 KiB keeps each envelope under the SDK's
	// 256 KiB scanner buffer with a comfortable margin (base64
	// inflates ~33%) while batching enough to avoid envelope-per-byte
	// overhead.
	StreamChunkBytes = 32 * 1024
)

// HostKeyMismatchError is returned when a pinned host key doesn't match
// what the remote presented during the SSH handshake. Distinct type so
// the HTTP handler can map it to a specific status / message.
type HostKeyMismatchError struct {
	Expected string
	Got      string
}

func (e *HostKeyMismatchError) Error() string {
	return "host key mismatch (expected " + e.Expected + ", got " + e.Got + ")"
}

// TOFUPinner is the dependency the dialer needs to record a newly-seen
// host key the first time a TOFU connect succeeds. The HTTP handler
// implements this against the sqlc-generated SetExecEndpointHostKey.
type TOFUPinner interface {
	PinHostKey(ctx context.Context, endpointID uuid.UUID, hostKeyOpenSSH string) error
}

// SSHDialer is the entry point for the agent-internal exec handler.
// Build one at server startup and reuse it for every exec call.
type SSHDialer struct {
	secrets  secrets.Store
	cache    *clientCache
	pinner   TOFUPinner
	logger   *zap.Logger
	stopCh   chan struct{}
	stopOnce sync.Once
}

// NewSSHDialer constructs an SSHDialer with sensible defaults. Call
// Close at shutdown to stop the cache reaper.
func NewSSHDialer(store secrets.Store, pinner TOFUPinner, logger *zap.Logger) *SSHDialer {
	if store == nil {
		panic("execproxy: NewSSHDialer requires a non-nil secrets.Store")
	}
	if pinner == nil {
		panic("execproxy: NewSSHDialer requires a non-nil TOFUPinner")
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	d := &SSHDialer{
		secrets: store,
		cache:   newClientCache(5 * time.Minute),
		pinner:  pinner,
		logger:  logger.Named("execproxy"),
		stopCh:  make(chan struct{}),
	}
	go d.cache.reapLoop(d.stopCh)
	return d
}

// Close stops the cache reaper. Idempotent.
func (d *SSHDialer) Close() {
	d.stopOnce.Do(func() { close(d.stopCh) })
}

// EvictCache clears the cached client for endpoint id — called by the
// admin handlers after any config / keypair / host-key mutation so the
// next call dials fresh.
func (d *SSHDialer) EvictCache(id uuid.UUID) { d.cache.Evict(id) }

// ExecRequest is the parsed input from the agent's
// POST /api/agent/exec/{slug} body. Stdin is the raw bytes (already
// decoded from base64 on the wire).
type ExecRequest struct {
	Command   string
	Args      []string
	Stdin     []byte
	TimeoutMs int64
}

// Exec opens an SSH session, runs the assembled command, and streams
// stdout/stderr/exit envelopes to w as NDJSON. All errors after the
// first byte is written go into the stream as a terminal "error"
// envelope; the function still returns nil to the caller because the
// HTTP response has already started. Pre-stream errors (dial, auth,
// host-key mismatch) return without writing anything so the HTTP
// handler can map them to a status code.
func (d *SSHDialer) Exec(
	ctx context.Context,
	ep *dbq.AgentExecEndpoint,
	req ExecRequest,
	w http.ResponseWriter,
) error {
	timeout := time.Duration(req.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = DefaultExecTimeout
	}
	if timeout > MaxExecTimeout {
		timeout = MaxExecTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if ep.Transport.String != "ssh" {
		return &PreStreamError{Kind: "config", Status: http.StatusNotImplemented,
			Message: "transport not configured (expected ssh)"}
	}

	endpointID, err := uuidFromPg(ep.ID)
	if err != nil {
		return &PreStreamError{Kind: "config", Status: http.StatusInternalServerError,
			Message: "invalid endpoint id"}
	}

	client, dialErr := d.acquireClient(ctx, ep, endpointID)
	if dialErr != nil {
		return dialErr
	}

	session, err := client.NewSession()
	if err != nil {
		// A session-open failure on a cached client usually means the
		// TCP connection died silently. Evict and try once more with a
		// fresh dial — masking transient broken-pipe is worth ~150ms
		// when caches age.
		d.cache.Evict(endpointID)
		client, dialErr = d.acquireClient(ctx, ep, endpointID)
		if dialErr != nil {
			return dialErr
		}
		session, err = client.NewSession()
		if err != nil {
			return &PreStreamError{Kind: "transport", Status: http.StatusBadGateway,
				Message: "ssh session open: " + err.Error()}
		}
	}
	defer session.Close()

	stdoutPipe, err := session.StdoutPipe()
	if err != nil {
		return &PreStreamError{Kind: "transport", Status: http.StatusBadGateway,
			Message: "stdout pipe: " + err.Error()}
	}
	stderrPipe, err := session.StderrPipe()
	if err != nil {
		return &PreStreamError{Kind: "transport", Status: http.StatusBadGateway,
			Message: "stderr pipe: " + err.Error()}
	}
	if len(req.Stdin) > 0 {
		stdinPipe, err := session.StdinPipe()
		if err != nil {
			return &PreStreamError{Kind: "transport", Status: http.StatusBadGateway,
				Message: "stdin pipe: " + err.Error()}
		}
		go func() {
			defer stdinPipe.Close()
			_, _ = stdinPipe.Write(req.Stdin)
		}()
	}

	cmdLine := JoinCommand(req.Command, req.Args)
	if err := session.Start(cmdLine); err != nil {
		return &PreStreamError{Kind: "transport", Status: http.StatusBadGateway,
			Message: "session start: " + err.Error()}
	}

	// Past this point we have a session running on the remote. From
	// here on errors go INTO the stream as "error" envelopes; the HTTP
	// status is already 200.
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)

	flusher, _ := w.(http.Flusher)
	stream := &envelopeWriter{w: w, flusher: flusher}

	streamStart := time.Now()
	var wg sync.WaitGroup
	wg.Add(2)
	go pumpStream(&wg, stdoutPipe, "stdout", stream)
	go pumpStream(&wg, stderrPipe, "stderr", stream)
	wg.Wait()

	waitErr := session.Wait()
	durationMs := time.Since(streamStart).Milliseconds()

	exitCode := 0
	var exitErr *ssh.ExitError
	switch {
	case waitErr == nil:
		// success path — exitCode stays 0
	case errors.As(waitErr, &exitErr):
		exitCode = exitErr.ExitStatus()
	default:
		// Anything else (network drop, killed by signal, etc.) is a
		// mid-stream transport failure — emit a terminal error
		// envelope so the SDK surfaces *ExecError to the agent.
		stream.writeEnvelope(execEnvelope{Type: "error", Kind: "transport",
			Message: "session wait: " + waitErr.Error()})
		d.logger.Warn("exec session wait failed",
			zap.String("endpoint_slug", ep.Slug),
			zap.Error(waitErr))
		return nil
	}

	stream.writeEnvelope(execEnvelope{
		Type:       "exit",
		Code:       exitCode,
		DurationMs: durationMs,
	})
	return nil
}

// pumpStream reads chunks from one of the session's stream pipes and
// emits one NDJSON envelope per chunk through stream. Closes its half
// of the WaitGroup when the pipe returns EOF or error.
func pumpStream(wg *sync.WaitGroup, src io.Reader, kind string, w *envelopeWriter) {
	defer wg.Done()
	buf := make([]byte, StreamChunkBytes)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			w.writeEnvelope(execEnvelope{
				Type: kind,
				Data: base64.StdEncoding.EncodeToString(buf[:n]),
			})
		}
		if err != nil {
			return
		}
	}
}

// envelopeWriter serializes JSON envelopes onto an http.ResponseWriter
// from potentially concurrent goroutines (one per stream). A mutex
// guards the underlying Write so envelopes never interleave mid-line.
type envelopeWriter struct {
	mu      sync.Mutex
	w       io.Writer
	flusher http.Flusher
}

func (e *envelopeWriter) writeEnvelope(env execEnvelope) {
	b, _ := json.Marshal(env)
	e.mu.Lock()
	defer e.mu.Unlock()
	e.w.Write(b)
	e.w.Write([]byte{'\n'})
	if e.flusher != nil {
		e.flusher.Flush()
	}
}

// execEnvelope mirrors the SDK's wire shape; kept private to the
// package — public consumers only see the streamed JSON.
type execEnvelope struct {
	Type       string `json:"type"`
	Data       string `json:"data,omitempty"`
	Code       int    `json:"code,omitempty"`
	DurationMs int64  `json:"durationMs,omitempty"`
	Kind       string `json:"kind,omitempty"`
	Message    string `json:"message,omitempty"`
}

// PreStreamError is returned by Exec when the failure happened before
// any byte of the streaming response was written. The HTTP handler maps
// .Status to a status code; the agent SDK uses the status code (not the
// body) to classify into ExecError.Kind.
type PreStreamError struct {
	Kind    string // transport | timeout | config | denied
	Status  int    // HTTP status to write
	Message string
}

func (e *PreStreamError) Error() string { return e.Kind + ": " + e.Message }

// acquireClient returns a cached *ssh.Client for endpointID if one is
// live, otherwise dials a fresh one and caches it. Decrypts the
// endpoint's private key via secrets.Store.
func (d *SSHDialer) acquireClient(
	ctx context.Context,
	ep *dbq.AgentExecEndpoint,
	endpointID uuid.UUID,
) (*ssh.Client, *PreStreamError) {
	if c := d.cache.Get(endpointID); c != nil {
		return c, nil
	}

	if !ep.PrivateKeyRef.Valid || ep.PrivateKeyRef.String == "" {
		return nil, &PreStreamError{Kind: "config", Status: http.StatusNotFound,
			Message: "keypair not generated (endpoint not configured)"}
	}
	if !ep.Host.Valid || ep.Host.String == "" {
		return nil, &PreStreamError{Kind: "config", Status: http.StatusNotFound,
			Message: "host not configured"}
	}
	if !ep.SshUser.Valid || ep.SshUser.String == "" {
		return nil, &PreStreamError{Kind: "config", Status: http.StatusNotFound,
			Message: "user not configured"}
	}

	privPEM, err := d.secrets.Get(ctx, "exec/"+endpointID.String()+"/private_key", ep.PrivateKeyRef.String)
	if err != nil {
		d.logger.Error("decrypt private key", zap.String("endpoint_slug", ep.Slug), zap.Error(err))
		return nil, &PreStreamError{Kind: "config", Status: http.StatusInternalServerError,
			Message: "decrypt private key failed"}
	}
	d.logger.Debug("decrypted private key", zap.Int("priv_key_bytes", len(privPEM)))

	signer, err := ssh.ParsePrivateKey([]byte(privPEM))
	if err != nil {
		return nil, &PreStreamError{Kind: "config", Status: http.StatusInternalServerError,
			Message: "parse private key: " + err.Error()}
	}

	hostKeyCB, pinIfTOFU := d.hostKeyCallback(ep)

	cfg := &ssh.ClientConfig{
		User:            ep.SshUser.String,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: hostKeyCB,
		Timeout:         DialTimeout,
	}

	port := 22
	if ep.Port.Valid && ep.Port.Int32 > 0 {
		port = int(ep.Port.Int32)
	}
	addr := net.JoinHostPort(ep.Host.String, strconv.Itoa(port))

	// Dial with the request ctx so the caller's cancellation propagates
	// to the TCP handshake. ssh.Dial doesn't take a ctx directly; wrap
	// net.Dial via a dialer that honors it.
	var dialer net.Dialer
	dialer.Timeout = DialTimeout
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		if mismatchErr := (*HostKeyMismatchError)(nil); errors.As(err, &mismatchErr) {
			return nil, &PreStreamError{Kind: "transport", Status: http.StatusBadGateway,
				Message: err.Error()}
		}
		return nil, &PreStreamError{Kind: "transport", Status: http.StatusBadGateway,
			Message: "dial: " + err.Error()}
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(rawConn, addr, cfg)
	if err != nil {
		_ = rawConn.Close()
		var mismatchErr *HostKeyMismatchError
		if errors.As(err, &mismatchErr) {
			return nil, &PreStreamError{Kind: "denied", Status: http.StatusBadGateway,
				Message: err.Error()}
		}
		return nil, &PreStreamError{Kind: "denied", Status: http.StatusBadGateway,
			Message: "ssh handshake: " + err.Error()}
	}
	client := ssh.NewClient(sshConn, chans, reqs)

	// Pin host key on successful first TOFU connect. Errors here are
	// logged but not fatal — the dial succeeded, the operator just won't
	// see the fingerprint until next call.
	if pinIfTOFU != nil {
		if err := pinIfTOFU(ctx); err != nil {
			d.logger.Warn("host-key TOFU pin failed",
				zap.String("endpoint_slug", ep.Slug),
				zap.Error(err))
		}
	}

	d.cache.Put(endpointID, client)
	return client, nil
}

// hostKeyCallback returns the ssh.HostKeyCallback for the endpoint plus
// (when the endpoint is in TOFU mode) a closure the caller invokes after
// a successful handshake to persist the observed host key.
//
// Pinned mode (ep.HostKeyOpenssh non-empty): strict compare; mismatch
// returns *HostKeyMismatchError, ssh.Dial fails.
//
// TOFU mode (ep.HostKeyOpenssh empty): callback always accepts and
// captures the observed key into a closure-bound variable; the second
// return persists it once the rest of the handshake completes.
func (d *SSHDialer) hostKeyCallback(ep *dbq.AgentExecEndpoint) (ssh.HostKeyCallback, func(context.Context) error) {
	if ep.HostKeyOpenssh.Valid && ep.HostKeyOpenssh.String != "" {
		expectedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(ep.HostKeyOpenssh.String))
		if err != nil {
			// Corrupt pinned host key — refuse all connects until the
			// operator unpins. Surfaces as a transport error.
			return func(string, net.Addr, ssh.PublicKey) error {
				return fmt.Errorf("pinned host key is corrupt: %w", err)
			}, nil
		}
		expectedFP := ssh.FingerprintSHA256(expectedKey)
		return func(_ string, _ net.Addr, key ssh.PublicKey) error {
			gotFP := ssh.FingerprintSHA256(key)
			if gotFP != expectedFP {
				return &HostKeyMismatchError{Expected: expectedFP, Got: gotFP}
			}
			return nil
		}, nil
	}

	// TOFU. Capture the observed key into observed; pinIfTOFU writes it
	// after the handshake finishes. We don't write inside the callback
	// because the callback runs while the SSH handshake is mid-flight
	// and a DB roundtrip would stall it.
	var observed ssh.PublicKey
	cb := func(_ string, _ net.Addr, key ssh.PublicKey) error {
		observed = key
		return nil
	}
	endpointID, _ := uuidFromPg(ep.ID)
	pinFn := func(ctx context.Context) error {
		if observed == nil {
			return nil
		}
		line := ssh.MarshalAuthorizedKey(observed)
		// Strip trailing newline so storage is canonical.
		if n := len(line); n > 0 && line[n-1] == '\n' {
			line = line[:n-1]
		}
		return d.pinner.PinHostKey(ctx, endpointID, string(line))
	}
	return cb, pinFn
}

// uuidFromPg converts a sqlc-generated pgtype.UUID into a google/uuid
// value. pgtype.UUID has public Bytes/Valid fields so we read them
// directly — no interface gymnastics.
func uuidFromPg(p pgtype.UUID) (uuid.UUID, error) {
	if !p.Valid {
		return uuid.Nil, errors.New("execproxy: row id is null")
	}
	return uuid.UUID(p.Bytes), nil
}

// HostKeyFingerprint returns the SHA256 fingerprint of a host key
// OpenSSH-formatted string, for UI display. Empty input → empty output.
func HostKeyFingerprint(openssh string) string {
	if openssh == "" {
		return ""
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(openssh))
	if err != nil {
		return ""
	}
	return ssh.FingerprintSHA256(key)
}

// Suppress unused-import warning for bytes (kept for future use in
// envelope buffering optimizations).
var _ = bytes.NewBuffer
