package apitest

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHTestServer is a minimal in-process SSH server for exec-endpoint
// integration tests. It accepts public-key auth against a single
// authorized key (set via Authorize) and serves canned responses to
// exec channel requests defined per command.
//
// Lifecycle: NewSSHTestServer(t) → registers t.Cleanup; tests use
// .Addr(), .Authorize(pubKey), and .HandleCommand(cmd, handler). No
// global state — every test gets a fresh server on a random port.
type SSHTestServer struct {
	t       *testing.T
	ln      net.Listener
	cfg     *ssh.ServerConfig
	hostKey ssh.Signer

	mu        sync.Mutex
	authPub   ssh.PublicKey
	handlers  map[string]CommandHandler
	defaultFn CommandHandler

	closeOnce sync.Once
	stopped   chan struct{}
}

// CommandHandler implements the body of one exec channel session. It
// receives the parsed command line (everything the SSH client sent —
// `cmd arg1 'arg with space' ...`) plus a Session for I/O. Return value
// becomes the exit code (0 on nil error; ssh.ExitError preserved
// otherwise).
//
// Use Session.Stdout / Session.Stderr to write output; close Session.Stdin
// before returning if the test sent stdin and you've consumed it.
type CommandHandler func(s *Session) (exitCode int, err error)

// Session carries the per-exec I/O bundle. Stdin is provided by the
// SSH client (the agent under test); Stdout/Stderr feed back to the
// client. Close cleans up if the handler bails early — tests typically
// won't call it explicitly.
type Session struct {
	Command string         // full command line as sent on the SSH exec request
	Stdin   io.Reader      // stdin bytes from the client
	Stdout  io.WriteCloser // canonical stdout pipe
	Stderr  io.WriteCloser // canonical stderr pipe
}

// NewSSHTestServer starts a fresh server on a random localhost port.
// Auto-generates a fresh ED25519 host key per server so every test
// exercises the TOFU code path with a unique fingerprint.
func NewSSHTestServer(t *testing.T) *SSHTestServer {
	t.Helper()

	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("apitest: ssh host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatalf("apitest: ssh signer: %v", err)
	}

	s := &SSHTestServer{
		t:        t,
		hostKey:  signer,
		handlers: make(map[string]CommandHandler),
		stopped:  make(chan struct{}),
	}

	s.cfg = &ssh.ServerConfig{
		PublicKeyCallback: s.authorize,
	}
	s.cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("apitest: ssh listen: %v", err)
	}
	s.ln = ln

	go s.acceptLoop()
	t.Cleanup(s.Close)
	return s
}

// Addr returns host:port of the listening server, suitable for paste
// into ConfigureExecEndpointSSH.
func (s *SSHTestServer) Addr() (host string, port int) {
	addr := s.ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port
}

// Authorize registers the OpenSSH-format public key authorized to log
// in. Tests pass the public key the operator-configure flow generated.
// Without this, all auth attempts fail.
func (s *SSHTestServer) Authorize(openSSHPubKey string) {
	s.t.Helper()
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.TrimRight(openSSHPubKey, "\n")))
	if err != nil {
		s.t.Fatalf("apitest: parse authorized key: %v", err)
	}
	s.mu.Lock()
	s.authPub = pub
	s.mu.Unlock()
}

// HandleCommand registers a handler for an exact command line. The SSH
// client sends the full command as one string (the result of
// JoinCommand on the airlock side), so match on the joined form:
// `kick-build --branch main` rather than the {cmd, args} pair.
//
// HandleCommandPrefix is the looser alternative when only the verb
// matters.
func (s *SSHTestServer) HandleCommand(command string, fn CommandHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handlers[command] = fn
}

// HandleDefault registers a fallback handler invoked for any command
// without an exact match. Useful for "always succeed" smoke handlers.
func (s *SSHTestServer) HandleDefault(fn CommandHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.defaultFn = fn
}

// Close stops the listener; safe to call multiple times.
func (s *SSHTestServer) Close() {
	s.closeOnce.Do(func() {
		close(s.stopped)
		_ = s.ln.Close()
	})
}

func (s *SSHTestServer) authorize(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	s.mu.Lock()
	authorized := s.authPub
	s.mu.Unlock()
	if authorized == nil {
		return nil, errors.New("no authorized key configured")
	}
	if ssh.FingerprintSHA256(authorized) != ssh.FingerprintSHA256(key) {
		return nil, errors.New("public key not authorized")
	}
	return &ssh.Permissions{}, nil
}

func (s *SSHTestServer) acceptLoop() {
	for {
		select {
		case <-s.stopped:
			return
		default:
		}
		conn, err := s.ln.Accept()
		if err != nil {
			select {
			case <-s.stopped:
				return
			default:
			}
			// Transient accept errors (test still running): brief pause
			// and retry. Listener closed: stopped channel fires above.
			time.Sleep(10 * time.Millisecond)
			continue
		}
		go s.serveConn(conn)
	}
}

func (s *SSHTestServer) serveConn(rawConn net.Conn) {
	defer rawConn.Close()
	sshConn, chans, reqs, err := ssh.NewServerConn(rawConn, s.cfg)
	if err != nil {
		return
	}
	defer sshConn.Close()
	go ssh.DiscardRequests(reqs)

	for ch := range chans {
		if ch.ChannelType() != "session" {
			_ = ch.Reject(ssh.UnknownChannelType, "only session channels supported")
			continue
		}
		go s.serveChannel(ch)
	}
}

func (s *SSHTestServer) serveChannel(newCh ssh.NewChannel) {
	channel, reqs, err := newCh.Accept()
	if err != nil {
		return
	}
	defer channel.Close()

	for req := range reqs {
		switch req.Type {
		case "exec":
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			cmd := parseExecPayload(req.Payload)
			s.runCommand(channel, cmd)
			// One exec per session in SSH — close and return.
			return
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

// parseExecPayload extracts the command string from an SSH "exec"
// request payload. Format is a 4-byte big-endian length prefix + the
// string bytes (RFC 4254 §6.5).
func parseExecPayload(p []byte) string {
	if len(p) < 4 {
		return ""
	}
	n := int(p[0])<<24 | int(p[1])<<16 | int(p[2])<<8 | int(p[3])
	if 4+n > len(p) {
		return ""
	}
	return string(p[4 : 4+n])
}

func (s *SSHTestServer) runCommand(ch ssh.Channel, cmd string) {
	s.mu.Lock()
	handler := s.handlers[cmd]
	if handler == nil {
		handler = s.defaultFn
	}
	s.mu.Unlock()

	if handler == nil {
		// Unhandled command — send a 127-style "not found" exit.
		_ = sendExitStatus(ch, 127)
		return
	}

	stderrPipe := ch.Stderr()
	session := &Session{
		Command: cmd,
		Stdin:   ch,
		Stdout:  noopCloser{Writer: ch},
		Stderr:  noopCloser{Writer: stderrPipe},
	}
	exit, err := handler(session)
	if err != nil {
		// Translate a generic handler error into a non-zero exit so
		// the SSH client gets a clean signal. Tests that want to drive
		// transport-level failures should close the listener instead.
		if exit == 0 {
			exit = 1
		}
		_, _ = stderrPipe.Write([]byte(err.Error()))
	}
	_ = sendExitStatus(ch, exit)
}

// sendExitStatus writes the SSH exit-status channel request that the
// client (ssh.Session.Wait) blocks on. Payload format is the exit code
// as a big-endian uint32.
func sendExitStatus(ch ssh.Channel, code int) error {
	payload := []byte{byte(code >> 24), byte(code >> 16), byte(code >> 8), byte(code)}
	if code < 0 {
		// SSH wire format is unsigned; clamp.
		payload = []byte{0xff, 0xff, 0xff, 0xff}
	}
	_, err := ch.SendRequest("exit-status", false, payload)
	return err
}

// noopCloser adapts a plain Writer to io.WriteCloser. The SSH channel
// already manages its own lifecycle; handlers shouldn't close it.
type noopCloser struct{ io.Writer }

func (noopCloser) Close() error { return nil }

// HostKeyOpenSSH returns the server's host key in OpenSSH wire format,
// suitable for direct comparison or pinning. Tests use this to assert
// the host-key TOFU code path captured the right key.
func (s *SSHTestServer) HostKeyOpenSSH() string {
	line := ssh.MarshalAuthorizedKey(s.hostKey.PublicKey())
	return strings.TrimRight(string(line), "\n")
}

// Fingerprint returns SHA256:base64 fingerprint, matching what the
// operator UI surfaces.
func (s *SSHTestServer) Fingerprint() string {
	return ssh.FingerprintSHA256(s.hostKey.PublicKey())
}

// CommandsHandled returns the number of exec requests this server has
// served. Useful in tests that need to assert cache reuse vs cold dial
// (we expect one exec per call regardless of caching, but it's a
// secondary signal worth having). Reads are not synchronized with
// in-flight serveChannel goroutines; call after the test's exec calls
// have completed.
func (s *SSHTestServer) String() string {
	host, port := s.Addr()
	return fmt.Sprintf("%s:%d", host, port)
}
