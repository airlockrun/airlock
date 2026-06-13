package execproxy

import (
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// GenerateED25519 produces a usable private key (parseable by
// ssh.ParsePrivateKey) and a public key line that matches the
// "<algo> <base64> <comment>" shape the operator copies into
// authorized_keys.
func TestGenerateED25519_ProducesUsableKeypair(t *testing.T) {
	kp, err := GenerateED25519("myagent", "ci-runner")
	if err != nil {
		t.Fatalf("GenerateED25519: %v", err)
	}

	// Private key parses cleanly — handler will do exactly this when
	// dialing.
	signer, err := ssh.ParsePrivateKey([]byte(kp.PrivatePEM))
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}
	if signer.PublicKey().Type() != ssh.KeyAlgoED25519 {
		t.Errorf("public key algo = %q, want ssh-ed25519", signer.PublicKey().Type())
	}

	// Public-key line has three space-separated fields and ends with
	// the dated comment.
	parts := strings.Fields(strings.TrimSpace(kp.PublicOpenSSH))
	if len(parts) != 3 {
		t.Fatalf("PublicOpenSSH has %d fields, want 3: %q", len(parts), kp.PublicOpenSSH)
	}
	if parts[0] != "ssh-ed25519" {
		t.Errorf("first field = %q, want ssh-ed25519", parts[0])
	}
	if !strings.HasPrefix(parts[2], "airlock-myagent-ci-runner-") {
		t.Errorf("comment = %q, want prefix 'airlock-myagent-ci-runner-'", parts[2])
	}
	if kp.Comment != parts[2] {
		t.Errorf("kp.Comment = %q, public-key comment = %q", kp.Comment, parts[2])
	}
}

func TestGenerateED25519_RejectsEmptySlug(t *testing.T) {
	_, err := GenerateED25519("", "x")
	if err == nil {
		t.Fatalf("expected error for empty agentSlug")
	}
	_, err = GenerateED25519("x", "")
	if err == nil {
		t.Fatalf("expected error for empty endpointSlug")
	}
}
