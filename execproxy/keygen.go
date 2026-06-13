package execproxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"
)

// Keypair carries a freshly generated ED25519 keypair plus the OpenSSH
// public-key line and its dated comment. Airlock stores PrivatePEM
// encrypted via secrets.Store and persists PublicOpenSSH + Comment in
// the agent_exec_endpoints row for UI display.
type Keypair struct {
	PrivatePEM    string
	PublicOpenSSH string
	Comment       string
}

// GenerateED25519 mints a new ED25519 keypair with a dated, human-grep'able
// comment. The comment shape lets the operator find old keys in
// authorized_keys after a rotation:
//
//	ssh-ed25519 AAAA… airlock-myagent-ci-runner-2026-05-26
//
// agentSlug + endpointSlug + an ISO date give a stable per-rotation
// identifier the operator can match exactly.
func GenerateED25519(agentSlug, endpointSlug string) (Keypair, error) {
	if agentSlug == "" || endpointSlug == "" {
		return Keypair{}, fmt.Errorf("execproxy: agentSlug and endpointSlug are required")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Keypair{}, fmt.Errorf("ed25519 keygen: %w", err)
	}

	// PEM-encode the private key in the OpenSSH-compatible PKCS#8 form
	// — recoverable later via ssh.ParseRawPrivateKey.
	privDER, err := marshalEd25519PKCS8(priv)
	if err != nil {
		return Keypair{}, err
	}
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privDER,
	})

	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return Keypair{}, fmt.Errorf("ssh.NewPublicKey: %w", err)
	}
	comment := fmt.Sprintf("airlock-%s-%s-%s", agentSlug, endpointSlug, time.Now().UTC().Format("2006-01-02"))

	// MarshalAuthorizedKey produces "ssh-ed25519 AAAA…\n" without a
	// comment; we append our own to match the canonical
	// "<algo> <base64> <comment>\n" layout.
	keyLine := string(ssh.MarshalAuthorizedKey(sshPub))
	if n := len(keyLine); n > 0 && keyLine[n-1] == '\n' {
		keyLine = keyLine[:n-1]
	}
	return Keypair{
		PrivatePEM:    string(privPEM),
		PublicOpenSSH: keyLine + " " + comment + "\n",
		Comment:       comment,
	}, nil
}

// marshalEd25519PKCS8 serializes an Ed25519 private key into PKCS#8
// DER, the format `ssh.ParseRawPrivateKey` accepts when wrapped in a
// "PRIVATE KEY" PEM block. crypto/x509 supports this directly.
func marshalEd25519PKCS8(priv ed25519.PrivateKey) ([]byte, error) {
	// crypto/x509.MarshalPKCS8PrivateKey supports ed25519 since Go 1.13.
	return x509MarshalPKCS8(priv)
}
