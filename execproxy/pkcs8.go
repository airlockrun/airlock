package execproxy

import (
	"crypto/ed25519"
	"crypto/x509"
)

// x509MarshalPKCS8 wraps crypto/x509.MarshalPKCS8PrivateKey for ed25519,
// extracted into a tiny helper so keygen.go reads cleanly. Kept separate
// because the type signature in stdlib accepts any private key — we want
// the call site narrowed to ed25519.PrivateKey for clarity.
func x509MarshalPKCS8(priv ed25519.PrivateKey) ([]byte, error) {
	return x509.MarshalPKCS8PrivateKey(priv)
}
