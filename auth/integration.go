package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
)

const integrationTokenPrefix = "alk_int_"

// NewIntegrationToken returns a build-scoped bearer token and the hash Airlock
// stores. The plaintext token exists only in the codegen toolserver environment.
func NewIntegrationToken() (string, []byte, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	token := integrationTokenPrefix + base64.RawURLEncoding.EncodeToString(raw)
	return token, HashIntegrationToken(token), nil
}

// HashIntegrationToken validates and hashes an integration token for lookup.
// Invalid token shapes return nil so they cannot match a database row.
func HashIntegrationToken(token string) []byte {
	encoded, ok := strings.CutPrefix(token, integrationTokenPrefix)
	if !ok {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) != 32 {
		return nil
	}
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// BearerToken extracts a strict Authorization bearer token.
func BearerToken(header string) (string, error) {
	token, ok := strings.CutPrefix(header, "Bearer ")
	if !ok || token == "" || strings.ContainsAny(token, " \t\r\n") {
		return "", errors.New("invalid authorization header")
	}
	return token, nil
}
