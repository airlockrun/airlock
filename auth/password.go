package auth

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"

	"github.com/trustelem/zxcvbn"
	"golang.org/x/crypto/bcrypt"
)

// MinPasswordScore is the minimum acceptable zxcvbn strength score (0–4) for a
// user-chosen password. The frontend meter enforces the same threshold via
// @zxcvbn-ts, so "acceptable" means the same thing on both sides and a password
// the meter shows as green is one the backend will accept. 3 ("safely
// unguessable") is the floor for an internet-facing login.
const MinPasswordScore = 3

// ErrWeakPassword is returned by ValidatePasswordStrength for passwords below
// MinPasswordScore.
var ErrWeakPassword = errors.New("password is too weak: choose a longer or less predictable password")

// ValidatePasswordStrength rejects weak passwords using zxcvbn. userInputs are
// context strings (email, display name) that count against the score when the
// password contains them. Returns nil when the password is strong enough.
func ValidatePasswordStrength(password string, userInputs []string) error {
	if zxcvbn.PasswordStrength(password, userInputs).Score < MinPasswordScore {
		return ErrWeakPassword
	}
	return nil
}

// HashPassword hashes a plaintext password using bcrypt.
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return string(hash), nil
}

// CheckPassword compares a plaintext password with a bcrypt hash.
// Returns nil on success, error on mismatch.
func CheckPassword(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

// GenerateTempPassword returns a random, high-entropy temporary password
// (lowercase base32, 24 chars). Used for admin-provisioned users and the
// `airlock auth reset` break-glass; the recipient is forced to change it or
// register a passkey on first login. It comfortably clears MinPasswordScore.
func GenerateTempPassword() (string, error) {
	b := make([]byte, 15) // 15 bytes → 24 base32 chars, ~120 bits
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate temp password: %w", err)
	}
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)), nil
}
