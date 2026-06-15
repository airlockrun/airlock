package passkey

import "github.com/go-webauthn/webauthn/webauthn"

// User adapts an airlock user and its stored credentials to webauthn.User. The
// WebAuthn id is the user's UUID bytes — stable across email/display-name
// changes and used as the discoverable-login user handle. Build one with the
// user's full credential set so go-webauthn can match and exclude correctly.
type User struct {
	id          []byte
	name        string
	displayName string
	creds       []webauthn.Credential
}

// NewUser constructs the webauthn.User adapter. id is the user UUID bytes, name
// is the email, displayName is the human name, and creds are the user's mapped
// credentials (nil for a user with none yet).
func NewUser(id []byte, name, displayName string, creds []webauthn.Credential) *User {
	return &User{id: id, name: name, displayName: displayName, creds: creds}
}

func (u *User) WebAuthnID() []byte                         { return u.id }
func (u *User) WebAuthnName() string                       { return u.name }
func (u *User) WebAuthnDisplayName() string                { return u.displayName }
func (u *User) WebAuthnCredentials() []webauthn.Credential { return u.creds }
