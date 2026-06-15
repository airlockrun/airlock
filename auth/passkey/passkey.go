// Package passkey wraps go-webauthn for airlock's human login. It builds the
// relying-party instance from the deployment's public URL and adapts an airlock
// user to the webauthn.User interface. The ceremony state, credential storage,
// and HTTP handlers live in service/passkeys and api — this package is the thin
// library binding with no airlock dependencies.
package passkey

import (
	"fmt"
	"net/url"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// New builds the WebAuthn relying party from airlock's public URL. The RP ID is
// the URL host without scheme or port; the sole permitted origin is the public
// URL's scheme://host[:port]. Both are baked into every credential at
// registration, so PUBLIC_URL's host must stay stable for a deployment — a host
// change invalidates all enrolled passkeys.
//
// Discoverable (resident) keys and user verification are required: resident keys
// enable usernameless "sign in with a passkey", and user verification means the
// authenticator proves presence with a biometric or PIN, not mere possession.
func New(publicURL string) (*webauthn.WebAuthn, error) {
	u, err := url.Parse(publicURL)
	if err != nil {
		return nil, fmt.Errorf("parse public url %q: %w", publicURL, err)
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("public url %q has no host", publicURL)
	}
	return webauthn.New(&webauthn.Config{
		RPID:          u.Hostname(),
		RPDisplayName: "Airlock",
		RPOrigins:     []string{u.Scheme + "://" + u.Host},
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		},
	})
}
