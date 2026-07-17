package api

import (
	"context"
	"testing"

	passkeyauth "github.com/airlockrun/airlock/auth/passkey"
	"github.com/airlockrun/airlock/db/dbq"
	passkeysvc "github.com/airlockrun/airlock/service/passkeys"
	"go.uber.org/zap"
)

func TestPasskeyLoginIsAlwaysDiscoverable(t *testing.T) {
	skipIfNoDB(t)
	ctx := context.Background()
	_, userID := testAgentAndUser(t)
	user, err := dbq.New(testDB.Pool()).GetUserByID(ctx, toPgUUID(userID))
	if err != nil {
		t.Fatal(err)
	}
	webAuthn, err := passkeyauth.New("https://airlock.test")
	if err != nil {
		t.Fatal(err)
	}
	svc := passkeysvc.New(testDB, webAuthn, zap.NewNop())

	for _, email := range []string{"", user.Email, "absent@example.com"} {
		_, options, err := svc.LoginBegin(ctx, email)
		if err != nil {
			t.Fatalf("LoginBegin(%q): %v", email, err)
		}
		if len(options.Response.AllowedCredentials) != 0 {
			t.Fatalf("LoginBegin(%q) disclosed %d credentials", email, len(options.Response.AllowedCredentials))
		}
	}
}
