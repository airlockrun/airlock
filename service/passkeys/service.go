// Package passkeys owns the per-user WebAuthn surface: registering, listing,
// renaming, and deleting the caller's own passkeys, plus setting and removing
// the caller's password. It also drives the public login ceremony (begin /
// finish), which has no principal yet.
//
// Ceremony challenge state lives in the webauthn_ceremonies table (short-lived,
// single-use) so a multi-replica deployment can finish a ceremony on a
// different instance than began it. Every credential a user owns is one row in
// webauthn_credentials; the raw public key never leaves the backend.
package passkeys

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/auth/passkey"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// ErrNeedsReauth is returned by the login finish path when the assertion is
// invalid — the handler maps it to 401.
var ErrNeedsReauth = errors.New("passkey assertion failed")

// Service is the per-user passkey + password layer. Authenticated methods gate
// on TenantSelfPasskeyManage (any user manages their own); the login ceremony
// is public.
type Service struct {
	db       *db.DB
	webAuthn *webauthn.WebAuthn
	logger   *zap.Logger
}

func New(d *db.DB, w *webauthn.WebAuthn, logger *zap.Logger) *Service {
	if d == nil {
		panic("passkeys: db is required")
	}
	if w == nil {
		panic("passkeys: webauthn is required")
	}
	if logger == nil {
		panic("passkeys: logger is required")
	}
	return &Service{db: d, webAuthn: w, logger: logger}
}

// Passkey is the wire shape the handler sees — display metadata only, never the
// public key or raw credential id.
type Passkey struct {
	ID             uuid.UUID
	FriendlyName   string
	CreatedAt      pgtype.Timestamptz
	LastUsedAt     pgtype.Timestamptz
	BackupEligible bool
}

// LoginResult carries the identity a successful assertion resolved to, enough
// for the handler to mint tokens without re-reading the row.
type LoginResult struct {
	UserID             uuid.UUID
	Email              string
	TenantRole         string
	MustChangePassword bool
}

// List returns the caller's passkeys, oldest first.
func (s *Service) List(ctx context.Context, p authz.Principal) ([]Passkey, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.TenantSelfPasskeyManage, uuid.Nil); err != nil {
		return nil, err
	}
	rows, err := q.ListCredentialsByUserID(ctx, pgtype.UUID{Bytes: p.UserID, Valid: true})
	if err != nil {
		s.logger.Error("list passkeys failed", zap.Error(err))
		return nil, err
	}
	out := make([]Passkey, len(rows))
	for i, r := range rows {
		out[i] = passkeyDTO(r)
	}
	return out, nil
}

// RegisterBegin starts a registration ceremony for the caller. The returned
// options are handed to the browser; ceremonyID must be echoed to
// RegisterFinish.
func (s *Service) RegisterBegin(ctx context.Context, p authz.Principal) (ceremonyID string, options *protocol.CredentialCreation, err error) {
	q := dbq.New(s.db.Pool())
	if err = authz.Authorize(ctx, q, p, authz.TenantSelfPasskeyManage, uuid.Nil); err != nil {
		return "", nil, err
	}
	user, _, err := s.loadWebauthnUser(ctx, q, p.UserID)
	if err != nil {
		return "", nil, err
	}
	// Exclude the user's existing authenticators so the same device can't be
	// registered twice.
	excl := make([]protocol.CredentialDescriptor, 0, len(user.WebAuthnCredentials()))
	for _, c := range user.WebAuthnCredentials() {
		excl = append(excl, c.Descriptor())
	}
	options, session, err := s.webAuthn.BeginRegistration(user, webauthn.WithExclusions(excl))
	if err != nil {
		s.logger.Error("begin registration failed", zap.Error(err))
		return "", nil, err
	}
	id, err := s.createCeremony(ctx, q, p.UserID, "register", session)
	if err != nil {
		return "", nil, err
	}
	return id, options, nil
}

// RegisterFinish completes a registration ceremony. The attestation is read
// straight from r.Body by go-webauthn; ceremonyID and friendlyName come from
// the query string. Registering a passkey also clears must_change_password —
// it satisfies the "secure your account" requirement.
func (s *Service) RegisterFinish(ctx context.Context, p authz.Principal, ceremonyID, friendlyName string, r *http.Request) (Passkey, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.TenantSelfPasskeyManage, uuid.Nil); err != nil {
		return Passkey{}, err
	}
	session, row, err := s.consumeCeremony(ctx, q, ceremonyID, "register")
	if err != nil {
		return Passkey{}, err
	}
	if uuid.UUID(row.UserID.Bytes) != p.UserID {
		return Passkey{}, service.Detail(service.ErrInvalidInput, "ceremony does not belong to this user")
	}
	user, dbUser, err := s.loadWebauthnUser(ctx, q, p.UserID)
	if err != nil {
		return Passkey{}, err
	}
	cred, err := s.webAuthn.FinishRegistration(user, *session, r)
	if err != nil {
		return Passkey{}, service.Detail(service.ErrInvalidInput, "registration verification failed")
	}

	name := strings.TrimSpace(friendlyName)
	if name == "" {
		name = "Passkey"
	}
	created, err := q.CreateCredential(ctx, credToParams(p.UserID, name, cred))
	if err != nil {
		s.logger.Error("create credential failed", zap.Error(err))
		return Passkey{}, err
	}
	if dbUser.MustChangePassword {
		if err := q.ClearMustChangePassword(ctx, pgtype.UUID{Bytes: p.UserID, Valid: true}); err != nil {
			s.logger.Error("clear must_change_password failed", zap.Error(err))
			return Passkey{}, err
		}
	}
	return passkeyDTO(created), nil
}

// Rename relabels one of the caller's passkeys. Owner-scoped at the query level.
func (s *Service) Rename(ctx context.Context, p authz.Principal, id uuid.UUID, name string) error {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.TenantSelfPasskeyManage, uuid.Nil); err != nil {
		return err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return service.Detail(service.ErrInvalidInput, "name is required")
	}
	return q.RenameCredential(ctx, dbq.RenameCredentialParams{
		FriendlyName: name,
		ID:           pgtype.UUID{Bytes: id, Valid: true},
		UserID:       pgtype.UUID{Bytes: p.UserID, Valid: true},
	})
}

// Delete removes one of the caller's passkeys, refusing to remove the last
// sign-in credential (a user with no passkey and no password could never log
// in again).
func (s *Service) Delete(ctx context.Context, p authz.Principal, id uuid.UUID) error {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.TenantSelfPasskeyManage, uuid.Nil); err != nil {
		return err
	}
	count, err := q.CountCredentialsByUserID(ctx, pgtype.UUID{Bytes: p.UserID, Valid: true})
	if err != nil {
		return err
	}
	hasPassword, err := s.userHasPassword(ctx, q, p.UserID)
	if err != nil {
		return err
	}
	if count <= 1 && !hasPassword {
		return service.Detail(service.ErrInvalidInput, "cannot remove your last sign-in credential; add a password or another passkey first")
	}
	return q.DeleteCredential(ctx, dbq.DeleteCredentialParams{
		ID:     pgtype.UUID{Bytes: id, Valid: true},
		UserID: pgtype.UUID{Bytes: p.UserID, Valid: true},
	})
}

// SetPassword sets or replaces the caller's password (strength-checked) and
// clears must_change_password — securing the account.
func (s *Service) SetPassword(ctx context.Context, p authz.Principal, password string) error {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.TenantSelfPasskeyManage, uuid.Nil); err != nil {
		return err
	}
	user, err := q.GetUserByID(ctx, pgtype.UUID{Bytes: p.UserID, Valid: true})
	if err != nil {
		return service.ErrNotFound
	}
	if err := auth.ValidatePasswordStrength(password, []string{user.Email, user.DisplayName}); err != nil {
		return service.Detail(service.ErrInvalidInput, "%s", err.Error())
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		s.logger.Error("hash password failed", zap.Error(err))
		return err
	}
	return q.UpdateUserPassword(ctx, dbq.UpdateUserPasswordParams{
		PasswordHash: pgtype.Text{String: hash, Valid: true},
		ID:           pgtype.UUID{Bytes: p.UserID, Valid: true},
	})
}

// RemovePassword clears the caller's password, refusing if it would leave no
// sign-in credential (no passkey registered).
func (s *Service) RemovePassword(ctx context.Context, p authz.Principal) error {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.TenantSelfPasskeyManage, uuid.Nil); err != nil {
		return err
	}
	count, err := q.CountCredentialsByUserID(ctx, pgtype.UUID{Bytes: p.UserID, Valid: true})
	if err != nil {
		return err
	}
	if count == 0 {
		return service.Detail(service.ErrInvalidInput, "cannot remove your password without a passkey; register one first")
	}
	return q.ClearUserPassword(ctx, pgtype.UUID{Bytes: p.UserID, Valid: true})
}

// LoginBegin starts a login ceremony. An empty email starts a usernameless
// (discoverable) login; a known email scopes to that user's credentials. An
// unknown email falls back to discoverable so the response shape doesn't reveal
// whether the account exists.
func (s *Service) LoginBegin(ctx context.Context, email string) (ceremonyID string, options *protocol.CredentialAssertion, err error) {
	q := dbq.New(s.db.Pool())
	email = strings.TrimSpace(email)

	var (
		session *webauthn.SessionData
		userID  uuid.UUID
	)
	if email != "" {
		// airlockvet:allow-dbq reason: pre-Principal passkey login — runs before authz can apply, gated by the WebAuthn assertion at finish
		if u, gErr := q.GetUserByEmail(ctx, email); gErr == nil {
			user, _, lErr := s.loadWebauthnUser(ctx, q, uuid.UUID(u.ID.Bytes))
			if lErr != nil {
				return "", nil, lErr
			}
			options, session, err = s.webAuthn.BeginLogin(user)
			userID = uuid.UUID(u.ID.Bytes)
		}
	}
	if session == nil {
		options, session, err = s.webAuthn.BeginDiscoverableLogin()
	}
	if err != nil {
		s.logger.Error("begin login failed", zap.Error(err))
		return "", nil, err
	}
	id, err := s.createCeremony(ctx, q, userID, "login", session)
	if err != nil {
		return "", nil, err
	}
	return id, options, nil
}

// LoginFinish completes a login ceremony and returns the resolved identity. The
// assertion is read from r.Body by go-webauthn. On success the matched
// credential's sign counter is advanced.
func (s *Service) LoginFinish(ctx context.Context, ceremonyID string, r *http.Request) (LoginResult, error) {
	q := dbq.New(s.db.Pool())
	session, row, err := s.consumeCeremony(ctx, q, ceremonyID, "login")
	if err != nil {
		return LoginResult{}, err
	}

	var cred *webauthn.Credential
	if row.UserID.Valid {
		// Email-first: the ceremony is bound to a specific user.
		user, _, lErr := s.loadWebauthnUser(ctx, q, uuid.UUID(row.UserID.Bytes))
		if lErr != nil {
			return LoginResult{}, lErr
		}
		cred, err = s.webAuthn.FinishLogin(user, *session, r)
	} else {
		// Discoverable: resolve the user from the assertion's user handle.
		cred, err = s.webAuthn.FinishDiscoverableLogin(s.discoverableHandler(ctx, q), *session, r)
	}
	if err != nil {
		return LoginResult{}, ErrNeedsReauth
	}

	if err := q.UpdateCredentialSignCount(ctx, dbq.UpdateCredentialSignCountParams{
		CredentialID: cred.ID,
		SignCount:    int64(cred.Authenticator.SignCount),
		CloneWarning: cred.Authenticator.CloneWarning,
		BackupState:  cred.Flags.BackupState,
	}); err != nil {
		s.logger.Error("update sign count failed", zap.Error(err))
	}
	if cred.Authenticator.CloneWarning {
		s.logger.Warn("passkey sign-count regression (possible clone)", zap.Binary("credential_id", cred.ID))
	}

	// Resolve the final identity. For discoverable login the user came from the
	// handler; re-read by credential owner to get the live row.
	owner, err := s.userByCredentialOwner(ctx, q, row, cred)
	if err != nil {
		return LoginResult{}, err
	}
	return LoginResult{
		UserID:             uuid.UUID(owner.ID.Bytes),
		Email:              owner.Email,
		TenantRole:         owner.TenantRole,
		MustChangePassword: owner.MustChangePassword,
	}, nil
}

// GC deletes expired ceremony rows. Safe to call concurrently from any replica.
func (s *Service) GC(ctx context.Context) error {
	return dbq.New(s.db.Pool()).DeleteExpiredCeremonies(ctx)
}

// --- internal helpers ---

func (s *Service) discoverableHandler(ctx context.Context, q *dbq.Queries) webauthn.DiscoverableUserHandler {
	return func(rawID, userHandle []byte) (webauthn.User, error) {
		id, err := uuid.FromBytes(userHandle)
		if err != nil {
			return nil, err
		}
		user, _, err := s.loadWebauthnUser(ctx, q, id)
		if err != nil {
			return nil, err
		}
		return user, nil
	}
}

// userByCredentialOwner returns the live user row for the just-authenticated
// credential. For email-first the ceremony already names the user; for
// discoverable we resolve via the credential's stored owner.
func (s *Service) userByCredentialOwner(ctx context.Context, q *dbq.Queries, row dbq.WebauthnCeremony, cred *webauthn.Credential) (dbq.User, error) {
	if row.UserID.Valid {
		// airlockvet:allow-dbq reason: pre-Principal passkey login — runs before authz can apply, identity proven by the verified assertion
		return q.GetUserByID(ctx, row.UserID)
	}
	// airlockvet:allow-dbq reason: pre-Principal passkey login — runs before authz can apply, identity proven by the verified assertion
	return q.GetUserByCredentialID(ctx, cred.ID)
}

func (s *Service) loadWebauthnUser(ctx context.Context, q *dbq.Queries, userID uuid.UUID) (*passkey.User, dbq.User, error) {
	u, err := q.GetUserByID(ctx, pgtype.UUID{Bytes: userID, Valid: true})
	if err != nil {
		return nil, dbq.User{}, service.ErrNotFound
	}
	rows, err := q.ListCredentialsByUserID(ctx, pgtype.UUID{Bytes: userID, Valid: true})
	if err != nil {
		return nil, dbq.User{}, err
	}
	creds := make([]webauthn.Credential, len(rows))
	for i, r := range rows {
		creds[i] = dbToWebauthnCred(r)
	}
	id := userID // copy so the slice doesn't alias the loop/param storage
	return passkey.NewUser(id[:], u.Email, u.DisplayName, creds), u, nil
}

func (s *Service) userHasPassword(ctx context.Context, q *dbq.Queries, userID uuid.UUID) (bool, error) {
	u, err := q.GetUserByID(ctx, pgtype.UUID{Bytes: userID, Valid: true})
	if err != nil {
		return false, service.ErrNotFound
	}
	return u.PasswordHash.Valid && u.PasswordHash.String != "", nil
}

func (s *Service) createCeremony(ctx context.Context, q *dbq.Queries, userID uuid.UUID, kind string, session *webauthn.SessionData) (string, error) {
	data, err := json.Marshal(session)
	if err != nil {
		return "", err
	}
	var uid pgtype.UUID
	if userID != uuid.Nil {
		uid = pgtype.UUID{Bytes: userID, Valid: true}
	}
	id, err := q.CreateCeremony(ctx, dbq.CreateCeremonyParams{
		UserID:      uid,
		Kind:        kind,
		SessionData: data,
	})
	if err != nil {
		s.logger.Error("create ceremony failed", zap.Error(err))
		return "", err
	}
	return uuid.UUID(id.Bytes).String(), nil
}

func (s *Service) consumeCeremony(ctx context.Context, q *dbq.Queries, ceremonyID, kind string) (*webauthn.SessionData, dbq.WebauthnCeremony, error) {
	id, err := uuid.Parse(ceremonyID)
	if err != nil {
		return nil, dbq.WebauthnCeremony{}, service.Detail(service.ErrInvalidInput, "invalid ceremony id")
	}
	row, err := q.ConsumeCeremony(ctx, pgtype.UUID{Bytes: id, Valid: true})
	if err != nil {
		// No row (or expired) — single-use means a replay lands here too.
		return nil, dbq.WebauthnCeremony{}, service.Detail(service.ErrInvalidInput, "ceremony expired or already used")
	}
	if row.Kind != kind {
		return nil, dbq.WebauthnCeremony{}, service.Detail(service.ErrInvalidInput, "ceremony kind mismatch")
	}
	var session webauthn.SessionData
	if err := json.Unmarshal(row.SessionData, &session); err != nil {
		return nil, dbq.WebauthnCeremony{}, err
	}
	return &session, row, nil
}

func passkeyDTO(r dbq.WebauthnCredential) Passkey {
	return Passkey{
		ID:             uuid.UUID(r.ID.Bytes),
		FriendlyName:   r.FriendlyName,
		CreatedAt:      r.CreatedAt,
		LastUsedAt:     r.LastUsedAt,
		BackupEligible: r.BackupEligible,
	}
}

func credToParams(userID uuid.UUID, name string, cred *webauthn.Credential) dbq.CreateCredentialParams {
	aaguid := cred.Authenticator.AAGUID
	if aaguid == nil {
		aaguid = []byte{}
	}
	return dbq.CreateCredentialParams{
		UserID:          pgtype.UUID{Bytes: userID, Valid: true},
		CredentialID:    cred.ID,
		PublicKey:       cred.PublicKey,
		AttestationType: cred.AttestationType,
		Aaguid:          aaguid,
		SignCount:       int64(cred.Authenticator.SignCount),
		Transports:      transportsToStrings(cred.Transport),
		BackupEligible:  cred.Flags.BackupEligible,
		BackupState:     cred.Flags.BackupState,
		CloneWarning:    cred.Authenticator.CloneWarning,
		FriendlyName:    name,
	}
}

func dbToWebauthnCred(row dbq.WebauthnCredential) webauthn.Credential {
	return webauthn.Credential{
		ID:              row.CredentialID,
		PublicKey:       row.PublicKey,
		AttestationType: row.AttestationType,
		Transport:       stringsToTransports(row.Transports),
		Flags: webauthn.CredentialFlags{
			BackupEligible: row.BackupEligible,
			BackupState:    row.BackupState,
		},
		Authenticator: webauthn.Authenticator{
			AAGUID:       row.Aaguid,
			SignCount:    uint32(row.SignCount),
			CloneWarning: row.CloneWarning,
		},
	}
}

func transportsToStrings(ts []protocol.AuthenticatorTransport) []string {
	out := make([]string, len(ts))
	for i, t := range ts {
		out[i] = string(t)
	}
	return out
}

func stringsToTransports(ss []string) []protocol.AuthenticatorTransport {
	out := make([]protocol.AuthenticatorTransport, len(ss))
	for i, s := range ss {
		out[i] = protocol.AuthenticatorTransport(s)
	}
	return out
}
