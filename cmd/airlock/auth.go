package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/mail"
	"os"
	"strings"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/jackc/pgx/v5/pgtype"
)

func runAuth(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "airlock auth: missing subcommand (try: airlock auth unlock <email> | airlock auth reset <email> | airlock auth provision --admin <email>)")
		os.Exit(2)
	}
	switch args[0] {
	case "unlock":
		runAuthUnlock(args[1:])
	case "reset":
		runAuthReset(args[1:])
	case "provision":
		runAuthProvision(args[1:])
	case "set-password":
		runAuthSetPassword(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "airlock auth: unknown subcommand %q\n", args[0])
		os.Exit(2)
	}
}

// runAuthSetPassword updates a known user's password from stdin. Keeping the
// value on stdin makes the host-only recovery path usable without putting a
// credential in an argv list, a shell history entry, or a service log.
func runAuthSetPassword(args []string) {
	fs := flag.NewFlagSet("auth set-password", flag.ExitOnError)
	stdin := fs.Bool("stdin", false, "read one password from standard input (required)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: airlock auth set-password --stdin <email>")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if !*stdin || fs.NArg() != 1 {
		fs.Usage()
		os.Exit(2)
	}
	email := strings.TrimSpace(fs.Arg(0))
	parsed, err := mail.ParseAddress(email)
	if err != nil || parsed.Address != email {
		fmt.Fprintln(os.Stderr, "airlock auth set-password: a single valid email address is required")
		os.Exit(2)
	}

	// A password is a single line. Bound the input before hashing so a bad
	// pipe cannot consume unbounded memory in this host recovery command.
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 4097))
	if err != nil || len(raw) == 0 || len(raw) > 4096 {
		fmt.Fprintln(os.Stderr, "airlock auth set-password: read one non-empty password from stdin")
		os.Exit(2)
	}
	password := strings.TrimSuffix(strings.TrimSuffix(string(raw), "\n"), "\r")
	if password == "" || strings.ContainsAny(password, "\r\n") {
		fmt.Fprintln(os.Stderr, "airlock auth set-password: password must be one non-empty line")
		os.Exit(2)
	}
	if err := auth.ValidatePasswordStrength(password, []string{email, strings.SplitN(email, "@", 2)[0]}); err != nil {
		fmt.Fprintf(os.Stderr, "airlock auth set-password: %v\n", err)
		os.Exit(2)
	}

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		fmt.Fprintln(os.Stderr, "airlock auth set-password: DATABASE_URL is not set")
		os.Exit(1)
	}
	ctx := context.Background()
	database := db.New(ctx, dbURL)
	defer database.Close()
	q := dbq.New(database.Pool())
	user, err := q.GetUserByEmail(ctx, email)
	if err != nil {
		fmt.Fprintf(os.Stderr, "airlock auth set-password: no user with email %q\n", email)
		os.Exit(1)
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hash password: %v\n", err)
		os.Exit(1)
	}
	if _, err := q.UpdateUserPasswordAndRevokeSessions(ctx, dbq.UpdateUserPasswordAndRevokeSessionsParams{
		PasswordHash: pgtype.Text{String: hash, Valid: true},
		ID:           user.ID,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "airlock auth set-password: update password: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stdout, "Password updated.")
}

// runAuthProvision creates a host-authorized administrator with a one-time
// temporary password. It is deliberately separate from the authenticated
// users API: this is a break-glass recovery path for an owner who no longer
// has an administrator session. The password is printed only to stdout so an
// operator can route it through an appropriate secret-safe channel.
func runAuthProvision(args []string) {
	fs := flag.NewFlagSet("auth provision", flag.ExitOnError)
	admin := fs.Bool("admin", false, "create an administrator (required)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: airlock auth provision --admin <email>")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if !*admin || fs.NArg() != 1 {
		fs.Usage()
		os.Exit(2)
	}

	email := strings.TrimSpace(fs.Arg(0))
	parsed, err := mail.ParseAddress(email)
	if err != nil || parsed.Address != email {
		fmt.Fprintln(os.Stderr, "airlock auth provision: a single valid email address is required")
		os.Exit(2)
	}
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		fmt.Fprintln(os.Stderr, "airlock auth provision: DATABASE_URL is not set")
		os.Exit(1)
	}

	temp, err := auth.GenerateTempPassword()
	if err != nil {
		fmt.Fprintf(os.Stderr, "generate temp password: %v\n", err)
		os.Exit(1)
	}
	hash, err := auth.HashPassword(temp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hash password: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()
	database := db.New(ctx, dbURL)
	defer database.Close()
	_, err = dbq.New(database.Pool()).CreateUser(ctx, dbq.CreateUserParams{
		Email:              email,
		DisplayName:        strings.SplitN(email, "@", 2)[0],
		PasswordHash:       pgtype.Text{String: hash, Valid: true},
		TenantRole:         "admin",
		MustChangePassword: true,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "airlock auth provision: create administrator: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Temporary password for %s:\n\n    %s\n\nLog in with it once; you'll be required to set a new password or register a passkey.\n", email, temp)
}

// runAuthReset sets a one-time temporary password for any user and prints it to
// stdout. The user is forced to change it (or register a passkey) on first
// login. Operator-only break-glass: it needs DATABASE_URL, which only someone
// with host access has. Covers a locked-out admin who lost their passkey.
func runAuthReset(args []string) {
	fs := flag.NewFlagSet("auth reset", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: airlock auth reset <email>")
	}
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(2)
	}
	email := fs.Arg(0)

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		fmt.Fprintln(os.Stderr, "airlock auth reset: DATABASE_URL is not set")
		os.Exit(1)
	}

	ctx := context.Background()
	database := db.New(ctx, dbURL)
	defer database.Close()
	q := dbq.New(database.Pool())

	user, err := q.GetUserByEmail(ctx, email)
	if err != nil {
		fmt.Fprintf(os.Stderr, "airlock auth reset: no user with email %q\n", email)
		os.Exit(1)
	}

	temp, err := auth.GenerateTempPassword()
	if err != nil {
		fmt.Fprintf(os.Stderr, "generate temp password: %v\n", err)
		os.Exit(1)
	}
	hash, err := auth.HashPassword(temp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hash password: %v\n", err)
		os.Exit(1)
	}
	if err := q.SetTempPassword(ctx, dbq.SetTempPasswordParams{
		PasswordHash: pgtype.Text{String: hash, Valid: true},
		ID:           user.ID,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "set temp password: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Temporary password for %s:\n\n    %s\n\nLog in with it once; you'll be required to set a new password or register a passkey.\n", email, temp)
}

func runAuthUnlock(args []string) {
	fs := flag.NewFlagSet("auth unlock", flag.ExitOnError)
	ipFlag := fs.String("ip", "", "narrow the unlock to a specific (email, ip) bucket; pass the same IP form NormalizeIP would produce (raw IPv4, IPv6 /64 prefix, or 'unknown')")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: airlock auth unlock <email> [--ip <ip>]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(2)
	}
	email := fs.Arg(0)

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		fmt.Fprintln(os.Stderr, "airlock auth unlock: DATABASE_URL is not set")
		os.Exit(1)
	}

	ctx := context.Background()
	database := db.New(ctx, dbURL)
	defer database.Close()
	q := dbq.New(database.Pool())

	if *ipFlag != "" {
		if err := q.ClearAuthFailures(ctx, dbq.ClearAuthFailuresParams{Email: email, Ip: *ipFlag}); err != nil {
			fmt.Fprintf(os.Stderr, "clear failures: %v\n", err)
			os.Exit(1)
		}
		if err := q.ClearAuthLockout(ctx, dbq.ClearAuthLockoutParams{Email: email, Ip: *ipFlag}); err != nil {
			fmt.Fprintf(os.Stderr, "clear lockout: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("cleared lockout for %s @ %s\n", email, *ipFlag)
		return
	}

	failures, err := q.ClearAuthFailuresByEmail(ctx, email)
	if err != nil {
		fmt.Fprintf(os.Stderr, "clear failures: %v\n", err)
		os.Exit(1)
	}
	lockouts, err := q.ClearAuthLockoutsByEmail(ctx, email)
	if err != nil {
		fmt.Fprintf(os.Stderr, "clear lockouts: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("cleared %d lockout(s) and %d failure record(s) for %s\n", lockouts, failures, email)
}
