package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
)

func runAuth(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "airlock auth: missing subcommand (try: airlock auth unlock <email>)")
		os.Exit(2)
	}
	switch args[0] {
	case "unlock":
		runAuthUnlock(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "airlock auth: unknown subcommand %q\n", args[0])
		os.Exit(2)
	}
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

