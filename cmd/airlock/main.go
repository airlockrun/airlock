package main

import (
	"fmt"
	"io"
	"os"
)

const usage = `airlock — agent runtime + admin CLI

Usage:
  airlock <command> [args...]

Commands:
  serve                       Start the HTTP server (config from env).
  auth unlock <email>         Clear lockouts/failures for an email.
                              --ip <ip>  narrow to one (email, ip) bucket.
  help                        Show this help.

All commands read DATABASE_URL (and the rest of airlock's env) the same way.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, rest := os.Args[1], os.Args[2:]
	switch cmd {
	case "serve":
		runServe(rest)
	case "auth":
		runAuth(rest)
	case "help", "-h", "--help":
		printUsage(os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "airlock: unknown command %q\n\n", cmd)
		printUsage(os.Stderr)
		os.Exit(2)
	}
}

func printUsage(w io.Writer) {
	fmt.Fprint(w, usage)
}
