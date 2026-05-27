package execproxy

import "strings"

// ShellQuote wraps s in single quotes for safe inclusion in a POSIX
// shell command line. The remote sshd hands our command string to the
// user's login shell (`$SHELL -c "..."`), so any argument that contains
// whitespace, glob characters, or shell metacharacters must be quoted
// to avoid being re-split on the remote side.
//
// Single-quoting handles every metacharacter except `'` itself; we
// escape an embedded apostrophe by closing the quote, emitting an
// escaped `'`, and reopening the quote: don't  →  'don'\”t'
func ShellQuote(s string) string {
	if s == "" {
		return "''"
	}
	if !needsQuoting(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('\'')
	for _, r := range s {
		if r == '\'' {
			b.WriteString(`'\''`)
		} else {
			b.WriteRune(r)
		}
	}
	b.WriteByte('\'')
	return b.String()
}

// needsQuoting reports whether s contains any character that would be
// interpreted by a POSIX shell. We keep the "safe" set deliberately
// narrow — false positives just produce extra quotes, false negatives
// produce shell injection.
func needsQuoting(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '_' || r == '-' || r == '.' || r == '/' || r == ':' || r == '=' || r == '@' || r == ',' || r == '+':
		default:
			return true
		}
	}
	return false
}

// JoinCommand assembles command + args into a single shell command line
// suitable for SSH exec. Args are shell-quoted; command is not — pipes,
// redirection, and shell substitution in command pass through to the
// remote shell unchanged. This is the semantic of `ssh user@host cmd a1 a2`:
// the SSH client joins everything with spaces and the remote shell does
// the parsing.
func JoinCommand(command string, args []string) string {
	if len(args) == 0 {
		return command
	}
	var b strings.Builder
	b.Grow(len(command) + len(args)*16)
	b.WriteString(command)
	for _, a := range args {
		b.WriteByte(' ')
		b.WriteString(ShellQuote(a))
	}
	return b.String()
}
