package agents

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// scpLikeGitRe matches the scp-style SSH clone URL git accepts:
// [user@]host:path — e.g. git@github.com:owner/repo.git.
var scpLikeGitRe = regexp.MustCompile(`^[^@/\s]+@([^:/\s]+):(.+)$`)

// normalizeGitRemoteURL converts a habitual SSH clone URL to its HTTPS
// equivalent and rejects anything that isn't an http(s) remote. Our git
// credentials are PATs, which only authenticate over HTTPS (Basic auth via
// http.extraheader) — an SSH remote has no usable auth and would fail at push.
// Normalizes the two common SSH shapes so a pasted clone URL just works:
//
//	git@host:owner/repo(.git)            -> https://host/owner/repo(.git)
//	ssh://[user@]host[:port]/owner/repo  -> https://host/owner/repo
func normalizeGitRemoteURL(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("git remote URL is required")
	}
	if !strings.Contains(s, "://") {
		if m := scpLikeGitRe.FindStringSubmatch(s); m != nil {
			return "https://" + m[1] + "/" + strings.TrimPrefix(m[2], "/"), nil
		}
		return "", fmt.Errorf("git remote must be an https URL")
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", fmt.Errorf("git remote must be an https URL")
	}
	switch u.Scheme {
	case "http", "https":
		return s, nil
	case "ssh":
		return "https://" + u.Hostname() + u.Path, nil
	default:
		return "", fmt.Errorf("git remote must be an https URL, got %q scheme", u.Scheme)
	}
}
