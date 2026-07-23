package storage

import (
	"errors"
	"path"
	"strings"
	"unicode/utf8"
)

// CleanAgentPath validates and canonicalizes a tenant-relative storage path.
// Returns the cleaned slash-normalized form on success.
//
// Rejects:
//   - empty paths
//   - NUL bytes (S3 key delimiter / shell injection vector)
//   - absolute paths (leading "/")
//   - traversal segments ("..", anything that path.Clean reduces to "." or
//     escapes the prefix)
//   - empty path segments ("//")
//   - backslashes (Windows-style; we operate exclusively in forward-slash space)
//
// The returned path is suitable for concatenation under an "agents/{id}/"
// prefix without further escaping.
func CleanAgentPath(p string) (string, error) {
	if p == "" {
		return "", errors.New("empty path")
	}
	if !utf8.ValidString(p) {
		return "", errors.New("invalid utf-8 in path")
	}
	if strings.ContainsRune(p, '\\') {
		return "", errors.New("backslash in path")
	}
	if strings.HasPrefix(p, "/") {
		return "", errors.New("absolute path")
	}
	if strings.Contains(p, "//") {
		return "", errors.New("empty path segment")
	}
	cleaned := path.Clean(p)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", errors.New("path traversal")
	}
	if strings.HasPrefix(cleaned, "/") {
		return "", errors.New("absolute path after clean")
	}
	if cleaned != p {
		return "", errors.New("path is not canonical")
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return "", errors.New("control character in path")
		}
	}
	return cleaned, nil
}
