package storage

import (
	"errors"
	"path"
	"strings"
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
	if strings.ContainsRune(p, 0) {
		return "", errors.New("nul byte in path")
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
	return cleaned, nil
}
