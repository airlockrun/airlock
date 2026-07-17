package agentapi

import (
	"context"
	"errors"
	"testing"

	"github.com/airlockrun/airlock/db/dbq"
	"github.com/jackc/pgx/v5"
)

func TestParseByteRange(t *testing.T) {
	const size = 100
	tests := []struct {
		name      string
		header    string
		wantStart int64
		wantEnd   int64
		wantOK    bool
	}{
		{"closed range", "bytes=0-9", 0, 9, true},
		{"mid range", "bytes=10-19", 10, 19, true},
		{"open-ended", "bytes=50-", 50, 99, true},
		{"end clamped to size", "bytes=90-200", 90, 99, true},
		{"suffix last N", "bytes=-10", 90, 99, true},
		{"suffix larger than file", "bytes=-500", 0, 99, true},
		{"single byte", "bytes=0-0", 0, 0, true},

		{"missing prefix", "0-9", 0, 0, false},
		{"start past end", "bytes=100-105", 0, 0, false},
		{"start beyond size", "bytes=150-160", 0, 0, false},
		{"end before start", "bytes=20-10", 0, 0, false},
		{"multi-range unsupported", "bytes=0-9,20-29", 0, 0, false},
		{"garbage", "bytes=abc", 0, 0, false},
		{"no dash", "bytes=10", 0, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start, end, ok := parseByteRange(tt.header, size)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if ok && (start != tt.wantStart || end != tt.wantEnd) {
				t.Fatalf("got [%d,%d], want [%d,%d]", start, end, tt.wantStart, tt.wantEnd)
			}
		})
	}
}

func TestParseByteRangeEmptyObject(t *testing.T) {
	if _, _, ok := parseByteRange("bytes=0-0", 0); ok {
		t.Fatal("a range against a zero-length object must be unsatisfiable")
	}
	if _, _, ok := parseByteRange("bytes=-5", 0); ok {
		t.Fatal("a suffix range against a zero-length object must be unsatisfiable")
	}
}

func TestGetDirectoryByPathMatchesPathSegments(t *testing.T) {
	skipIfNoDB(t)
	agentID, _ := testAgentAndUser(t)
	q := dbq.New(testDB.Pool())
	ctx := context.Background()

	for _, path := range []string{"foo", "foo/bar"} {
		if err := q.UpsertDirectory(ctx, dbq.UpsertDirectoryParams{
			AgentID:     toPgUUID(agentID),
			Path:        path,
			ReadAccess:  "public",
			WriteAccess: "admin",
			ListAccess:  "user",
			Scope:       "agent",
		}); err != nil {
			t.Fatalf("UpsertDirectory(%q): %v", path, err)
		}
	}

	tests := []struct {
		name     string
		path     string
		wantPath string
		wantNone bool
	}{
		{name: "exact", path: "foo", wantPath: "foo"},
		{name: "child", path: "foo/file.txt", wantPath: "foo"},
		{name: "longest nested", path: "foo/bar/file.txt", wantPath: "foo/bar"},
		{name: "partial segment", path: "foobar/file.txt", wantNone: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir, err := q.GetDirectoryByPath(ctx, dbq.GetDirectoryByPathParams{
				AgentID: toPgUUID(agentID),
				Path:    tt.path,
			})
			if tt.wantNone {
				if !errors.Is(err, pgx.ErrNoRows) {
					t.Fatalf("GetDirectoryByPath(%q) error = %v, want pgx.ErrNoRows", tt.path, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("GetDirectoryByPath(%q): %v", tt.path, err)
			}
			if dir.Path != tt.wantPath {
				t.Fatalf("GetDirectoryByPath(%q).Path = %q, want %q", tt.path, dir.Path, tt.wantPath)
			}
		})
	}
}
