// Package apihelpers carries the low-level HTTP/db utility functions
// shared by airlock's two HTTP surfaces:
//
//   - api/ — operator-facing /api/v1, /auth, /webhooks (user JWT).
//   - agentapi/ — agent-internal /api/agent (agent JWT).
//
// router.go (in api/) wires both surfaces, so api imports agentapi.
// To keep the dep graph acyclic, anything both packages need lives
// here as a leaf: protobuf + JSON readers/writers, pgtype helpers,
// UUID parsing. No trigger / service / dbq imports — pure plumbing.
package apihelpers

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"unicode/utf8"

	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

const MaxRequestBodyBytes int64 = 4 << 20

var ErrRequestBodyTooLarge = errors.New("request body too large")

// ProtoMarshal is the shared protojson encoder. UseProtoNames=false
// emits camelCase (matching the frontend convention) and
// EmitUnpopulated=true keeps zero-valued scalars on the wire so the
// frontend doesn't have to defensively check undefined vs. zero.
var ProtoMarshal = protojson.MarshalOptions{
	UseProtoNames:   false,
	EmitUnpopulated: true,
}

// ProtoUnmarshal is the shared protojson decoder. DiscardUnknown is
// on so a newer frontend pushing fields a stale backend doesn't
// understand isn't a 400.
var ProtoUnmarshal = protojson.UnmarshalOptions{
	DiscardUnknown: true,
}

// WriteProto serializes msg via ProtoMarshal and writes it as
// application/json. Errors from Marshal are swallowed — for proto
// types we control, they don't fail.
func WriteProto(w http.ResponseWriter, status int, msg proto.Message) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	b, _ := ProtoMarshal.Marshal(msg)
	w.Write(b)
}

// WriteError is the shared 4xx/5xx wire shape — an ErrorResponse
// proto with the given message, encoded the same way as any other
// response so the frontend's typed-error path handles it without a
// separate code branch.
func WriteError(w http.ResponseWriter, status int, msg string) {
	WriteProto(w, status, &airlockv1.ErrorResponse{Error: msg})
}

// DecodeProto reads the request body and parses it via the shared
// ProtoUnmarshal options. Closes r.Body when done.
func DecodeProto(r *http.Request, msg proto.Message) error {
	defer r.Body.Close()
	b, err := readBody(r)
	if err != nil {
		return err
	}
	return ProtoUnmarshal.Unmarshal(b, msg)
}

// WriteJSON is the legacy non-proto response writer used by the
// /api/agent surface (where the agentsdk client speaks JSON, not
// proto) and by a couple of operator endpoints that predate the
// proto rollout.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// ReadJSON decodes a non-proto request body. Closes r.Body when
// done.
func ReadJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	b, err := readBody(r)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(v); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return errors.New("request body must contain a single JSON value")
		}
		return err
	}
	return nil
}

func readBody(r *http.Request) ([]byte, error) {
	if r.ContentLength > MaxRequestBodyBytes {
		return nil, ErrRequestBodyTooLarge
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, MaxRequestBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > MaxRequestBodyBytes {
		return nil, ErrRequestBodyTooLarge
	}
	return b, nil
}

// WriteJSONError is WriteError's non-proto twin: a JSON
// {"error": msg} body. Used by handlers whose response shape is JSON
// throughout.
func WriteJSONError(w http.ResponseWriter, status int, msg string) {
	WriteJSON(w, status, map[string]string{"error": msg})
}

// PgUUID converts a pgtype.UUID to a google/uuid.UUID. Returns the
// zero UUID for an invalid pg value — callers that need to
// distinguish NULL from zero should check the Valid flag directly.
func PgUUID(u pgtype.UUID) uuid.UUID {
	return uuid.UUID(u.Bytes)
}

// ToPgUUID converts a google/uuid.UUID to a Valid pgtype.UUID.
func ToPgUUID(u uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: u, Valid: true}
}

// ParseUUID is a thin alias for uuid.Parse — exists for symmetry
// with the other helpers and so handlers don't import google/uuid
// just for one call.
func ParseUUID(s string) (uuid.UUID, error) {
	return uuid.Parse(s)
}

// ParseOptionalProviderID accepts an empty string (returns invalid
// pgtype.UUID, no error) or a parseable UUID (returns Valid
// pgtype.UUID). Used by model-slot handlers where empty FK ⇄ "no
// provider bound for this slot".
func ParseOptionalProviderID(s string) (pgtype.UUID, error) {
	if s == "" {
		return pgtype.UUID{}, nil
	}
	u, err := uuid.Parse(s)
	if err != nil {
		return pgtype.UUID{}, err
	}
	return ToPgUUID(u), nil
}

// PgText wraps a string in a pgtype.Text marked Valid. Use for
// INSERTs or UPDATEs against NULLABLE text columns where empty
// string is meaningful (e.g. a key with no comment).
func PgText(s string) pgtype.Text {
	return pgtype.Text{String: s, Valid: true}
}

// PgInt4 wraps an int32 as a Valid pgtype.Int4.
func PgInt4(n int32) pgtype.Int4 {
	return pgtype.Int4{Int32: n, Valid: true}
}

// TruncateUTF8 clips s to at most maxLen *bytes*, never cutting in
// the middle of a UTF-8 sequence. A naive s[:maxLen] would leave a
// dangling lead byte (e.g. Cyrillic 0xd0 starts a 2-byte rune;
// slicing between the lead and continuation byte produces invalid
// UTF-8 that Postgres rejects with `invalid byte sequence for
// encoding "UTF8"`). Backs off to the previous rune boundary via
// utf8.RuneStart.
func TruncateUTF8(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	for end := maxLen; end > 0; end-- {
		if utf8.RuneStart(s[end]) {
			return s[:end]
		}
	}
	return ""
}
