package api

import (
	"encoding/json"
	"io"
	"net/http"

	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

var protoMarshal = protojson.MarshalOptions{
	UseProtoNames:   false,
	EmitUnpopulated: true,
}

var protoUnmarshal = protojson.UnmarshalOptions{
	DiscardUnknown: true,
}

func writeProto(w http.ResponseWriter, status int, msg proto.Message) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	b, _ := protoMarshal.Marshal(msg)
	w.Write(b)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeProto(w, status, &airlockv1.ErrorResponse{Error: msg})
}

func decodeProto(r *http.Request, msg proto.Message) error {
	defer r.Body.Close()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	return protoUnmarshal.Unmarshal(b, msg)
}

// pgUUID converts a pgtype.UUID to a google/uuid.UUID.
func pgUUID(u pgtype.UUID) uuid.UUID {
	return uuid.UUID(u.Bytes)
}

// toPgUUID converts a google/uuid.UUID to a pgtype.UUID.
func toPgUUID(u uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: u, Valid: true}
}

func parseUUID(s string) (uuid.UUID, error) {
	return uuid.Parse(s)
}

// parseOptionalProviderID accepts an empty string (returns invalid pgtype.UUID,
// no error) or a parseable UUID (returns valid pgtype.UUID). Used by the
// model-slot handlers where empty FK ⇄ "no provider bound for this slot".
func parseOptionalProviderID(s string) (pgtype.UUID, error) {
	if s == "" {
		return pgtype.UUID{}, nil
	}
	u, err := uuid.Parse(s)
	if err != nil {
		return pgtype.UUID{}, err
	}
	return toPgUUID(u), nil
}

// --- JSON helpers for /api/agent routes ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func readJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(v)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// pgText wraps a string in a pgtype.Text marked Valid. Use for INSERTs
// or UPDATEs against NULLABLE text columns where empty-string is
// meaningful (e.g. a key with no comment).
func pgText(s string) pgtype.Text {
	return pgtype.Text{String: s, Valid: true}
}

// pgInt4 wraps an int32 as a Valid pgtype.Int4.
func pgInt4(n int32) pgtype.Int4 {
	return pgtype.Int4{Int32: n, Valid: true}
}
