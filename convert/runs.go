package convert

import (
	"encoding/json"

	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/types/known/structpb"
)

// RunToProto maps a Run row to the wire RunInfo. The detail flag
// controls whether heavy fields (input payload, action timeline,
// stdout log, panic trace) are populated; list endpoints leave them
// off, detail endpoints turn them on.
func RunToProto(r dbq.Run, detail bool) *airlockv1.RunInfo {
	info := &airlockv1.RunInfo{
		Id:              PgUUIDToString(r.ID),
		AgentId:         PgUUIDToString(r.AgentID),
		BridgeId:        PgUUIDToString(r.BridgeID),
		Status:          r.Status,
		StartedAt:       PgTimestampToProto(r.StartedAt),
		FinishedAt:      PgTimestampToProto(r.FinishedAt),
		DurationMs:      r.DurationMs.Int32,
		ErrorMessage:    r.ErrorMessage,
		ErrorKind:       r.ErrorKind,
		LlmTokensIn:     r.LlmTokensIn,
		LlmTokensOut:    r.LlmTokensOut,
		LlmTokensCached: r.LlmTokensCached,
		LlmCostEstimate: PgNumericToFloat(r.LlmCostEstimate),
		SourceRef:       r.SourceRef,
		TriggerType:     r.TriggerType,
	}
	if detail {
		info.InputPayload = JSONToStruct(r.InputPayload)
		info.Actions = JSONToListValue(r.Actions)
		info.StdoutLog = r.StdoutLog
		info.PanicTrace = r.PanicTrace
	}
	return info
}

// JSONToStruct decodes a JSON object blob into a protobuf Struct,
// treating empty / "{}" / "null" as absent.
func JSONToStruct(data []byte) *structpb.Struct {
	if len(data) == 0 || string(data) == "{}" || string(data) == "null" {
		return nil
	}
	return AnyToStruct(data)
}

// JSONToListValue decodes a JSON array blob into a protobuf
// ListValue, treating empty / "[]" / "null" as absent.
func JSONToListValue(data []byte) *structpb.ListValue {
	if len(data) == 0 || string(data) == "[]" || string(data) == "null" {
		return nil
	}
	var items []any
	if err := json.Unmarshal(data, &items); err != nil {
		return nil
	}
	lv, _ := structpb.NewList(items)
	return lv
}

// PgNumericToFloat reads a pgtype.Numeric as float64. Returns 0 if
// the value isn't representable.
func PgNumericToFloat(n pgtype.Numeric) float64 {
	f, _ := n.Float64Value()
	return f.Float64
}
