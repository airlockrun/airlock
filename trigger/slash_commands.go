package trigger

import (
	"context"
	"strings"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/service/slashcommands"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

type SlashCommand = slashcommands.SlashCommand
type SlashCommandResult = slashcommands.SlashCommandResult
type SlashConv = slashcommands.SlashConv

// Registry supplies platform command-menu metadata from the command service.
var Registry = slashcommands.Registry

type RunCanceler interface {
	CancelRun(runID uuid.UUID) bool
}

func TrySlashCommand(ctx context.Context, conv SlashConv, convID pgtype.UUID, access agentsdk.Access, message string) (SlashCommandResult, error) {
	return slashcommands.TrySlashCommand(ctx, conv, convID, access, message)
}

func isStartCommand(text string) bool {
	fields := strings.Fields(strings.TrimSpace(text))
	if len(fields) == 0 {
		return false
	}
	cmd := fields[0]
	if at := strings.IndexByte(cmd, '@'); at >= 0 {
		cmd = cmd[:at]
	}
	return strings.EqualFold(cmd, "/start")
}
