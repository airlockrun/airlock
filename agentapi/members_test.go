package agentapi

import (
	"testing"

	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestAgentMembersReturnsOnlySafeRosterFields(t *testing.T) {
	userID := uuid.MustParse("4d9c4eb3-5661-4a8f-bcde-ea6f47988ea6")
	groupID := uuid.MustParse("afbf6e02-b244-4eef-b621-213ed70d8de5")
	members := agentMembers([]dbq.ListAgentGrantsRow{
		{GranteeID: pgtype.UUID{Bytes: userID, Valid: true}, Kind: "user", Role: "admin", Email: "private@example.test", DisplayName: "Private"},
		{GranteeID: pgtype.UUID{Bytes: groupID, Valid: true}, Kind: "group", Role: "public"},
	})

	if len(members) != 2 {
		t.Fatalf("len(members) = %d, want 2", len(members))
	}
	if got, want := members[0], (agentMember{ID: userID.String(), Kind: "user", Role: "admin"}); got != want {
		t.Fatalf("members[0] = %#v, want %#v", got, want)
	}
	if got, want := members[1], (agentMember{ID: groupID.String(), Kind: "group", Role: "public"}); got != want {
		t.Fatalf("members[1] = %#v, want %#v", got, want)
	}
}
