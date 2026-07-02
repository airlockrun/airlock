package modelresolve

import (
	"testing"

	"github.com/airlockrun/airlock/db/dbq"
	"github.com/jackc/pgx/v5/pgtype"
)

func fk(valid bool) pgtype.UUID { return pgtype.UUID{Bytes: [16]byte{1}, Valid: valid} }

func TestEffectiveForCapability(t *testing.T) {
	agent := dbq.Agent{
		ExecProviderID: fk(true), ExecModel: "agent-exec",
		// vision override left unset → should fall to the system default
	}
	settings := dbq.SystemSetting{
		DefaultExecProviderID: fk(true), DefaultExecModel: "sys-exec",
		DefaultVisionProviderID: fk(true), DefaultVisionModel: "sys-vision",
	}

	if _, m := EffectiveForCapability(agent, settings, "text"); m != "agent-exec" {
		t.Errorf("text: agent override should win, got %q", m)
	}
	if _, m := EffectiveForCapability(agent, settings, "vision"); m != "sys-vision" {
		t.Errorf("vision: should fall to system default, got %q", m)
	}
}

func TestEffectiveForSlot(t *testing.T) {
	agent := dbq.Agent{ExecProviderID: fk(true), ExecModel: "agent-exec"}
	settings := dbq.SystemSetting{
		DefaultExecProviderID: fk(true), DefaultExecModel: "sys-exec",
		DefaultImageGenProviderID: fk(true), DefaultImageGenModel: "sys-image",
	}

	bound := dbq.AgentModelSlot{Slug: "s", Capability: "image", AssignedProviderID: fk(true), AssignedModel: "pinned"}
	if _, m := EffectiveForSlot(agent, settings, bound); m != "pinned" {
		t.Errorf("bound slot should use its assignment, got %q", m)
	}

	// Unbound text slot → agent exec override, then system default.
	unboundText := dbq.AgentModelSlot{Slug: "s", Capability: "text"}
	if _, m := EffectiveForSlot(agent, settings, unboundText); m != "agent-exec" {
		t.Errorf("unbound text slot should inherit agent exec, got %q", m)
	}

	// Unbound image slot with no agent override → system image default.
	unboundImage := dbq.AgentModelSlot{Slug: "s", Capability: "image"}
	if _, m := EffectiveForSlot(agent, settings, unboundImage); m != "sys-image" {
		t.Errorf("unbound image slot should inherit system image default, got %q", m)
	}
}
