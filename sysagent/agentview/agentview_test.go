package agentview

import (
	"testing"

	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
)

func TestStripDropsAndKeeps(t *testing.T) {
	p := &airlockv1.AgentInfo{
		Id:         "11111111-1111-1111-1111-111111111111",
		Slug:       "calories",
		Name:       "Calories",
		Status:     "active",
		BuildModel: "claude-x",
	}
	m := Strip(p, "id", "build_model", "does_not_exist")

	if _, ok := m["id"]; ok {
		t.Error("id should be dropped")
	}
	if _, ok := m["build_model"]; ok {
		t.Error("build_model should be dropped")
	}
	if m["slug"] != "calories" {
		t.Errorf("slug should survive, got %v", m["slug"])
	}
	if m["status"] != "active" {
		t.Errorf("status should survive, got %v", m["status"])
	}
}

func TestAgentDropsUUIDsAndTimestamps(t *testing.T) {
	p := &airlockv1.AgentInfo{
		Id:              "11111111-1111-1111-1111-111111111111",
		Slug:            "calories",
		Name:            "Calories",
		Status:          "active",
		YourAccess:      "admin",
		BuildModel:      "claude-x",
		ExecModel:       "claude-y",
		BuildProviderId: "22222222-2222-2222-2222-222222222222",
		ExecProviderId:  "33333333-3333-3333-3333-333333333333",
		SourceRef:       "deadbeef",
	}
	m := Agent(p)

	for _, gone := range []string{
		"id", "source_ref", "build_model", "exec_model",
		"build_provider_id", "exec_provider_id", "created_at", "updated_at",
	} {
		if _, ok := m[gone]; ok {
			t.Errorf("%q should be dropped from the agent view", gone)
		}
	}
	// Handles + status the LLM needs survive.
	if m["slug"] != "calories" {
		t.Errorf("slug must survive, got %v", m["slug"])
	}
	if m["your_access"] != "admin" {
		t.Errorf("your_access must survive, got %v", m["your_access"])
	}
}
