package api

import (
	"context"
	"strings"
	"testing"
)

// setSystemDefaultModel updates one default_*_model column in system_settings.
// Restored to "" by t.Cleanup so tests stay independent.
func setSystemDefaultModel(t *testing.T, column, value string) {
	t.Helper()
	_, err := testDB.Pool().Exec(context.Background(),
		"UPDATE system_settings SET "+column+" = $1 WHERE id = true", value)
	if err != nil {
		t.Fatalf("update %s: %v", column, err)
	}
	t.Cleanup(func() {
		_, _ = testDB.Pool().Exec(context.Background(),
			"UPDATE system_settings SET "+column+" = '' WHERE id = true")
	})
}

func TestResolveModel(t *testing.T) {
	skipIfNoDB(t)

	cases := []struct {
		name        string
		slug        string
		capability  string
		defaultCol  string // system_settings column to seed; "" = none
		defaultVal  string // model slug to put in that column
		execModel   string // agent.exec_model; "" = leave blank
		wantProv    string
		wantModel   string
		wantErrSubs string // substring expected in error; "" = expect success
	}{
		{
			name: "transcription resolves to default_stt_model",
			capability: "transcription",
			defaultCol: "default_stt_model", defaultVal: "openai/whisper-1",
			wantProv: "openai", wantModel: "whisper-1",
		},
		{
			name: "speech resolves to default_tts_model",
			capability: "speech",
			defaultCol: "default_tts_model", defaultVal: "openai/tts-1",
			wantProv: "openai", wantModel: "tts-1",
		},
		{
			name: "image resolves to default_image_gen_model",
			capability: "image",
			defaultCol: "default_image_gen_model", defaultVal: "openai/dall-e-3",
			wantProv: "openai", wantModel: "dall-e-3",
		},
		{
			name: "embedding resolves to default_embedding_model",
			capability: "embedding",
			defaultCol: "default_embedding_model", defaultVal: "openai/text-embedding-3-small",
			wantProv: "openai", wantModel: "text-embedding-3-small",
		},
		{
			name: "vision resolves to default_vision_model",
			capability: "vision",
			defaultCol: "default_vision_model", defaultVal: "openai/gpt-4o",
			wantProv: "openai", wantModel: "gpt-4o",
		},
		{
			name: "empty capability falls back to agent exec_model",
			capability: "",
			execModel: "openai/gpt-4o-mini",
			wantProv: "openai", wantModel: "gpt-4o-mini",
		},
		{
			name: "text capability falls back to agent exec_model",
			capability: "text",
			execModel: "openai/gpt-4o",
			wantProv: "openai", wantModel: "gpt-4o",
		},
		{
			name: "missing capability default returns clear error",
			capability: "transcription",
			wantErrSubs: "no model configured for capability",
		},
		{
			name: "missing exec_model returns clear error",
			capability: "text",
			wantErrSubs: "no model configured for capability",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ah := testAgentHandler()
			agentID, _ := testAgentAndUser(t)

			// All success cases use openai — seed it once with a known key.
			if tc.wantErrSubs == "" {
				seedEnabledProvider(t, "openai", "OpenAI", "sk-test")
			}

			if tc.defaultCol != "" {
				setSystemDefaultModel(t, tc.defaultCol, tc.defaultVal)
			}
			if tc.execModel != "" {
				setAgentExecModel(t, agentID.String(), tc.execModel)
			}

			provID, modelID, apiKey, _, err := ah.resolveModel(
				context.Background(), agentID.String(), tc.slug, tc.capability)

			if tc.wantErrSubs != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got success (provider=%s model=%s)",
						tc.wantErrSubs, provID, modelID)
				}
				if !strings.Contains(err.Error(), tc.wantErrSubs) {
					t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErrSubs)
				}
				return
			}

			if err != nil {
				t.Fatalf("resolveModel: %v", err)
			}
			if provID != tc.wantProv {
				t.Errorf("providerID = %q, want %q", provID, tc.wantProv)
			}
			if modelID != tc.wantModel {
				t.Errorf("modelID = %q, want %q", modelID, tc.wantModel)
			}
			if apiKey != "sk-test" {
				t.Errorf("apiKey = %q, want sk-test (decrypt failed?)", apiKey)
			}
		})
	}
}
