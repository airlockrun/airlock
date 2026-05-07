package api

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// setSystemDefaultModel binds one capability's system default to (provider
// row UUID, bare model name). The caller passes the *_model column suffix
// (e.g. "stt", "exec"); we update both default_*_model and the FK column
// in lockstep — the schema treats them as a pair. Cleanup resets both.
func setSystemDefaultModel(t *testing.T, capabilitySuffix string, providerRowID uuid.UUID, modelName string) {
	t.Helper()
	modelCol := "default_" + capabilitySuffix + "_model"
	fkCol := "default_" + capabilitySuffix + "_provider_id"
	_, err := testDB.Pool().Exec(context.Background(),
		"UPDATE system_settings SET "+modelCol+" = $1, "+fkCol+" = $2 WHERE id = true",
		modelName, providerRowID)
	if err != nil {
		t.Fatalf("update default %s: %v", capabilitySuffix, err)
	}
	t.Cleanup(func() {
		_, _ = testDB.Pool().Exec(context.Background(),
			"UPDATE system_settings SET "+modelCol+" = '', "+fkCol+" = NULL WHERE id = true")
	})
}

func TestResolveModel(t *testing.T) {
	skipIfNoDB(t)

	// Each case names the capability under test plus where the (provider
	// row, model name) binding lives — either on system_settings via the
	// *_model + *_provider_id pair (capabilitySuffix), or on the agent's
	// exec_provider_id + exec_model pair (execModel).
	cases := []struct {
		name             string
		slug             string
		capability       string
		capabilitySuffix string // e.g. "stt"; "" = don't set system default
		modelName        string // bare model name to bind
		execModel        string // bare model name on agent.exec_model; "" = leave blank
		wantProv         string
		wantModel        string
		wantErrSubs      string
	}{
		{
			name: "transcription resolves to default_stt_*",
			capability:       "transcription",
			capabilitySuffix: "stt", modelName: "whisper-1",
			wantProv: "openai", wantModel: "whisper-1",
		},
		{
			name: "speech resolves to default_tts_*",
			capability:       "speech",
			capabilitySuffix: "tts", modelName: "tts-1",
			wantProv: "openai", wantModel: "tts-1",
		},
		{
			name: "image resolves to default_image_gen_*",
			capability:       "image",
			capabilitySuffix: "image_gen", modelName: "dall-e-3",
			wantProv: "openai", wantModel: "dall-e-3",
		},
		{
			name: "embedding resolves to default_embedding_*",
			capability:       "embedding",
			capabilitySuffix: "embedding", modelName: "text-embedding-3-small",
			wantProv: "openai", wantModel: "text-embedding-3-small",
		},
		{
			name: "vision resolves to default_vision_*",
			capability:       "vision",
			capabilitySuffix: "vision", modelName: "gpt-4o",
			wantProv: "openai", wantModel: "gpt-4o",
		},
		{
			name: "empty capability falls back to agent exec_*",
			capability: "",
			execModel:  "gpt-4o-mini",
			wantProv:   "openai", wantModel: "gpt-4o-mini",
		},
		{
			name: "text capability falls back to agent exec_*",
			capability: "text",
			execModel:  "gpt-4o",
			wantProv:   "openai", wantModel: "gpt-4o",
		},
		{
			name: "missing capability default returns clear error",
			capability:  "transcription",
			wantErrSubs: "no model configured for capability",
		},
		{
			name: "missing exec_model returns clear error",
			capability:  "text",
			wantErrSubs: "no model configured for capability",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ah := testAgentHandler()
			agentID, _ := testAgentAndUser(t)

			// All success cases use openai — seed it once with a known key
			// and use the returned row UUID for the FK bindings.
			var openaiID uuid.UUID
			if tc.wantErrSubs == "" {
				openaiID = seedEnabledProvider(t, "openai", "OpenAI", "sk-test")
			}

			if tc.capabilitySuffix != "" {
				setSystemDefaultModel(t, tc.capabilitySuffix, openaiID, tc.modelName)
			}
			if tc.execModel != "" {
				setAgentExecModel(t, agentID.String(), openaiID, tc.execModel)
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
