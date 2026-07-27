package agentapi

import (
	"context"
	"strings"
	"testing"

	"github.com/airlockrun/airlock/networkpolicy"
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

func TestLanguageModelOptionsProviderHTTPClient(t *testing.T) {
	h := &Handler{httpNetwork: networkpolicy.New(nil, false)}
	compat := h.languageModelOptions(resolvedModel{providerID: "openai-compatible"})
	if compat.HTTPClient == nil {
		t.Fatal("openai-compatible HTTP client is nil")
	}
	if compat.HTTPClient.Timeout != 0 {
		t.Fatalf("openai-compatible HTTP client timeout = %s, want no client-wide timeout", compat.HTTPClient.Timeout)
	}

	hosted := h.languageModelOptions(resolvedModel{providerID: "openai"})
	if hosted.HTTPClient != nil {
		t.Fatalf("hosted provider HTTP client = %p, want nil", hosted.HTTPClient)
	}
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
			name:             "transcription resolves to default_stt_*",
			capability:       "transcription",
			capabilitySuffix: "stt", modelName: "whisper-1",
			wantProv: "openai", wantModel: "whisper-1",
		},
		{
			name:             "speech resolves to default_tts_*",
			capability:       "speech",
			capabilitySuffix: "tts", modelName: "tts-1",
			wantProv: "openai", wantModel: "tts-1",
		},
		{
			name:             "image resolves to default_image_gen_*",
			capability:       "image",
			capabilitySuffix: "image_gen", modelName: "dall-e-3",
			wantProv: "openai", wantModel: "dall-e-3",
		},
		{
			name:             "embedding resolves to default_embedding_*",
			capability:       "embedding",
			capabilitySuffix: "embedding", modelName: "text-embedding-3-small",
			wantProv: "openai", wantModel: "text-embedding-3-small",
		},
		{
			name:             "vision resolves to default_vision_*",
			capability:       "vision",
			capabilitySuffix: "vision", modelName: "gpt-4o",
			wantProv: "openai", wantModel: "gpt-4o",
		},
		{
			name:       "empty capability falls back to agent exec_*",
			capability: "",
			execModel:  "gpt-4o-mini",
			wantProv:   "openai", wantModel: "gpt-4o-mini",
		},
		{
			name:       "text capability falls back to agent exec_*",
			capability: "text",
			execModel:  "gpt-4o",
			wantProv:   "openai", wantModel: "gpt-4o",
		},
		{
			name:        "missing capability default returns clear error",
			capability:  "transcription",
			wantErrSubs: "no model configured for capability",
		},
		{
			name:        "missing exec_model returns clear error",
			capability:  "text",
			wantErrSubs: "no model configured for capability",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			skipIfNoDB(t) // per-subtest snapshot restore — each case seeds "openai"
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

			resolved, err := ah.resolveModel(
				context.Background(), agentID.String(), tc.slug, tc.capability)

			if tc.wantErrSubs != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got success (provider=%s model=%s)",
						tc.wantErrSubs, resolved.providerID, resolved.modelID)
				}
				if !strings.Contains(err.Error(), tc.wantErrSubs) {
					t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErrSubs)
				}
				return
			}

			if err != nil {
				t.Fatalf("resolveModel: %v", err)
			}
			if resolved.providerID != tc.wantProv {
				t.Errorf("providerID = %q, want %q", resolved.providerID, tc.wantProv)
			}
			if resolved.modelID != tc.wantModel {
				t.Errorf("modelID = %q, want %q", resolved.modelID, tc.wantModel)
			}
			if resolved.providerSlug != "default" {
				t.Errorf("providerSlug = %q, want %q", resolved.providerSlug, "default")
			}
			if resolved.apiKey != "sk-test" {
				t.Errorf("apiKey = %q, want sk-test (decrypt failed?)", resolved.apiKey)
			}
		})
	}
}
