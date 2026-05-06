package trigger

import (
	"context"
	"errors"
	"fmt"

	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/secrets"
	"github.com/airlockrun/goai/model"
	solprovider "github.com/airlockrun/sol/provider"
)

// ErrTranscriptionNotConfigured is returned when no system-wide transcription
// model is set. Callers handle this non-fatally (degrade to file-only delivery).
var ErrTranscriptionNotConfigured = errors.New("transcription not configured")

// TranscriptionResolver returns the admin-configured transcription model or
// ErrTranscriptionNotConfigured when no model is set.
type TranscriptionResolver func(ctx context.Context) (model.TranscriptionModel, error)

// NewTranscriptionResolver returns a resolver that reads
// system_settings.default_transcription_model and looks up the associated
// provider credentials.
func NewTranscriptionResolver(database *db.DB, encryptor secrets.Store) TranscriptionResolver {
	return func(ctx context.Context) (model.TranscriptionModel, error) {
		q := dbq.New(database.Pool())
		settings, err := q.GetSystemSettings(ctx)
		if err != nil {
			return nil, fmt.Errorf("get system settings: %w", err)
		}
		if settings.DefaultSttModel == "" {
			return nil, ErrTranscriptionNotConfigured
		}
		providerID, modelID := solprovider.ParseModel(settings.DefaultSttModel)
		p, err := q.GetProviderByProviderID(ctx, providerID)
		if err != nil {
			return nil, fmt.Errorf("provider %q not configured: %w", providerID, err)
		}
		if !p.IsEnabled {
			return nil, fmt.Errorf("provider %q is disabled", providerID)
		}
		apiKey, err := encryptor.Get(ctx, "provider/"+p.ProviderID+"/api_key", p.ApiKey)
		if err != nil {
			return nil, fmt.Errorf("decrypt API key for %q: %w", providerID, err)
		}
		m := solprovider.CreateTranscriptionModel(providerID, modelID, solprovider.Options{
			APIKey:  apiKey,
			BaseURL: p.BaseUrl,
		})
		if m == nil {
			return nil, fmt.Errorf("provider %q does not support transcription", providerID)
		}
		return m, nil
	}
}
