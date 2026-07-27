package builder

import (
	"net/http"
	"testing"
)

func TestLanguageModelOptionsProviderHTTPClient(t *testing.T) {
	client := &http.Client{}
	b := &BuildService{providerHTTPClient: client}

	compat := b.languageModelOptions(&resolvedProvider{CatalogID: "openai-compatible"})
	if compat.HTTPClient != client {
		t.Fatal("openai-compatible provider did not receive the builder HTTP client")
	}

	hosted := b.languageModelOptions(&resolvedProvider{CatalogID: "openai"})
	if hosted.HTTPClient != nil {
		t.Fatal("hosted provider received the provider endpoint HTTP client")
	}
}
