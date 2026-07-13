package api

import (
	"net/http"

	"github.com/airlockrun/agentsdk"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
)

func getAgentSDKInfo(publicURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeProto(w, http.StatusOK, &airlockv1.GetAgentSDKInfoResponse{
			Version:       agentsdk.Version,
			CommandImport: "github.com/airlockrun/agentsdk/cmd/air",
			AirlockUrl:    publicURL,
		})
	}
}
