package agentsdk

// SealRequest is the shared wire shape — both sides must use this.
type SealRequest struct {
	Plaintext string `json:"plaintext"`
}

// SealResponse mirrors agentsdk.SealResponse.
type SealResponse struct {
	Sealed string `json:"sealed"`
}
