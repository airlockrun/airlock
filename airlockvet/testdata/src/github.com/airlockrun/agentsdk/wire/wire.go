package wire

type SealRequest struct {
	Plaintext string `json:"plaintext"`
}

type SealResponse struct {
	Sealed string `json:"sealed"`
}
