package runtime

import (
	"encoding/json"
)

type JsonrpcMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *JsonrpcError   `json:"error,omitempty"`
}
type JsonrpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

const (
	RpcErrParse          = -32700
	RpcErrInvalidRequest = -32600
	RpcErrMethodNotFound = -32601
	RpcErrInvalidParams  = -32602
	RpcErrInternal       = -32603
	RpcErrServerError    = -32000
)
