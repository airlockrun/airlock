package trigger

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/google/uuid"
)

func (d *Dispatcher) EnsureRuntime(ctx context.Context, agentID uuid.UUID) error {
	_, err := d.EnsureRunning(ctx, agentID)
	return err
}

// InvokeRuntime transports an already-authorized capability invocation. The app
// borrows the host run; this transport never creates or completes another run.
func (d *Dispatcher) InvokeRuntime(ctx context.Context, agentID uuid.UUID, input wire.RuntimeInvokeRequest) (wire.RuntimeInvokeResponse, error) {
	var result wire.RuntimeInvokeResponse
	if err := wire.CheckAppRuntimeProtocol(input.RuntimeProtocol); err != nil {
		return result, err
	}
	if input.Context.AgentID != agentID.String() || input.Context.RunID == "" {
		return result, errors.New("runtime invocation scope mismatch")
	}
	c, err := d.EnsureRunning(ctx, agentID)
	if err != nil {
		return result, err
	}
	if blocked, err := d.runtimeForwardGate(ctx, agentID); err != nil {
		return result, err
	} else if blocked {
		return result, ErrAgentDeploying
	}
	body, err := json.Marshal(input)
	if err != nil {
		return result, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint+wire.RuntimeInvokePath, bytes.NewReader(body))
	if err != nil {
		return result, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	d.containers.MarkBusy(agentID)
	defer d.containers.MarkIdle(agentID)
	client := &http.Client{Timeout: 5 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(req)
	if err != nil {
		return result, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return result, fmt.Errorf("app runtime invocation returned HTTP %d; verify runtime compatibility", response.StatusCode)
	}
	const maxResponse = 20 << 20
	data, err := io.ReadAll(io.LimitReader(response.Body, maxResponse+1))
	if err != nil {
		return result, err
	}
	if len(data) > maxResponse {
		return result, errors.New("app runtime response exceeds limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return result, fmt.Errorf("invalid app runtime response: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return result, errors.New("invalid trailing app runtime response")
	}
	if err := wire.CheckAppRuntimeProtocol(result.RuntimeProtocol); err != nil {
		return result, err
	}
	return result, nil
}

func (d *Dispatcher) StartJSExecutor(ctx context.Context, runID, token uuid.UUID) (io.ReadWriteCloser, error) {
	manager, ok := d.containers.(interface {
		StartJSExecutor(context.Context, uuid.UUID, uuid.UUID) (io.ReadWriteCloser, error)
	})
	if !ok {
		return nil, errors.New("container manager does not implement isolated JS execution")
	}
	return manager.StartJSExecutor(ctx, runID, token)
}
