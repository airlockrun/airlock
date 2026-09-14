package chat

import (
	"context"
	"sync"

	"github.com/airlockrun/goai/stream"
)

// drainingModel retains every stream, including setup retries that the runner
// can abandon on cancellation. Closing a host model stream joins its accounting.
type drainingModel struct {
	stream.Model
	mu      sync.Mutex
	streams []<-chan stream.Event
}

func (m *drainingModel) Stream(ctx context.Context, options *stream.CallOptions) (<-chan stream.Event, error) {
	events, err := m.Model.Stream(ctx, options)
	if events != nil {
		m.mu.Lock()
		m.streams = append(m.streams, events)
		m.mu.Unlock()
	}
	return events, err
}

// wait is called after the runner returns and its model contexts are cancelled.
func (m *drainingModel) wait() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, events := range m.streams {
		for range events {
		}
	}
}
