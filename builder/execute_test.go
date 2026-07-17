package builder

import (
	"context"
	"errors"
	"testing"

	"github.com/airlockrun/airlock/config"
	"github.com/airlockrun/airlock/container"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestExecuteWaitsForBuildCapacityBeforeDependencies(t *testing.T) {
	b := &BuildService{buildSem: make(chan struct{}, 1)}
	b.buildSem <- struct{}{}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := b.Execute(ctx, BuildPlan{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Execute() error = %v, want context.Canceled", err)
	}
}

type deploymentQueryState struct {
	status          string
	tokenVersion    int64
	sourceRef       string
	imageRef        string
	beforeIncrement func()
	increments      int
}

func (q *deploymentQueryState) IncrementAgentTokenVersion(context.Context, pgtype.UUID) (int64, error) {
	if q.beforeIncrement != nil {
		q.beforeIncrement()
	}
	q.tokenVersion++
	q.increments++
	return q.tokenVersion, nil
}

func (q *deploymentQueryState) FinalizeAgentDeployment(_ context.Context, arg dbq.FinalizeAgentDeploymentParams) (int64, error) {
	if q.tokenVersion != arg.AgentTokenVersion || q.status != arg.ExpectedStatus {
		return 0, nil
	}
	q.status = arg.NextStatus
	q.sourceRef = arg.SourceRef
	q.imageRef = arg.ImageRef
	return 1, nil
}

func (q *deploymentQueryState) stop() {
	q.status = "stopped"
	q.tokenVersion++
}

type deploymentContainerManager struct {
	container.ContainerManager
	starts  int
	stops   int
	lastOpt container.AgentOpts
	onStart func()
}

func (m *deploymentContainerManager) StartAgent(_ context.Context, opts container.AgentOpts) (*container.Container, error) {
	m.starts++
	m.lastOpt = opts
	if m.onStart != nil {
		m.onStart()
	}
	return &container.Container{AgentID: opts.AgentID, Image: opts.Image, Token: opts.Token}, nil
}

func (m *deploymentContainerManager) StopAgent(context.Context, uuid.UUID) error {
	m.stops++
	return nil
}

func (m *deploymentContainerManager) LockSwap(uuid.UUID) func() { return func() {} }

func TestDeployAgentStopInterleavingsRejectActivation(t *testing.T) {
	tests := []struct {
		name           string
		kind           BuildKind
		status         string
		oldImage       string
		stopBefore     bool
		stopAfterStart bool
		wantStops      int
	}{
		{
			name:       "initial stop before token reservation",
			kind:       BuildKindBuild,
			status:     "building",
			stopBefore: true,
			wantStops:  1,
		},
		{
			name:           "initial stop after container start",
			kind:           BuildKindBuild,
			status:         "building",
			stopAfterStart: true,
			wantStops:      1,
		},
		{
			name:           "active upgrade stop after container start",
			kind:           BuildKindUpgrade,
			status:         "active",
			oldImage:       "agent:old",
			stopAfterStart: true,
			wantStops:      2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agentID := uuid.New()
			q := &deploymentQueryState{
				status:       tt.status,
				tokenVersion: 7,
				sourceRef:    "old-source",
				imageRef:     tt.oldImage,
			}
			if tt.stopBefore {
				q.beforeIncrement = func() {
					q.beforeIncrement = nil
					q.stop()
				}
			}
			containers := &deploymentContainerManager{}
			if tt.stopAfterStart {
				containers.onStart = q.stop
			}
			b := &BuildService{
				cfg:        &config.Config{JWTSecret: "deployment-test-secret", APIURLAgent: "http://airlock.test"},
				containers: containers,
			}
			plan := BuildPlan{
				Agent: dbq.Agent{
					ID:                pgtype.UUID{Bytes: agentID, Valid: true},
					Status:            tt.status,
					ImageRef:          tt.oldImage,
					AgentTokenVersion: 7,
				},
				Kind: tt.kind,
			}

			err := b.deployAgent(context.Background(), q, plan, "postgres://agent", "new-source", "agent:new")
			if !errors.Is(err, ErrDeploymentConflict) {
				t.Fatalf("deployAgent() error = %v, want ErrDeploymentConflict", err)
			}
			if q.status != "stopped" {
				t.Fatalf("status = %q, want stopped", q.status)
			}
			if q.sourceRef != "old-source" || q.imageRef != tt.oldImage {
				t.Fatalf("refs = (%q, %q), want unchanged", q.sourceRef, q.imageRef)
			}
			if containers.starts != 1 {
				t.Fatalf("starts = %d, want 1", containers.starts)
			}
			if containers.stops != tt.wantStops {
				t.Fatalf("stops = %d, want %d", containers.stops, tt.wantStops)
			}
			if containers.lastOpt.Token == "" {
				t.Fatal("deployment token is empty")
			}
			if q.increments != 1 {
				t.Fatalf("token increments = %d, want 1", q.increments)
			}
		})
	}
}

func TestDeployAgentStoppedUpgradeUpdatesRefsWithoutStarting(t *testing.T) {
	agentID := uuid.New()
	q := &deploymentQueryState{
		status:       "stopped",
		tokenVersion: 11,
		sourceRef:    "old-source",
		imageRef:     "agent:old",
	}
	containers := &deploymentContainerManager{}
	b := &BuildService{
		cfg:        &config.Config{JWTSecret: "deployment-test-secret"},
		containers: containers,
	}
	plan := BuildPlan{
		Agent: dbq.Agent{
			ID:                pgtype.UUID{Bytes: agentID, Valid: true},
			Status:            "stopped",
			ImageRef:          "agent:old",
			AgentTokenVersion: 11,
		},
		Kind: BuildKindUpgrade,
	}

	if err := b.deployAgent(context.Background(), q, plan, "postgres://agent", "new-source", "agent:new"); err != nil {
		t.Fatalf("deployAgent(): %v", err)
	}
	if q.status != "stopped" {
		t.Fatalf("status = %q, want stopped", q.status)
	}
	if q.sourceRef != "new-source" || q.imageRef != "agent:new" {
		t.Fatalf("refs = (%q, %q), want new refs", q.sourceRef, q.imageRef)
	}
	if q.tokenVersion != 12 || q.increments != 1 {
		t.Fatalf("token version/increments = %d/%d, want 12/1", q.tokenVersion, q.increments)
	}
	if containers.starts != 0 || containers.stops != 0 {
		t.Fatalf("container starts/stops = %d/%d, want 0/0", containers.starts, containers.stops)
	}
}
