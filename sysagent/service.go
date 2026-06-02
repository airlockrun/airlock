package sysagent

import (
	"context"
	"sync"

	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/realtime"
	"github.com/airlockrun/airlock/secrets"
	agentssvc "github.com/airlockrun/airlock/service/agents"
	bridgessvc "github.com/airlockrun/airlock/service/bridges"
	catalogsvc "github.com/airlockrun/airlock/service/catalog"
	connsvc "github.com/airlockrun/airlock/service/connections"
	execsvc "github.com/airlockrun/airlock/service/execendpoints"
	gitcredssvc "github.com/airlockrun/airlock/service/gitcredentials"
	memberssvc "github.com/airlockrun/airlock/service/members"
	modelssvc "github.com/airlockrun/airlock/service/models"
	runssvc "github.com/airlockrun/airlock/service/runs"
	siblingssvc "github.com/airlockrun/airlock/service/siblings"
	userssvc "github.com/airlockrun/airlock/service/users"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Service is the central sysagent hub. Owns the dependency set every
// tool body needs (db, encryptor, all the per-domain service handles,
// logger) plus the public URL used to mint deep-link tool results.
//
// One instance per Airlock; constructed in api/router.go and shared
// across HTTP requests. Per-request state (Principal, conversation, message
// history) lives on the chat loop, not here.
type Service struct {
	db        *db.DB
	encryptor secrets.Store
	pubsub    *realtime.PubSub
	publicURL string
	logger    *zap.Logger

	// Per-domain services. The tool catalogue resolves these at
	// registration time; no global lookups in tool bodies.
	agents   *agentssvc.Service
	bridges  *bridgessvc.Service
	catalog  *catalogsvc.Service
	conns    *connsvc.Service
	execs    *execsvc.Service
	gitcreds *gitcredssvc.Service
	members  *memberssvc.Service
	models   *modelssvc.Service
	runs     *runssvc.Service
	siblings *siblingssvc.Service
	users    *userssvc.Service

	// activeRuns is the in-process registry of cancellable chat
	// goroutines, keyed by run id. /cancel and operator-initiated
	// shutdowns look up the cancel func here. The map only carries
	// in-process state — a multi-replica deployment would need a DB
	// signal too, but airlock is single-instance today.
	activeMu   sync.Mutex
	activeRuns map[uuid.UUID]context.CancelFunc
}

// Deps bundles the dependencies New requires. Pulled out as a struct
// so the call site stays readable as the service set grows.
type Deps struct {
	DB        *db.DB
	Encryptor secrets.Store
	PubSub    *realtime.PubSub
	PublicURL string // base URL for deep-link tools (no trailing slash)
	Logger    *zap.Logger

	Agents   *agentssvc.Service
	Bridges  *bridgessvc.Service
	Catalog  *catalogsvc.Service
	Conns    *connsvc.Service
	Execs    *execsvc.Service
	GitCreds *gitcredssvc.Service
	Members  *memberssvc.Service
	Models   *modelssvc.Service
	Runs     *runssvc.Service
	Siblings *siblingssvc.Service
	Users    *userssvc.Service
}

// New wires the sysagent Service. Fail-loud on nil deps — every field
// is required (CLAUDE.md rule).
func New(d Deps) *Service {
	if d.DB == nil {
		panic("sysagent: db is required")
	}
	if d.Encryptor == nil {
		panic("sysagent: encryptor is required")
	}
	if d.PubSub == nil {
		panic("sysagent: pubsub is required")
	}
	if d.PublicURL == "" {
		panic("sysagent: public URL is required")
	}
	if d.Logger == nil {
		panic("sysagent: logger is required")
	}
	if d.Agents == nil || d.Bridges == nil || d.Catalog == nil || d.Conns == nil ||
		d.Execs == nil || d.GitCreds == nil || d.Members == nil ||
		d.Models == nil || d.Runs == nil || d.Siblings == nil || d.Users == nil {
		panic("sysagent: every per-domain service is required")
	}
	return &Service{
		db:         d.DB,
		encryptor:  d.Encryptor,
		pubsub:     d.PubSub,
		publicURL:  d.PublicURL,
		logger:     d.Logger,
		agents:     d.Agents,
		bridges:    d.Bridges,
		catalog:    d.Catalog,
		conns:      d.Conns,
		execs:      d.Execs,
		gitcreds:   d.GitCreds,
		members:    d.Members,
		models:     d.Models,
		runs:       d.Runs,
		siblings:   d.Siblings,
		users:      d.Users,
		activeRuns: make(map[uuid.UUID]context.CancelFunc),
	}
}

// registerActiveRun stores the cancel func for an in-flight chat
// goroutine. CancelRun looks up here.
func (s *Service) registerActiveRun(runID uuid.UUID, cancel context.CancelFunc) {
	s.activeMu.Lock()
	s.activeRuns[runID] = cancel
	s.activeMu.Unlock()
}

// unregisterActiveRun drops the cancel func once the chat goroutine
// returns. Safe to call even if CancelRun raced ahead.
func (s *Service) unregisterActiveRun(runID uuid.UUID) {
	s.activeMu.Lock()
	delete(s.activeRuns, runID)
	s.activeMu.Unlock()
}

// Logger exposes the package logger for callers that want to surface
// sysagent events through the same channel (e.g. the API handler
// logging request failures).
func (s *Service) Logger() *zap.Logger { return s.logger }
