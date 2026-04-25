package builder

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/airlockrun/airlock/container"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/goai/tool"
	sol "github.com/airlockrun/sol"
	"github.com/airlockrun/sol/bus"
	"github.com/airlockrun/sol/executor"
	solprovider "github.com/airlockrun/sol/provider"
	soltools "github.com/airlockrun/sol/tools"
	"github.com/airlockrun/sol/websearch"
	"github.com/airlockrun/goai/stream"
	dmount "github.com/docker/docker/api/types/mount"
	"go.uber.org/zap"
)

// solRunOpts configures an in-process Sol run with a remote toolserver.
type solRunOpts struct {
	WorkDir     string            // host path to sparse checkout
	AgentDir    string            // container-side path (e.g., /workspace/agents/{id})
	BuildModel  string            // "provider/model" string
	Prompt      string            // prompt for the runner
	LogCallback func(line string) // called for each log line
	LocalTools  tool.Set          // optional in-process tools (e.g., set_agent_description)
	TestDBURL    string // test schema DB URL with search_path baked in
	TestDBPSQL   string // test schema DB URL without search_path (for psql)
	TestDBSchema string // test schema name (for psql SET search_path)
}

// solRunResult captures the outcome of an in-process Sol run.
type solRunResult struct {
	Status    sol.RunStatus
	TotalText string
	Error     error
}

// runSolInProcess starts a toolserver container, runs the Sol Runner in-process,
// and returns the result. The toolserver provides filesystem tools (read, write,
// bash, etc.) while the LLM loop runs in the Airlock process.
func (b *BuildService) runSolInProcess(ctx context.Context, opts solRunOpts) (*solRunResult, error) {
	// Fall back to the system-wide default build model when no per-agent
	// override has been set. Live inheritance — no snapshot at agent create.
	if opts.BuildModel == "" {
		q := dbq.New(b.db.Pool())
		settings, sErr := q.GetSystemSettings(ctx)
		if sErr != nil {
			return nil, fmt.Errorf("load system settings: %w", sErr)
		}
		opts.BuildModel = settings.DefaultBuildModel
	}
	if opts.BuildModel == "" {
		return nil, fmt.Errorf("no build model configured — set one in admin Settings or on the agent's Models tab")
	}

	// Step 1: Resolve LLM model (decrypt API key from DB).
	model, rp, err := b.resolveModel(ctx, opts.BuildModel)
	if err != nil {
		return nil, fmt.Errorf("resolve model: %w", err)
	}

	// Step 1b: Resolve web search tool (optional).
	hasWebSearch := false
	if searchTool, ok := b.resolveSearchTool(ctx, rp); ok {
		if opts.LocalTools == nil {
			opts.LocalTools = tool.Set{}
		}
		opts.LocalTools[searchTool.Name] = searchTool
		hasWebSearch = true
	}

	// Step 2: Start toolserver container.
	var toolEnv []string
	if opts.TestDBURL != "" {
		toolEnv = append(toolEnv,
			"TEST_DB_URL="+opts.TestDBURL,
			"TEST_DB_PSQL="+opts.TestDBPSQL,
			"TEST_DB_SCHEMA="+opts.TestDBSchema,
		)
	}
	mounts := []dmount.Mount{
		{Type: dmount.TypeBind, Source: opts.WorkDir, Target: "/workspace"},
	}
	// Dev: overlay the baked /libs with the live source tree so agentsdk
	// edits are visible without rebuilding the agent-builder image.
	// Prod (AgentLibsPath empty): the image's pinned /libs is authoritative.
	if b.cfg.AgentLibsPath != "" {
		for _, sub := range []string{"agentsdk", "goai", "sol"} {
			mounts = append(mounts, dmount.Mount{
				Type:     dmount.TypeBind,
				Source:   filepath.Join(b.cfg.AgentLibsPath, sub),
				Target:   "/libs/" + sub,
				ReadOnly: true,
			})
		}
	}
	tc, err := b.containers.StartToolserver(ctx, container.ToolserverOpts{
		Image:   b.cfg.AgentBuilderImage,
		Mounts:  mounts,
		WorkDir: opts.AgentDir,
		Env:     toolEnv,
	})
	if err != nil {
		return nil, fmt.Errorf("start toolserver: %w", err)
	}
	defer b.containers.StopToolserver(ctx, tc.Name)

	b.logger.Info("toolserver ready", zap.String("endpoint", tc.Endpoint))

	// Step 3: Connect to toolserver via WebSocket.
	wsURL := strings.Replace(tc.Endpoint, "http://", "ws://", 1) + "/ws"
	transport, err := executor.NewWSTransport(wsURL)
	if err != nil {
		return nil, fmt.Errorf("connect to toolserver: %w", err)
	}
	defer transport.Close()

	// Step 4: Fetch remote tools and set auto-approve rules.
	remoteTools, err := transport.FetchTools(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch tools: %w", err)
	}
	if err := transport.SetRules(ctx, []bus.PermissionRule{
		{Permission: "*", Pattern: "*", Action: "allow"},
	}); err != nil {
		return nil, fmt.Errorf("set rules: %w", err)
	}

	remoteExec := executor.NewRemoteExecutor(transport, remoteTools)

	// Step 5: Build tool.Set and executor, merging local tools if present.
	toolSet := remoteToolsToSet(remoteTools)
	var exec tool.Executor = remoteExec

	if len(opts.LocalTools) > 0 {
		for name, t := range opts.LocalTools {
			toolSet[name] = t
		}
		exec = &compositeExecutor{
			remote: remoteExec,
			local:  tool.NewLocalExecutor(opts.LocalTools, nil),
		}
	}

	// Step 6: Create the agent-builder agent with all tools.
	ag := newAgentBuilderAgent(toolSet, hasWebSearch)
	ag.Model = opts.BuildModel

	// Step 7: Create scoped bus and subscribe for log streaming.
	runBus := bus.New()
	if opts.LogCallback != nil {
		subscribeForLogs(runBus, opts.LogCallback)
	}

	// Step 8: Create and run Sol Runner.
	runner := sol.NewRunner(sol.RunnerOptions{
		Agent:    ag,
		Model:    model,
		Bus:      runBus,
		Executor: exec,
		Quiet:    true,
	})
	runner.PermissionManager().SetRules([]bus.PermissionRule{
		{Permission: "*", Pattern: "*", Action: "allow"},
	})

	result, err := runner.Run(ctx, opts.Prompt)
	if err != nil {
		return &solRunResult{
			Status: sol.RunFailed,
			Error:  err,
		}, nil
	}

	return &solRunResult{
		Status:    result.Status,
		TotalText: result.TotalText,
		Error:     result.Error,
	}, nil
}

// resolvedProvider holds the result of looking up and decrypting a provider.
type resolvedProvider struct {
	ProviderID string
	APIKey     string
	BaseURL    string
}

// resolveModel looks up the provider API key from the DB and creates a stream.Model.
func (b *BuildService) resolveModel(ctx context.Context, buildModel string) (stream.Model, *resolvedProvider, error) {
	rp, err := b.resolveProvider(ctx, buildModel)
	if err != nil {
		return nil, nil, err
	}
	_, modelID := solprovider.ParseModel(buildModel)
	model := solprovider.CreateModel(rp.ProviderID, modelID, solprovider.Options{
		APIKey:  rp.APIKey,
		BaseURL: rp.BaseURL,
	})
	return model, rp, nil
}

// resolveProvider looks up a provider's API key and returns the resolved config.
func (b *BuildService) resolveProvider(ctx context.Context, buildModel string) (*resolvedProvider, error) {
	providerID, _ := solprovider.ParseModel(buildModel)

	q := dbq.New(b.db.Pool())
	p, err := q.GetProviderByProviderID(ctx, providerID)
	if err != nil {
		return nil, fmt.Errorf("provider %q not configured", providerID)
	}
	if !p.IsEnabled {
		return nil, fmt.Errorf("provider %q is disabled", providerID)
	}
	apiKey, err := b.encryptor.Decrypt(p.ApiKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt API key for %q: %w", providerID, err)
	}

	baseURL := p.BaseUrl
	if b.cfg.LLMProxyURL != "" {
		baseURL = b.cfg.LLMProxyURL
	}

	return &resolvedProvider{
		ProviderID: providerID,
		APIKey:     apiKey,
		BaseURL:    baseURL,
	}, nil
}

// resolveSearchTool tries to create a web search tool for the builder.
// First checks whether the build LLM provider has a native search backend
// (grok/gemini/kimi); if not, walks the providers table for any enabled row
// whose overlay entry declares a SearchBackend, preferring catalog-only
// entries (brave/perplexity) over LLM providers that happen to offer search.
func (b *BuildService) resolveSearchTool(ctx context.Context, rp *resolvedProvider) (tool.Tool, bool) {
	// 1. Try the LLM provider cascade — reuses rp's key when the provider
	//    has a native search backend (soltools.WebSearch reads the overlay).
	if t, ok := soltools.WebSearch(rp.ProviderID, rp.APIKey); ok {
		return t, true
	}

	// 2. Walk the providers table for any configured search-capable row.
	q := dbq.New(b.db.Pool())
	providers, err := q.ListProviders(ctx)
	if err != nil {
		return tool.Tool{}, false
	}
	base, _ := solprovider.LoadProviders()

	type cand struct {
		row         dbq.Provider
		backend     string
		catalogOnly bool
	}
	var ranked []cand
	for _, p := range providers {
		if !p.IsEnabled {
			continue
		}
		ov, ok := solprovider.Overlay[p.ProviderID]
		if !ok || ov.SearchBackend == "" {
			continue
		}
		_, inBase := base[p.ProviderID]
		ranked = append(ranked, cand{row: p, backend: ov.SearchBackend, catalogOnly: !inBase})
	}
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].catalogOnly != ranked[j].catalogOnly {
			return ranked[i].catalogOnly
		}
		return ranked[i].row.ProviderID < ranked[j].row.ProviderID
	})
	for _, c := range ranked {
		apiKey, err := b.encryptor.Decrypt(c.row.ApiKey)
		if err != nil {
			continue
		}
		return websearch.NewTool(websearch.NewClient(websearch.Options{
			Provider: c.backend,
			APIKey:   apiKey,
		})), true
	}

	return tool.Tool{}, false
}

// remoteToolsToSet converts remote tool.Info list to a tool.Set for the agent definition.
// The tools in this set have no Execute function — execution goes through the RemoteExecutor.
func remoteToolsToSet(infos []tool.Info) tool.Set {
	ts := make(tool.Set)
	for _, info := range infos {
		ts[info.Name] = tool.Tool{
			Name:        info.Name,
			Description: info.Description,
			InputSchema: info.InputSchema,
		}
	}
	return ts
}

// subscribeForLogs subscribes to bus events and forwards them as log lines.
func subscribeForLogs(b *bus.Bus, cb func(string)) {
	b.Subscribe(bus.StreamToolCall, func(e bus.Event) {
		tc, ok := e.Properties.(stream.ToolCallEvent)
		if !ok {
			return
		}
		input := string(tc.Input)
		if len(input) > 200 {
			input = input[:200] + "..."
		}
		cb(fmt.Sprintf("[tool] %s %s", tc.ToolName, input))
	})
	b.Subscribe(bus.StreamToolResult, func(e bus.Event) {
		tr, ok := e.Properties.(stream.ToolResultEvent)
		if !ok {
			return
		}
		output := tr.Output.Output
		if len(output) > 500 {
			output = output[:500] + "..."
		}
		cb(fmt.Sprintf("[result] %s", output))
	})
	b.Subscribe(bus.StreamStepComplete, func(e bus.Event) {
		step, ok := e.Properties.(*sol.StepResult)
		if !ok {
			return
		}
		cb(fmt.Sprintf("[step] complete (finish: %s)", step.FinishReason))
	})
}
