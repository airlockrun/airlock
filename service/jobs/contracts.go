package jobs

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/robfig/cron/v3"
)

var (
	jobHandlerNamePattern  = regexp.MustCompile(`^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$`)
	jobContractHashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	jobCronParser          = cron.NewParser(cron.SecondOptional | cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor)
	ErrInvalidHandler      = errors.New("invalid job handler")
	ErrInvalidJobCron      = errors.New("invalid job cron declaration")
	ErrContractConflict    = errors.New("job handler contract conflict")
)

const (
	maxJobHandlerDescriptionBytes = 4096
	maxJobHandlerSchemaBytes      = 256 * 1024
	maxJobHandlerTimeoutMs        = int64(24 * 60 * 60 * 1000)
	maxJobHandlerAttempts         = int32(100)
	maxJobHandlerConcurrency      = int32(1000)
	maxJobCronDescriptionBytes    = 4096
	maxJobCronScheduleBytes       = 1024
	maxJobCronInputBytes          = 64 * 1024
)

// NormalizeJobManifest validates and canonicalizes a complete job manifest.
// Declarations are sorted by identity so equivalent manifests have one digest.
func NormalizeJobManifest(manifest wire.JobManifest) (wire.JobManifest, string, error) {
	handlers, err := NormalizeHandlerDefinitions(manifest.JobHandlers)
	if err != nil {
		return wire.JobManifest{}, "", err
	}
	sort.Slice(handlers, func(i, j int) bool {
		return HandlerKey(handlers[i].Name, handlers[i].Version) < HandlerKey(handlers[j].Name, handlers[j].Version)
	})

	crons, err := normalizeJobCronDefinitions(manifest.JobCrons, handlers)
	if err != nil {
		return wire.JobManifest{}, "", err
	}
	normalized := wire.JobManifest{JobHandlers: handlers, JobCrons: crons}
	encoded, err := json.Marshal(normalized)
	if err != nil {
		return wire.JobManifest{}, "", fmt.Errorf("encode canonical job manifest: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return normalized, hex.EncodeToString(sum[:]), nil
}

// NormalizeHandlerDefinitions validates and canonicalizes a complete runtime
// handler declaration. The returned order matches the declaration order.
func NormalizeHandlerDefinitions(definitions []wire.JobHandlerDef) ([]wire.JobHandlerDef, error) {
	seen := make(map[string]struct{}, len(definitions))
	normalized := make([]wire.JobHandlerDef, len(definitions))
	for i, definition := range definitions {
		canonical, err := normalizeHandlerDefinition(definition)
		if err != nil {
			return nil, err
		}
		normalized[i] = canonical
		key := HandlerKey(canonical.Name, canonical.Version)
		if _, exists := seen[key]; exists {
			return nil, fmt.Errorf("%w: duplicate %s", ErrInvalidHandler, key)
		}
		seen[key] = struct{}{}
	}
	return normalized, nil
}

func HandlerKey(name string, version int32) string {
	return fmt.Sprintf("%s@v%d", name, version)
}

func ImmutableContractMatches(left, right wire.JobHandlerDef) bool {
	return left.InputSchemaHash == right.InputSchemaHash &&
		left.OutputSchemaHash == right.OutputSchemaHash &&
		left.TimeoutMs == right.TimeoutMs &&
		left.MaxAttempts == right.MaxAttempts
}

func HashHandlerSchema(value json.RawMessage) string {
	canonical, err := canonicalHandlerSchema(value)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:])
}

func normalizeJobCronDefinitions(definitions []wire.JobCronDef, handlers []wire.JobHandlerDef) ([]wire.JobCronDef, error) {
	contracts := make(map[string]wire.JobHandlerDef, len(handlers))
	for _, handler := range handlers {
		contracts[HandlerKey(handler.Name, handler.Version)] = handler
	}

	normalized := make([]wire.JobCronDef, len(definitions))
	seen := make(map[string]struct{}, len(definitions))
	for i, definition := range definitions {
		if len(definition.Slug) > 63 || !jobHandlerNamePattern.MatchString(definition.Slug) {
			return nil, fmt.Errorf("%w: job cron slug %q must be lowercase snake_case with at most 63 characters", ErrInvalidJobCron, definition.Slug)
		}
		if _, exists := seen[definition.Slug]; exists {
			return nil, fmt.Errorf("%w: duplicate job cron %q", ErrInvalidJobCron, definition.Slug)
		}
		seen[definition.Slug] = struct{}{}
		if strings.TrimSpace(definition.Schedule) == "" || len(definition.Schedule) > maxJobCronScheduleBytes {
			return nil, fmt.Errorf("%w: job cron %q has an invalid schedule", ErrInvalidJobCron, definition.Slug)
		}
		if _, err := jobCronParser.Parse(definition.Schedule); err != nil {
			return nil, fmt.Errorf("%w: parse cron %s: %v", ErrInvalidJobCron, definition.Slug, err)
		}
		if strings.TrimSpace(definition.Description) == "" || len(definition.Description) > maxJobCronDescriptionBytes {
			return nil, fmt.Errorf("%w: job cron %q description must be nonblank and at most %d bytes", ErrInvalidJobCron, definition.Slug, maxJobCronDescriptionBytes)
		}
		if len(definition.HandlerName) > 63 || !jobHandlerNamePattern.MatchString(definition.HandlerName) || definition.HandlerVersion <= 0 {
			return nil, fmt.Errorf("%w: job cron %q has an invalid handler target", ErrInvalidJobCron, definition.Slug)
		}
		if !jobContractHashPattern.MatchString(definition.InputSchemaHash) || !jobContractHashPattern.MatchString(definition.OutputSchemaHash) {
			return nil, fmt.Errorf("%w: job cron %q has invalid schema hashes", ErrInvalidJobCron, definition.Slug)
		}
		handler, ok := contracts[HandlerKey(definition.HandlerName, definition.HandlerVersion)]
		if !ok {
			return nil, fmt.Errorf("%w: job cron %q targets a handler outside the manifest", ErrInvalidJobCron, definition.Slug)
		}
		if handler.InputSchemaHash != definition.InputSchemaHash || handler.OutputSchemaHash != definition.OutputSchemaHash {
			return nil, fmt.Errorf("%w: job cron %q does not match handler %s", ErrInvalidJobCron, definition.Slug, HandlerKey(definition.HandlerName, definition.HandlerVersion))
		}
		input, err := canonicalJobCronInput(definition.Input)
		if err != nil {
			return nil, fmt.Errorf("%w: job cron %q input: %v", ErrInvalidJobCron, definition.Slug, err)
		}
		definition.Input = input
		normalized[i] = definition
	}
	sort.Slice(normalized, func(i, j int) bool { return normalized[i].Slug < normalized[j].Slug })
	return normalized, nil
}

func canonicalJobCronInput(raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 || len(raw) > maxJobCronInputBytes {
		return nil, fmt.Errorf("must be a JSON object no larger than %d bytes", maxJobCronInputBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value map[string]any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if value == nil {
		return nil, errors.New("must be a JSON object")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return nil, errors.New("contains trailing data")
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if len(encoded) > maxJobCronInputBytes {
		return nil, fmt.Errorf("canonical input exceeds %d bytes", maxJobCronInputBytes)
	}
	return encoded, nil
}

func normalizeHandlerDefinition(definition wire.JobHandlerDef) (wire.JobHandlerDef, error) {
	name := HandlerKey(definition.Name, definition.Version)
	if len(definition.Name) > 63 || !jobHandlerNamePattern.MatchString(definition.Name) {
		return wire.JobHandlerDef{}, fmt.Errorf("%w: job handler name %q must be lowercase snake_case with at most 63 characters", ErrInvalidHandler, definition.Name)
	}
	if definition.Version <= 0 {
		return wire.JobHandlerDef{}, fmt.Errorf("%w: %s version must be positive", ErrInvalidHandler, name)
	}
	if strings.TrimSpace(definition.Description) == "" {
		return wire.JobHandlerDef{}, fmt.Errorf("%w: %s description is required", ErrInvalidHandler, name)
	}
	if len(definition.Description) > maxJobHandlerDescriptionBytes {
		return wire.JobHandlerDef{}, fmt.Errorf("%w: %s description exceeds %d bytes", ErrInvalidHandler, name, maxJobHandlerDescriptionBytes)
	}
	if definition.TimeoutMs <= 0 || definition.MaxAttempts <= 0 || definition.MaxConcurrency <= 0 {
		return wire.JobHandlerDef{}, fmt.Errorf("%w: %s timeout, max attempts, and max concurrency must be positive", ErrInvalidHandler, name)
	}
	if definition.TimeoutMs > maxJobHandlerTimeoutMs || definition.MaxAttempts > maxJobHandlerAttempts || definition.MaxConcurrency > maxJobHandlerConcurrency {
		return wire.JobHandlerDef{}, fmt.Errorf("%w: %s execution limits exceed platform bounds", ErrInvalidHandler, name)
	}
	if len(definition.InputSchema) > maxJobHandlerSchemaBytes || len(definition.OutputSchema) > maxJobHandlerSchemaBytes {
		return wire.JobHandlerDef{}, fmt.Errorf("%w: %s schema exceeds %d bytes", ErrInvalidHandler, name, maxJobHandlerSchemaBytes)
	}
	if !json.Valid(definition.InputSchema) || !json.Valid(definition.OutputSchema) {
		return wire.JobHandlerDef{}, fmt.Errorf("%w: %s schemas must be valid JSON", ErrInvalidHandler, name)
	}
	canonicalInput, err := canonicalHandlerSchema(definition.InputSchema)
	if err != nil {
		return wire.JobHandlerDef{}, fmt.Errorf("%w: %s input schema: %v", ErrInvalidHandler, name, err)
	}
	canonicalOutput, err := canonicalHandlerSchema(definition.OutputSchema)
	if err != nil {
		return wire.JobHandlerDef{}, fmt.Errorf("%w: %s output schema: %v", ErrInvalidHandler, name, err)
	}
	var input struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(canonicalInput, &input); err != nil || input.Type != "object" {
		return wire.JobHandlerDef{}, fmt.Errorf("%w: %s input schema must describe an object", ErrInvalidHandler, name)
	}
	if HashHandlerSchema(canonicalInput) != definition.InputSchemaHash {
		return wire.JobHandlerDef{}, fmt.Errorf("%w: %s input schema hash does not match", ErrInvalidHandler, name)
	}
	if HashHandlerSchema(canonicalOutput) != definition.OutputSchemaHash {
		return wire.JobHandlerDef{}, fmt.Errorf("%w: %s output schema hash does not match", ErrInvalidHandler, name)
	}
	definition.InputSchema = canonicalInput
	definition.OutputSchema = canonicalOutput
	return definition, nil
}

func canonicalHandlerSchema(value json.RawMessage) (json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.UseNumber()
	var decoded any
	if err := decoder.Decode(&decoded); err != nil {
		return nil, err
	}
	normalizeHandlerSchemaSets(decoded)
	return json.Marshal(decoded)
}

func normalizeHandlerSchemaSets(value any) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if key == "required" {
				if values, ok := child.([]any); ok {
					allStrings := true
					for _, value := range values {
						if _, ok := value.(string); !ok {
							allStrings = false
							break
						}
					}
					if allStrings {
						sort.Slice(values, func(i, j int) bool { return values[i].(string) < values[j].(string) })
					}
				}
			}
			normalizeHandlerSchemaSets(child)
		}
	case []any:
		for _, child := range typed {
			normalizeHandlerSchemaSets(child)
		}
	}
}
