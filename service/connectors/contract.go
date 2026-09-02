// Package connectors owns connector interface contracts, readiness, grants,
// and operator-visible connector resources.
package connectors

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/airlockrun/agentsdk/connector/protocol"
)

const ProtocolMajor = 1

var operationName = regexp.MustCompile(`^[a-z][a-z0-9]*(_[a-z0-9]+)*$`)
var contractID = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*\.[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*(?:\.[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*)+$`)

type Command struct {
	Name             string          `json:"name"`
	Revision         int32           `json:"revision"`
	Description      string          `json:"description,omitempty"`
	Mode             string          `json:"mode"`
	InputSchema      json.RawMessage `json:"inputSchema,omitempty"`
	OutputSchema     json.RawMessage `json:"outputSchema,omitempty"`
	InputSchemaHash  string          `json:"inputSchemaHash"`
	OutputSchemaHash string          `json:"outputSchemaHash"`
}

type Directory struct {
	Name        string `json:"name"`
	Revision    int32  `json:"revision"`
	Description string `json:"description,omitempty"`
	Read        bool   `json:"read"`
	Write       bool   `json:"write"`
	List        bool   `json:"list"`
}

type InterfaceDescriptor struct {
	Kind            string      `json:"kind"`
	ContractID      string      `json:"contractId"`
	Name            string      `json:"name"`
	Description     string      `json:"description"`
	ArtifactVersion string      `json:"artifactVersion"`
	Commands        []Command   `json:"commands"`
	Directories     []Directory `json:"directories"`
}

type NeedSpec struct {
	ContractID  string      `json:"contractId"`
	Commands    []Command   `json:"commands"`
	Directories []Directory `json:"directories"`
	Multiple    bool        `json:"multiple,omitempty"`
}

func ParseNeedSpec(raw []byte) (NeedSpec, error) {
	var spec NeedSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return NeedSpec{}, fmt.Errorf("decode connector need: %w", err)
	}
	if spec.ContractID == "" {
		return NeedSpec{}, errors.New("connector need contract_id is required")
	}
	if err := ValidateNeedSpec(spec); err != nil {
		return NeedSpec{}, err
	}
	return spec, nil
}

func ValidateNeedSpec(spec NeedSpec) error {
	if len(spec.ContractID) > 253 || !contractID.MatchString(spec.ContractID) {
		return errors.New("connector need contractId is required")
	}
	seen := make(map[string]struct{}, len(spec.Commands)+len(spec.Directories))
	for _, command := range spec.Commands {
		if !operationName.MatchString(command.Name) || command.Revision <= 0 || (command.Mode != "unary" && command.Mode != "job") {
			return fmt.Errorf("invalid connector command requirement %q", command.Name)
		}
		if _, exists := seen["c:"+command.Name]; exists {
			return fmt.Errorf("duplicate connector command requirement %q", command.Name)
		}
		seen["c:"+command.Name] = struct{}{}
		if err := validateHash(command.InputSchemaHash); err != nil {
			return err
		}
		if err := validateHash(command.OutputSchemaHash); err != nil {
			return err
		}
	}
	for _, directory := range spec.Directories {
		if !operationName.MatchString(directory.Name) || directory.Revision <= 0 || (!directory.Read && !directory.Write && !directory.List) {
			return fmt.Errorf("invalid connector directory requirement %q", directory.Name)
		}
		if _, exists := seen["d:"+directory.Name]; exists {
			return fmt.Errorf("duplicate connector directory requirement %q", directory.Name)
		}
		seen["d:"+directory.Name] = struct{}{}
	}
	return nil
}

func ParseDescriptor(raw []byte) (InterfaceDescriptor, error) {
	if len(raw) == 0 || len(raw) > 1<<20 {
		return InterfaceDescriptor{}, errors.New("connector interface descriptor must be between 1 byte and 1 MiB")
	}
	var descriptor InterfaceDescriptor
	if err := json.Unmarshal(raw, &descriptor); err != nil {
		return InterfaceDescriptor{}, fmt.Errorf("decode connector interface: %w", err)
	}
	if err := ValidateDescriptor(descriptor); err != nil {
		return InterfaceDescriptor{}, err
	}
	return descriptor, nil
}

func ValidateDescriptor(descriptor InterfaceDescriptor) error {
	if descriptor.Name == "" || descriptor.ArtifactVersion == "" {
		return errors.New("connector kind, contractId, name, and artifactVersion are required")
	}
	if err := protocol.ValidateKind(descriptor.Kind); err != nil {
		return err
	}
	if len(descriptor.ContractID) > 253 || !contractID.MatchString(descriptor.ContractID) {
		return errors.New("connector contractId must be a reverse-domain identifier")
	}
	if len(descriptor.Description) > 4096 || len(descriptor.Name) > 256 || len(descriptor.ContractID) > 255 {
		return errors.New("connector interface metadata exceeds its size limit")
	}
	seen := make(map[string]struct{}, len(descriptor.Commands)+len(descriptor.Directories))
	for i := range descriptor.Commands {
		command := &descriptor.Commands[i]
		if !operationName.MatchString(command.Name) || command.Revision <= 0 {
			return fmt.Errorf("invalid connector command %q", command.Name)
		}
		if command.Mode != "unary" && command.Mode != "job" {
			return fmt.Errorf("connector command %q has invalid mode", command.Name)
		}
		if _, ok := seen["c:"+command.Name]; ok {
			return fmt.Errorf("duplicate connector command %q", command.Name)
		}
		seen["c:"+command.Name] = struct{}{}
		if err := validateHash(command.InputSchemaHash); err != nil {
			return fmt.Errorf("connector command %q input hash: %w", command.Name, err)
		}
		if err := validateHash(command.OutputSchemaHash); err != nil {
			return fmt.Errorf("connector command %q output hash: %w", command.Name, err)
		}
		if len(command.InputSchema) > 512<<10 || len(command.OutputSchema) > 512<<10 || len(command.Description) > 4096 {
			return fmt.Errorf("connector command %q metadata exceeds its size limit", command.Name)
		}
		if schemaHash, err := hashJSON(command.InputSchema); err != nil || schemaHash != command.InputSchemaHash {
			return fmt.Errorf("connector command %q input schema hash mismatch", command.Name)
		}
		if schemaHash, err := hashJSON(command.OutputSchema); err != nil || schemaHash != command.OutputSchemaHash {
			return fmt.Errorf("connector command %q output schema hash mismatch", command.Name)
		}
	}
	for _, directory := range descriptor.Directories {
		if !operationName.MatchString(directory.Name) || directory.Revision <= 0 {
			return fmt.Errorf("invalid connector directory %q", directory.Name)
		}
		if _, ok := seen["d:"+directory.Name]; ok {
			return fmt.Errorf("duplicate connector directory %q", directory.Name)
		}
		seen["d:"+directory.Name] = struct{}{}
		if len(directory.Description) > 4096 {
			return fmt.Errorf("connector directory %q description exceeds its size limit", directory.Name)
		}
	}
	return nil
}

func hashJSON(raw []byte) (string, error) {
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return "", err
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func validateHash(value string) error {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		return errors.New("must be a lowercase SHA-256 digest")
	}
	if value != hex.EncodeToString(decoded) {
		return errors.New("must be a lowercase SHA-256 digest")
	}
	return nil
}

func DescriptorHash(descriptor InterfaceDescriptor) (string, []byte, error) {
	sort.Slice(descriptor.Commands, func(i, j int) bool { return descriptor.Commands[i].Name < descriptor.Commands[j].Name })
	sort.Slice(descriptor.Directories, func(i, j int) bool { return descriptor.Directories[i].Name < descriptor.Directories[j].Name })
	raw, err := json.Marshal(descriptor)
	if err != nil {
		return "", nil, err
	}
	var protocolDescriptor protocol.Interface
	if err := json.Unmarshal(raw, &protocolDescriptor); err != nil {
		return "", nil, err
	}
	digest, err := protocol.InterfaceDigest(protocolDescriptor)
	return digest, raw, err
}

// Compatible requires exact contract, command revision/schema/mode, and
// directory revision. Published directory authority may be a superset.
func Compatible(spec NeedSpec, descriptor InterfaceDescriptor) error {
	if spec.ContractID != descriptor.ContractID {
		return errors.New("connector contract ID does not match the need")
	}
	commands := make(map[string]Command, len(descriptor.Commands))
	for _, command := range descriptor.Commands {
		commands[command.Name] = command
	}
	for _, required := range spec.Commands {
		provided, ok := commands[required.Name]
		if !ok || provided.Revision != required.Revision || provided.Mode != required.Mode ||
			provided.InputSchemaHash != required.InputSchemaHash || provided.OutputSchemaHash != required.OutputSchemaHash {
			return fmt.Errorf("connector command %q does not exactly match the need", required.Name)
		}
	}
	directories := make(map[string]Directory, len(descriptor.Directories))
	for _, directory := range descriptor.Directories {
		directories[directory.Name] = directory
	}
	for _, required := range spec.Directories {
		provided, ok := directories[required.Name]
		if !ok || provided.Revision != required.Revision ||
			(required.Read && !provided.Read) || (required.Write && !provided.Write) || (required.List && !provided.List) {
			return fmt.Errorf("connector directory %q does not satisfy the need", required.Name)
		}
	}
	return nil
}

func RequiredCommand(spec NeedSpec, name, mode string) (Command, error) {
	for _, command := range spec.Commands {
		if command.Name == name && command.Mode == mode {
			return command, nil
		}
	}
	return Command{}, fmt.Errorf("connector command %q was not declared by the agent need", name)
}
