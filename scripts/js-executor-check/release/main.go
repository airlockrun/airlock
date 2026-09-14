// Command release checks published images without accessing private source or
// mutating a registry or Git repository. It uses only the standard library.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var communityImagePattern = regexp.MustCompile(`ghcr\.io/airlockrun/airlock[a-z-]*[^\s"'}]*`)
var sourceRevisionPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var versionPattern = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(rc|alpha|beta|dev)\.(0|[1-9][0-9]*))?$`)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	if err := run(ctx, os.Args[1:], output); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

type command struct {
	dir  string
	name string
	args []string
}

type commandRunner func(context.Context, command) (string, error)

func output(ctx context.Context, spec command) (string, error) {
	cmd := exec.CommandContext(ctx, spec.name, spec.args...)
	cmd.Dir = spec.dir
	cmd.Env = append(os.Environ(), "GOWORK=off")
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	return string(out), err
}

func run(ctx context.Context, args []string, runner commandRunner) error {
	flags := flag.NewFlagSet("release", flag.ContinueOnError)
	source := flags.String("source", "", "candidate source directory")
	version := flags.String("version", "", "candidate Airlock version")
	revision := flags.String("internal-revision", "", "exact archived internal revision (HQ)")
	public := flags.Bool("public", false, "require consistent image provenance without equating internal and public commits")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *source == "" || !versionPattern.MatchString(*version) || *public == (*revision != "") {
		return errors.New("require --source, --version and exactly one of --public or --internal-revision")
	}
	return checkPublicImages(ctx, *source, *version, *revision, runner)
}

// Registry reads happen before any public Git mutation. The archived compose
// inventory is authoritative; local .env overrides cannot change this gate.
func checkPublicImages(ctx context.Context, source, version, revision string, runner commandRunner) error {
	if revision != "" && !sourceRevisionPattern.MatchString(revision) {
		return fmt.Errorf("invalid source revision %q", revision)
	}
	file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(source, "version.go"), nil, 0)
	if err != nil {
		return err
	}
	var versions []string
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			value := spec.(*ast.ValueSpec)
			for i, name := range value.Names {
				if name.Name != "Version" || i >= len(value.Values) {
					continue
				}
				literal, ok := value.Values[i].(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					return errors.New("candidate Version must be a string constant")
				}
				v, err := strconv.Unquote(literal.Value)
				if err != nil {
					return err
				}
				versions = append(versions, "v"+v)
			}
		}
	}
	if len(versions) != 1 || versions[0] != version {
		return fmt.Errorf("candidate Version %v does not match %s", versions, version)
	}
	compose, err := os.ReadFile(filepath.Join(source, "docker-compose.yml"))
	if err != nil {
		return err
	}
	matches := communityImagePattern.FindAllString(string(compose), -1)
	if len(matches) == 0 {
		return errors.New("compose contains no community images")
	}
	var images []string
	for _, match := range matches {
		_, tag, ok := strings.Cut(match, ":")
		if !ok || tag != version {
			return fmt.Errorf("compose image %s does not match %s", match, version)
		}
		images = append(images, match)
	}
	slices.Sort(images)
	if !slices.Contains(images, "ghcr.io/airlockrun/airlock-js-executor:"+version) {
		return errors.New("candidate inventory lacks the executor image")
	}
	var executorImage string
	var labels map[string]string
	for _, image := range slices.Compact(images) {
		manifestJSON, err := runner(ctx, command{name: "docker", args: []string{
			"buildx", "imagetools", "inspect", image, "--format", "{{json .Manifest}}",
		}})
		if err != nil {
			return fmt.Errorf("inspect %s manifest: %w", image, err)
		}
		var manifest struct{ Digest string }
		if err := json.Unmarshal([]byte(manifestJSON), &manifest); err != nil {
			return fmt.Errorf("decode %s manifest: %w", image, err)
		}
		if !digestPattern.MatchString(manifest.Digest) {
			return fmt.Errorf("%s: invalid manifest digest", image)
		}
		pinnedImage := strings.Split(image, ":")[0] + "@" + manifest.Digest
		output, err := runner(ctx, command{name: "docker", args: []string{
			"buildx", "imagetools", "inspect", pinnedImage, "--format", "{{json .Image}}",
		}})
		if err != nil {
			return fmt.Errorf("inspect %s: %w", image, err)
		}
		var config struct {
			Architecture string `json:"architecture"`
			OS           string `json:"os"`
			Config       struct {
				Labels map[string]string `json:"Labels"`
			} `json:"config"`
		}
		if err := json.Unmarshal([]byte(output), &config); err != nil {
			return fmt.Errorf("decode %s config: %w", image, err)
		}
		// The publication matrix builds Linux amd64. Reject empty metadata and
		// an unexpected multi-platform map rather than passing it vacuously.
		if config.OS != "linux" || config.Architecture != "amd64" {
			return fmt.Errorf("%s: expected linux/amd64 image config", image)
		}
		imageRevision := config.Config.Labels["org.opencontainers.image.revision"]
		if !sourceRevisionPattern.MatchString(imageRevision) {
			return fmt.Errorf("%s: invalid image.revision %q", image, imageRevision)
		}
		if revision == "" {
			revision = imageRevision
		}
		for _, label := range []struct{ key, want string }{
			{"org.opencontainers.image.version", version},
			{"org.opencontainers.image.source", "https://github.com/airlockrun/airlock-internal"},
			{"org.opencontainers.image.revision", revision},
		} {
			if got := config.Config.Labels[label.key]; got != label.want {
				return fmt.Errorf("%s: %s = %q, want %q", image, label.key, got, label.want)
			}
		}
		if strings.HasPrefix(image, "ghcr.io/airlockrun/airlock-js-executor:") {
			labels, err = executorLabels(ctx, source, runner)
			if err != nil {
				return err
			}
			for key, want := range labels {
				if got := config.Config.Labels[key]; got != want {
					return fmt.Errorf("%s: %s = %q, want %q", image, key, got, want)
				}
			}
			executorImage = pinnedImage
		}
	}
	// All metadata is checked before executing anything. Digest references bind
	// the smoke to inspected artifacts even if a registry tag changes meanwhile.
	deno := labels["run.airlock.executor.deno-image"]
	for _, image := range []string{deno, executorImage} {
		if _, err := runner(ctx, command{name: "docker", args: []string{"pull", "--platform", "linux/amd64", image}}); err != nil {
			return fmt.Errorf("pull %s: %w", image, err)
		}
	}
	baseVersion, err := runImage(ctx, deno, "/usr/bin/deno", []string{"--version"}, runner)
	if err != nil {
		return err
	}
	if !regexp.MustCompile(`^deno [0-9]+\.[0-9]+\.[0-9]+(?: |\n)`).MatchString(baseVersion) {
		return errors.New("invalid canonical Deno version output")
	}
	imageVersion, err := runImage(ctx, executorImage, "/usr/bin/deno", []string{"--version"}, runner)
	if err != nil {
		return err
	}
	if baseVersion != imageVersion {
		return errors.New("executor Deno version drift")
	}
	protocol, err := runImage(ctx, executorImage, "/bin/cat", []string{"/usr/local/share/jsexec/protocol.sha256"}, runner)
	if err != nil {
		return err
	}
	if strings.TrimSpace(protocol) != labels["run.airlock.executor.protocol-source"]+"  jsexec/protocol.go" {
		return errors.New("executor protocol source drift")
	}
	smoke, err := runImage(ctx, executorImage, "/usr/local/bin/js-executor-check", nil, runner)
	if err != nil {
		return fmt.Errorf("executor smoke: %w", err)
	}
	if !strings.Contains(smoke, "executor protocol smoke: OK\n") {
		return errors.New("executor smoke did not report success")
	}
	fmt.Printf("release images ready for %s; internal source revision %s\n%s", version, revision, smoke)
	return nil
}

func runImage(ctx context.Context, image, entrypoint string, args []string, runner commandRunner) (string, error) {
	name := "airlock-release-check-" + rand.Text()
	argv := []string{"run", "--rm", "--pull", "never", "--platform", "linux/amd64", "--name", name,
		"--network", "none", "--read-only", "--user", "65532:65532", "--cap-drop", "ALL",
		"--security-opt", "no-new-privileges", "--memory", "256m", "--memory-swap", "256m",
		"--cpus", "1", "--pids-limit", "128", "--tmpfs", "/tmp:rw,noexec,nosuid,size=32m",
		"--entrypoint", entrypoint, image}
	out, err := runner(ctx, command{name: "docker", args: append(argv, args...)})
	if err != nil {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = runner(cleanup, command{name: "docker", args: []string{"rm", "--force", name}})
		return "", fmt.Errorf("run %s in %s: %w", entrypoint, image, err)
	}
	return out, nil
}

func executorLabels(ctx context.Context, source string, runner commandRunner) (map[string]string, error) {
	gomod, err := os.ReadFile(filepath.Join(source, "go.mod"))
	if err != nil {
		return nil, err
	}
	pins := regexp.MustCompile(`(?m)^\s*(?:require\s+)?github\.com/airlockrun/agentsdk\s+(v[^\s]+)`).FindAllStringSubmatch(string(gomod), -1)
	if len(pins) != 1 {
		return nil, errors.New("expected one published SDK pin in go.mod")
	}
	// Module downloads may update go.sum. Keep candidate bytes unchanged while
	// still verifying the download against the candidate's committed checksums.
	resolution, err := os.MkdirTemp("", "airlock-release-sdk-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(resolution)
	for _, name := range []string{"go.mod", "go.sum"} {
		data, err := os.ReadFile(filepath.Join(source, name))
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(resolution, name), data, 0o600); err != nil {
			return nil, err
		}
	}
	out, err := runner(ctx, command{dir: resolution, name: "go", args: []string{
		"mod", "download", "-json", "github.com/airlockrun/agentsdk@" + pins[0][1],
	}})
	if err != nil {
		return nil, err
	}
	var module struct{ Dir string }
	if err := json.Unmarshal([]byte(out), &module); err != nil {
		return nil, err
	}
	if module.Dir == "" {
		return nil, errors.New("SDK module source directory is missing")
	}
	assets, err := os.ReadFile(filepath.Join(module.Dir, "jsexec/assets.go"))
	if err != nil {
		return nil, err
	}
	deno := regexp.MustCompile(`(?m)^const DenoImage = "(denoland/deno@sha256:[0-9a-f]{64})"$`).FindAllStringSubmatch(string(assets), -1)
	if len(deno) != 1 {
		return nil, errors.New("SDK must declare one canonical Deno digest")
	}
	protocol, err := os.ReadFile(filepath.Join(module.Dir, "jsexec/protocol.go"))
	if err != nil {
		return nil, err
	}
	if len(protocol) == 0 {
		return nil, errors.New("SDK protocol source is empty")
	}
	return map[string]string{
		"run.airlock.executor.deno-image":      deno[0][1],
		"run.airlock.executor.protocol-source": fmt.Sprintf("%x", sha256.Sum256(protocol)),
		"run.airlock.executor.sdk-version":     pins[0][1],
	}, nil
}
