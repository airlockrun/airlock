// Package scaffold materializes agent project templates.
package scaffold

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"text/template"
)

//go:embed templates/*
var templates embed.FS

// ScaffoldData holds values substituted into templates.
type ScaffoldData struct {
	AgentID         string // UUID
	Module          string // Go module name for the agent (typically "agent")
	GoVersion       string // e.g., "1.24"
	AgentSDKVersion string // displayed in the agent's go.mod require line (informational — replace directives are unconditional)
}

// templateFile maps a template name to its output path relative to the target directory.
type templateFile struct {
	Template string // path within embedded FS
	Output   string // output path relative to target dir
}

var templateFiles = []templateFile{
	{"templates/main.go.tmpl", "main.go"},
	{"templates/scaffold_gen.go.tmpl", "scaffold_gen.go"},
	{"templates/go.mod.tmpl", "go.mod"},
	{"templates/sqlc.yaml.tmpl", "sqlc.yaml"},
	{"templates/layout.templ.tmpl", "views/layout.templ"},
	{"templates/index.templ.tmpl", "views/index.templ"},
	{"templates/db_migrations_doc.go.tmpl", "db/migrations/doc.go"},
}

// emptyDirs are created with a .gitkeep file so they survive git operations.
var emptyDirs = []string{
	"db/queries",
}

// GenerateDockerfile renders the Dockerfile template into dir/Dockerfile.
// Called by the build pipeline before every docker build so agents always
// get the latest Dockerfile — even on upgrades of previously-built agents.
func GenerateDockerfile(dir string, data ScaffoldData) error {
	if data.AgentSDKVersion == "" {
		return fmt.Errorf("scaffold: AgentSDKVersion is required")
	}
	tmpl, err := template.New("Dockerfile.tmpl").
		Option("missingkey=error").
		ParseFS(templates, "templates/Dockerfile.tmpl")
	if err != nil {
		return fmt.Errorf("parse Dockerfile template: %w", err)
	}

	outPath := filepath.Join(dir, "Dockerfile")
	f, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("create Dockerfile: %w", err)
	}
	defer f.Close()

	if err := tmpl.Execute(f, data); err != nil {
		return fmt.Errorf("render Dockerfile: %w", err)
	}
	return nil
}

// Materialize renders all scaffold templates into dir using data.
// Panics if a template references a missing field in data.
func Materialize(dir string, data ScaffoldData) error {
	if data.AgentSDKVersion == "" {
		return fmt.Errorf("scaffold: AgentSDKVersion is required (callers should pass agentsdk.Version with v prefix)")
	}
	tmpl, err := template.New("").
		Option("missingkey=error").
		ParseFS(templates, "templates/*.tmpl")
	if err != nil {
		return fmt.Errorf("parse templates: %w", err)
	}

	// Create empty directories with .gitkeep so they survive git operations.
	for _, d := range emptyDirs {
		dirPath := filepath.Join(dir, d)
		if err := os.MkdirAll(dirPath, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", d, err)
		}
		if err := os.WriteFile(filepath.Join(dirPath, ".gitkeep"), nil, 0o644); err != nil {
			return fmt.Errorf("gitkeep %s: %w", d, err)
		}
	}

	// Render each template
	for _, tf := range templateFiles {
		outPath := filepath.Join(dir, tf.Output)

		if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
			return fmt.Errorf("mkdir for %s: %w", tf.Output, err)
		}

		f, err := os.Create(outPath)
		if err != nil {
			return fmt.Errorf("create %s: %w", tf.Output, err)
		}

		t := tmpl.Lookup(filepath.Base(tf.Template))
		if t == nil {
			f.Close()
			return fmt.Errorf("template %s not found", tf.Template)
		}

		if err := t.Execute(f, data); err != nil {
			f.Close()
			return fmt.Errorf("render %s: %w", tf.Output, err)
		}

		if err := f.Close(); err != nil {
			return fmt.Errorf("close %s: %w", tf.Output, err)
		}
	}

	return nil
}
