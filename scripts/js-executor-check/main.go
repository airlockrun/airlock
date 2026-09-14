// Command js-executor-check verifies the packaged supervisor and its runtime.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/airlockrun/agentsdk/jsexec"
)

func main() {
	var err error
	switch {
	case len(os.Args) == 1:
		err = smoke()
	case len(os.Args) == 2 && os.Args[1] == "notices":
		err = notices()
	default:
		err = errors.New("usage: js-executor-check [notices]")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

type transport struct {
	io.Reader
	io.WriteCloser
	cmd *exec.Cmd
}

func (t transport) Close() error {
	_ = t.WriteCloser.Close()
	_ = t.cmd.Process.Kill()
	_ = t.cmd.Wait()
	return nil
}

func smoke() error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/local/bin/jsexecutor")
	in, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	t := transport{Reader: out, WriteCloser: in, cmd: cmd}
	client, err := jsexec.NewClient(t, jsexec.Options{
		Limits:   jsexec.DefaultLimits(),
		Bindings: []jsexec.Binding{{Name: "echo", Path: []string{"air", "echo"}}},
	})
	if err != nil {
		_ = t.Close()
		return err
	}
	defer client.Close()
	invoke := jsexec.InvokerFunc(func(_ context.Context, name string, args json.RawMessage) (json.RawMessage, error) {
		if name != "echo" {
			return nil, fmt.Errorf("unexpected callback %q", name)
		}
		return args, nil
	})
	for _, check := range []struct{ code, want string }{
		{`globalThis.count=40; return await air.echo(++count);`, `[41]`},
		{`return ++globalThis.count;`, `42`},
		{`try { await Deno.readTextFile("/etc/passwd"); return "allowed"; } catch(e) { return e.name; }`, `"NotCapable"`},
	} {
		result, err := client.Execute(ctx, check.code, invoke)
		if err != nil {
			return err
		}
		if string(result.Output) != check.want {
			return fmt.Errorf("smoke output %s, want %s", result.Output, check.want)
		}
	}
	version, err := exec.CommandContext(ctx, "/usr/bin/deno", "--version").Output()
	if err != nil {
		return err
	}
	fmt.Print(string(version))
	fmt.Println("executor protocol smoke: OK")
	return nil
}

// Notices use the compiled package graph, including Go's own license, rather
// than Airlock's unrelated server dependency inventory.
func notices() error {
	cmd := exec.Command("go", "list", "-deps", "-f", `{{with .Module}}{{.Path}}|{{.Dir}}{{end}}`, "./cmd/jsexecutor")
	out, err := cmd.Output()
	if err != nil {
		return err
	}
	fmt.Println("# Executor Supervisor Third-Party Notices")
	seen := map[string]bool{}
	modules := append([]string{"Go|" + runtime.GOROOT()}, strings.Split(string(out), "\n")...)
	for _, module := range modules {
		name, dir, ok := strings.Cut(module, "|")
		if !ok || seen[name] {
			continue
		}
		seen[name] = true
		var licenses []string
		for _, pattern := range []string{"LICENSE*", "LICENCE*", "COPYING*"} {
			paths, err := filepath.Glob(filepath.Join(dir, pattern))
			if err != nil {
				return err
			}
			licenses = append(licenses, paths...)
		}
		if len(licenses) == 0 {
			return fmt.Errorf("no license for %s", name)
		}
		noticeFiles, err := filepath.Glob(filepath.Join(dir, "NOTICE*"))
		if err != nil {
			return err
		}
		licenses = append(licenses, noticeFiles...)
		fmt.Printf("\n## %s\n", name)
		for _, path := range licenses {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			fmt.Printf("\n%s\n", data)
		}
	}
	return nil
}
