// airlockvet runs the project-specific static checks for the airlock
// codebase. Add new analyzers to the multichecker.Main call below.
package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/airlockrun/airlock/airlockvet"
	"golang.org/x/tools/go/analysis/multichecker"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "check" {
		if len(os.Args) != 2 {
			fmt.Fprintln(os.Stderr, "airlockvet check takes no flags or package overrides")
			os.Exit(2)
		}
		executable, err := os.Executable()
		if err == nil {
			err = check(func(dir string) error {
				cmd := exec.Command(executable, "./...")
				cmd.Dir = dir
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				return cmd.Run()
			})
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	multichecker.Main(
		airlockvet.Suppressions,
		airlockvet.NoDBQ,
		airlockvet.WriteProto,
		airlockvet.AgentWire,
		airlockvet.NoInlineRole,
		airlockvet.ServiceAuthz,
		airlockvet.Policy,
		airlockvet.CheckedAccess,
		airlockvet.Origins,
	)
}
