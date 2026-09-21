// mattest is a dev helper (not shipped): materialise a manifest + user config
// into the InstanceConfig JSON that `obachtctl instance upsert --config-file`
// consumes, for testing template manifests on a device without registry
// or signing (see obacht monorepo docs, template e2e harness).
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/obacht-dev/obacht-agent/internal/manifest"
)

func main() {
	if len(os.Args) < 5 {
		fmt.Fprintln(os.Stderr, "usage: mattest <manifest.yml> <userConfigJSON|-> <instanceID> <templateID> [version]")
		os.Exit(2)
	}
	mb, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	cfg := map[string]any{}
	if os.Args[2] != "-" {
		if err := json.Unmarshal([]byte(os.Args[2]), &cfg); err != nil {
			panic(err)
		}
	}
	ver := ""
	if len(os.Args) > 5 {
		ver = os.Args[5]
	}
	built, err := manifest.BuildInstanceConfig(mb, cfg, os.Args[3], os.Args[4], ver)
	if err != nil {
		fmt.Fprintln(os.Stderr, "materialize:", err)
		os.Exit(1)
	}
	out, _ := json.Marshal(built)
	fmt.Println(string(out))
}
