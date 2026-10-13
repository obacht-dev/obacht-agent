package system

import "strings"

// hostDataPlaceholder is resolved by the darwin driver at apply time to the
// instance's data directory (spec v2.9). The materialiser leaves it literal,
// like ${host.gateway}: the api cannot know the device's paths.
const hostDataPlaceholder = "${host.data}"

// dataDirEnv is always exported into a host service's environment so a
// binary can find its instance data without the placeholder.
const dataDirEnv = "OBACHT_DATA_DIR"

// expandHostData returns the argv and environment to render into the plist:
// every ${host.data} in args and env values replaced with dataDir, plus
// OBACHT_DATA_DIR=dataDir. The spec itself is not mutated.
func expandHostData(hs *HostServiceSpec, dataDir string) (args []string, env map[string]string) {
	sub := func(in string) string { return strings.ReplaceAll(in, hostDataPlaceholder, dataDir) }
	args = make([]string, len(hs.Args))
	for i, a := range hs.Args {
		args[i] = sub(a)
	}
	env = make(map[string]string, len(hs.Env)+1)
	for k, v := range hs.Env {
		env[k] = sub(v)
	}
	env[dataDirEnv] = dataDir
	return args, env
}
