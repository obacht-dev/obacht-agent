// obacht-power-toggle is a tiny privileged helper that flips Power Mode
// on/off by writing or removing /etc/sudoers.d/obacht-power.
//
// It is the ONLY thing the unprivileged `obacht` user is allowed to run
// as root via sudo (see /etc/sudoers.d/obacht-bootstrap installed by
// install.sh). Keeping the privileged surface this small means:
//
//   - if obacht-agent is compromised, the attacker can flip the switch
//     but cannot directly write arbitrary sudoers rules
//   - the file we write is fixed-content, fully audited, and limited to
//     the specific commands listed in POWER_SUDOERS_CONTENT below
//   - we visudo-validate before installing so a syntax error can never
//     brick the host's sudoers
//
// Usage:
//
//   obacht-power-toggle enable        # writes /etc/sudoers.d/obacht-power
//   obacht-power-toggle disable       # removes it
//   obacht-power-toggle status        # exit 0 if enabled, 1 if not, 2 on error
//   obacht-power-toggle --help
//
// The binary refuses to do anything if uid != 0 — sudo enforces this,
// but the runtime check is defense-in-depth.
//
// IMPORTANT: this file's path / argv0 must EXACTLY match what
// /etc/sudoers.d/obacht-bootstrap allows. Any rename requires
// regenerating that file, otherwise the agent will lose the ability to
// flip the switch (which is fine — fail-closed is the right behavior).

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
)

const (
	sudoersPath = "/etc/sudoers.d/obacht-power"

	// systemctlPath is the only binary `svc` will ever exec. Pinned with a
	// full path so a PATH hijack can't substitute it.
	systemctlPath = "/usr/bin/systemctl"

	// The content is intentionally the smallest grant we need. SEC-13: the
	// unprivileged `obacht` user is granted ONLY the `svc` subcommand of this
	// very binary — never raw systemctl with a `*.service` wildcard (which
	// fnmatch-expands to multiple space-separated units, allowing a
	// "obacht-x.service evil.service" smuggle) and never the vestigial
	// iptables/ip6tables rules (which were never invoked by any agent code).
	// `svc` itself validates the verb against a closed allow-list and the
	// unit against ^obacht-…\.(service|timer)$ as a single token before it
	// execs systemctl, so this grant cannot touch non-obacht units.
	powerSudoersContent = `# Managed by obacht-power-toggle. Do not edit by hand.
# Phase S5: Power Mode is ENABLED. The obacht user can run obacht-scoped
# systemd actions, mediated by the validating 'svc' subcommand below.
# To disable, run: sudo obacht-power-toggle disable
obacht ALL=(root) NOPASSWD: /usr/local/sbin/obacht-power-toggle svc *
`
)

// allowedSvcVerbs is the closed allow-list of systemctl actions `svc` exposes.
var allowedSvcVerbs = map[string]bool{
	"start":   true,
	"stop":    true,
	"restart": true,
	"reload":  true,
	"enable":  true,
	"disable": true,
}

// svcUnitRe constrains the unit to a single obacht-owned service/timer token.
// No spaces, no globs — this is the wildcard-smuggle defense.
var svcUnitRe = regexp.MustCompile(`^obacht-[a-zA-Z0-9@._-]+\.(service|timer)$`)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "--help", "-h", "help":
		usage()
	case "enable":
		mustRoot()
		if err := enable(); err != nil {
			fmt.Fprintln(os.Stderr, "enable:", err)
			os.Exit(2)
		}
		fmt.Println("power mode enabled")
	case "disable":
		mustRoot()
		if err := disable(); err != nil {
			fmt.Fprintln(os.Stderr, "disable:", err)
			os.Exit(2)
		}
		fmt.Println("power mode disabled")
	case "svc":
		mustRoot()
		os.Exit(svc(os.Args[2:]))
	case "status":
		if status() {
			fmt.Println("enabled")
			os.Exit(0)
		}
		fmt.Println("disabled")
		os.Exit(1)
	default:
		fmt.Fprintln(os.Stderr, "unknown command:", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: obacht-power-toggle {enable|disable|status|svc <verb> <unit>}")
}

// svc validates a (verb, unit) pair and, only if both pass the closed
// allow-list + obacht-unit regex, execs `systemctl <verb> <unit>` as root.
// This is the single privileged entrypoint the `obacht` user is granted in
// Power Mode (SEC-13). Returning a non-zero exit code propagates systemctl's
// own status to the caller.
func svc(args []string) int {
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: obacht-power-toggle svc <verb> <unit>")
		return 2
	}
	verb, unit := args[0], args[1]
	if !allowedSvcVerbs[verb] {
		fmt.Fprintf(os.Stderr, "svc: verb %q not allowed\n", verb)
		return 2
	}
	if !svcUnitRe.MatchString(unit) {
		fmt.Fprintf(os.Stderr, "svc: unit %q must match ^obacht-…\\.(service|timer)$\n", unit)
		return 2
	}
	cmd := exec.Command(systemctlPath, verb, unit)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode()
		}
		fmt.Fprintln(os.Stderr, "svc:", err)
		return 1
	}
	return 0
}

func mustRoot() {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "obacht-power-toggle must run as root (via sudo)")
		os.Exit(2)
	}
}

// enable writes the sudoers fragment, but only after visudo-validating
// it through a tmpfile so a botched binary update can't brick the host.
func enable() error {
	dir := filepath.Dir(sudoersPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".obacht-power-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // safe even if rename succeeded
	if _, err := tmp.WriteString(powerSudoersContent); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o440); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// visudo -c -f <file> exits non-zero on any syntax error.
	if visudo, err := exec.LookPath("visudo"); err == nil {
		cmd := exec.Command(visudo, "-c", "-f", tmpName)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("visudo rejected fragment: %v\n%s", err, out)
		}
	}
	// Atomic replace.
	return os.Rename(tmpName, sudoersPath)
}

func disable() error {
	err := os.Remove(sudoersPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func status() bool {
	_, err := os.Stat(sudoersPath)
	return err == nil
}
