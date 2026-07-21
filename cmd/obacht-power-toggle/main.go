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
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"syscall"

	"github.com/obacht-dev/obacht-agent/internal/unitpolicy"
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
# systemd actions, mediated by the validating 'svc' subcommand below, and
# install/remove agent-staged managed-service units, mediated by the
# validating 'unit' subcommand (internal/unitpolicy content policy).
# To disable, run: sudo obacht-power-toggle disable
obacht ALL=(root) NOPASSWD: /usr/local/sbin/obacht-power-toggle svc *
obacht ALL=(root) NOPASSWD: /usr/local/sbin/obacht-power-toggle unit *
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
	case "unit":
		mustRoot()
		os.Exit(unitCmd(os.Args[2:]))
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
	fmt.Fprintln(os.Stderr, "usage: obacht-power-toggle {enable|disable|status|svc <verb> <unit>|unit {install|remove} <unit>}")
}

// unitCmd validates and installs/removes an agent-staged managed-service
// unit. Trust model: the staged file is written by the UNPRIVILEGED obacht
// user, so its content is fully attacker-controlled if the agent is
// compromised — the unitpolicy content validation below is the actual
// privilege boundary, and it runs HERE (as root), independently of whatever
// the agent claims to have validated. The helper accepts only a unit NAME;
// the staging path is fixed, so no caller-supplied paths are ever opened.
func unitCmd(args []string) int {
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: obacht-power-toggle unit {install|remove} <unit>")
		return 2
	}
	verb, name := args[0], args[1]
	if err := unitpolicy.ValidateName(name); err != nil {
		fmt.Fprintln(os.Stderr, "unit:", err)
		return 2
	}
	installedPath := filepath.Join(unitpolicy.UnitDir, name)
	switch verb {
	case "install":
		content, err := readStagedUnit(name)
		if err != nil {
			fmt.Fprintln(os.Stderr, "unit install:", err)
			return 2
		}
		if err := unitpolicy.Validate(name, content); err != nil {
			fmt.Fprintln(os.Stderr, "unit install: policy rejected:", err)
			return 2
		}
		if err := atomicWriteRoot(installedPath, content, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "unit install:", err)
			return 2
		}
		if rc := runSystemctl("daemon-reload"); rc != 0 {
			return rc
		}
		if rc := runSystemctl("enable", name); rc != 0 {
			return rc
		}
		fmt.Printf("unit %s installed\n", name)
		return 0
	case "remove":
		// Best-effort stop/disable; the unit may already be gone.
		_ = runSystemctl("disable", "--now", name)
		if err := os.Remove(installedPath); err != nil && !os.IsNotExist(err) {
			fmt.Fprintln(os.Stderr, "unit remove:", err)
			return 2
		}
		if rc := runSystemctl("daemon-reload"); rc != 0 {
			return rc
		}
		fmt.Printf("unit %s removed\n", name)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unit: verb %q not allowed\n", verb)
		return 2
	}
}

// readStagedUnit opens the staged unit file symlink-safely (O_NOFOLLOW) and
// enforces regular-file + size limits before any parsing happens.
func readStagedUnit(name string) ([]byte, error) {
	stagePath := filepath.Join(unitpolicy.StagingDir, name)
	fh, err := os.OpenFile(stagePath, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open staged unit %s: %w", stagePath, err)
	}
	defer fh.Close()
	st, err := fh.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("staged unit %s is not a regular file", stagePath)
	}
	if st.Size() > unitpolicy.MaxUnitSize {
		return nil, fmt.Errorf("staged unit %s exceeds %d bytes", stagePath, unitpolicy.MaxUnitSize)
	}
	return io.ReadAll(io.LimitReader(fh, unitpolicy.MaxUnitSize+1))
}

// atomicWriteRoot writes a root-owned file via tmp+rename in the target dir.
func atomicWriteRoot(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".obacht-unit-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func runSystemctl(args ...string) int {
	cmd := exec.Command(systemctlPath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode()
		}
		fmt.Fprintln(os.Stderr, "systemctl:", err)
		return 1
	}
	return 0
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
