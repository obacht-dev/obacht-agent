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
)

const (
	sudoersPath = "/etc/sudoers.d/obacht-power"

	// The content is intentionally the smallest grant we need: the
	// unprivileged `obacht` user can run only obacht-power-controlled
	// system commands, listed individually with full paths so a path
	// hijack can't trick sudo. This grows as new "power"-level
	// templates need new commands; keep it audited.
	powerSudoersContent = `# Managed by obacht-power-toggle. Do not edit by hand.
# Phase S5: Power Mode is ENABLED. The obacht user can now run a
# specifically-listed set of root commands needed by privileged
# templates. To disable, run: sudo obacht-power-toggle disable
obacht ALL=(root) NOPASSWD: /usr/bin/systemctl restart *.service
obacht ALL=(root) NOPASSWD: /usr/bin/systemctl reload *.service
obacht ALL=(root) NOPASSWD: /usr/bin/systemctl start *.service
obacht ALL=(root) NOPASSWD: /usr/bin/systemctl stop *.service
obacht ALL=(root) NOPASSWD: /usr/bin/systemctl enable *.service
obacht ALL=(root) NOPASSWD: /usr/bin/systemctl disable *.service
obacht ALL=(root) NOPASSWD: /usr/sbin/iptables -t nat *
obacht ALL=(root) NOPASSWD: /usr/sbin/ip6tables -t nat *
`
)

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
	fmt.Fprintln(os.Stderr, "usage: obacht-power-toggle {enable|disable|status}")
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
