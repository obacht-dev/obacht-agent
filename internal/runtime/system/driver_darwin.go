//go:build darwin

// macOS host-service runtime. Unlike the Pi (systemd) driver, this runs a
// service directly on the host — outside the VM sandbox — as a user-level
// LaunchAgent. It exists for workloads that need full system/GPU access the VM
// cannot give (Ollama). The agent here runs as the GUI user (a child of the
// Obacht app), so everything is in the user's launchd domain (gui/<uid>); no
// root, no system-wide daemons.
//
// Security: the only inputs come from a registry-signed manifest, and the spec
// is structured (allowlisted binary + argv + env), never a raw plist or shell.
// The binary is pinned by sha256 and verified before it is ever executed.

package system

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// labelPrefix namespaces every plist obacht owns. listCustomServicesImpl and
// Remove rely on it, and validation refuses anything outside it.
const labelPrefix = "dev.obacht.hostsvc."

// instanceIDSanitizeRe maps an instance id onto a launchd-label-safe leaf.
var instanceIDSanitizeRe = regexp.MustCompile(`[^a-zA-Z0-9._-]`)

// Driver manages obacht's host services via launchd. Paths are overridable via
// env so tests don't touch the user's real LaunchAgents.
type Driver struct {
	log        *slog.Logger
	binDir     string // managed binaries          (…/obacht/host/bin)
	dataDir    string // per-service data root      (…/obacht/host/data)
	agentDir   string // ~/Library/LaunchAgents
	logDir     string // ~/Library/Logs/obacht
	uid        int
	httpClient *http.Client
}

func New(log *slog.Logger) *Driver {
	home, _ := os.UserHomeDir()
	base := envOr("OBACHT_HOST_BASE_DIR", filepath.Join(home, "Library", "Application Support", "obacht", "host"))
	return &Driver{
		log:        log,
		binDir:     filepath.Join(base, "bin"),
		dataDir:    filepath.Join(base, "data"),
		agentDir:   envOr("OBACHT_LAUNCHAGENTS_DIR", filepath.Join(home, "Library", "LaunchAgents")),
		logDir:     envOr("OBACHT_HOST_LOG_DIR", filepath.Join(home, "Library", "Logs", "obacht")),
		uid:        os.Getuid(),
		httpClient: &http.Client{Timeout: 10 * time.Minute},
	}
}

// hostLabel is the deterministic launchd label for an instance. Deriving it
// from the instance id (rather than the spec) means Remove/Status work with
// only the id, and a hostile spec cannot pick a label outside our namespace.
func hostLabel(instanceID string) string {
	return labelPrefix + instanceIDSanitizeRe.ReplaceAllString(instanceID, "-")
}

func (d *Driver) plistPath(label string) string { return filepath.Join(d.agentDir, label+".plist") }
func (d *Driver) guiDomain() string             { return fmt.Sprintf("gui/%d", d.uid) }

// Apply ensures the pinned binary is present + verified, writes the plist, and
// (re)loads the LaunchAgent. Idempotent: an unchanged plist does not restart
// the service (Ollama restarts are heavy).
func (d *Driver) Apply(ctx context.Context, instanceID string, spec Spec) error {
	if instanceID == "" || spec.HostService == nil {
		return fmt.Errorf("apply host-service: instance id and host_service are required")
	}
	if err := spec.Validate(); err != nil {
		return fmt.Errorf("apply host-service: %w", err)
	}
	hs := spec.HostService

	binPath, err := d.ensureBinary(ctx, hs)
	if err != nil {
		return fmt.Errorf("ensure binary: %w", err)
	}

	dataDir := hs.DataDir
	if dataDir == "" {
		dataDir = filepath.Join(d.dataDir, hostLabel(instanceID))
	}
	for _, dir := range []string{d.agentDir, d.logDir, dataDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}

	label := hostLabel(instanceID)
	plist := renderPlist(label, binPath, hs.Args, hs.Env, d.logDir)
	changed, err := writeIfDifferent(d.plistPath(label), []byte(plist), 0o644)
	if err != nil {
		return fmt.Errorf("write plist: %w", err)
	}
	if err := d.load(ctx, label, changed); err != nil {
		return err
	}
	d.log.Info("applied host-service", "instance", instanceID, "label", label, "binary", hs.Binary, "changed", changed)
	return nil
}

// Remove boots the LaunchAgent out and deletes its plist. Data (e.g. models) is
// left in place — mirrors the Pi convention of preserving instance data. The
// unitName argument is unused on macOS (the label is derived from the id).
func (d *Driver) Remove(ctx context.Context, instanceID, _ string) error {
	if instanceID == "" {
		return nil
	}
	label := hostLabel(instanceID)
	_ = d.runLaunchctl(ctx, "bootout", d.guiDomain()+"/"+label) // ignore: may not be loaded
	if err := os.Remove(d.plistPath(label)); err != nil && !os.IsNotExist(err) {
		d.log.Warn("remove plist", "label", label, "err", err)
	}
	d.log.Info("removed host-service", "instance", instanceID, "label", label)
	return nil
}

// Status maps launchd state to the systemd-style vocabulary the rest of the
// agent uses ("active"/"inactive"), or "" if unknown. unitName is the label.
func (d *Driver) Status(ctx context.Context, unitName string) (string, error) {
	if unitName == "" {
		return "", nil
	}
	out, err := d.launchctlOutput(ctx, "print", d.guiDomain()+"/"+unitName)
	if err != nil {
		return "", nil // not loaded → unknown
	}
	if strings.Contains(out, "state = running") {
		return "active", nil
	}
	return "inactive", nil
}

// load (re)bootstraps the LaunchAgent. On a changed plist it boots out + back
// in and force-restarts; otherwise it only ensures the service is loaded and
// running without a needless restart.
func (d *Driver) load(ctx context.Context, label string, changed bool) error {
	domain := d.guiDomain()
	svc := domain + "/" + label
	plist := d.plistPath(label)
	if changed {
		_ = d.runLaunchctl(ctx, "bootout", svc) // ignore: may not be loaded yet
		if err := d.runLaunchctl(ctx, "bootstrap", domain, plist); err != nil {
			return fmt.Errorf("bootstrap %s: %w", label, err)
		}
		return d.runLaunchctl(ctx, "kickstart", "-k", svc)
	}
	if st, _ := d.Status(ctx, label); st == "" {
		if err := d.runLaunchctl(ctx, "bootstrap", domain, plist); err != nil {
			return fmt.Errorf("bootstrap %s: %w", label, err)
		}
	}
	_ = d.runLaunchctl(ctx, "kickstart", svc) // start if stopped; harmless if running
	return nil
}

// ensureBinary returns the path to the verified, pinned binary, downloading
// (and for archives, extracting) it if missing. The sha256 digest verifies the
// downloaded artifact BEFORE it is extracted or executed.
func (d *Driver) ensureBinary(ctx context.Context, hs *HostServiceSpec) (string, error) {
	if err := os.MkdirAll(d.binDir, 0o755); err != nil {
		return "", err
	}
	want := strings.TrimPrefix(hs.BinaryDigest, "sha256:")

	if hs.Archive == "tgz" {
		// Extraction dir is keyed by the verified digest, so a new version
		// (new digest) extracts fresh and a re-install reuses the existing one.
		extractDir := filepath.Join(d.binDir, hs.Binary+"-"+want[:16])
		binPath := filepath.Join(extractDir, hs.Binary)
		if isExecutable(binPath) {
			return binPath, nil // already extracted + verified
		}
		tgz := filepath.Join(d.binDir, "."+want[:16]+".tgz")
		if err := d.download(ctx, hs.BinaryURL, tgz, want, 0o644); err != nil {
			return "", err
		}
		defer os.Remove(tgz)
		if err := extractTarGz(tgz, extractDir); err != nil {
			return "", fmt.Errorf("extract %s: %w", hs.BinaryURL, err)
		}
		if !isExecutable(binPath) {
			return "", fmt.Errorf("binary %q not found (executable) in archive", hs.Binary)
		}
		return binPath, nil
	}

	// Raw binary.
	path := filepath.Join(d.binDir, hs.Binary)
	if sum, err := fileSHA256(path); err == nil && sum == want {
		return path, nil // already present + verified
	}
	if err := d.download(ctx, hs.BinaryURL, path, want, 0o755); err != nil {
		return "", err
	}
	return path, nil
}

func (d *Driver) download(ctx context.Context, url, dest, wantHex string, mode os.FileMode) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := d.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
	}
	tmp := dest + ".tmp"
	_ = os.Remove(tmp)
	fh, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return err
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(fh, h), resp.Body); err != nil {
		fh.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := fh.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != wantHex {
		_ = os.Remove(tmp)
		return fmt.Errorf("download %s: sha256 mismatch (got %s, want %s)", url, got, wantHex)
	}
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// MARK: - launchctl + small helpers

func (d *Driver) runLaunchctl(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, "launchctl", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("launchctl %s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (d *Driver) launchctlOutput(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "launchctl", args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func fileSHA256(path string) (string, error) {
	fh, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer fh.Close()
	h := sha256.New()
	if _, err := io.Copy(h, fh); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func isExecutable(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0
}

// withinDir reports whether target resolves inside dir (segment-boundary safe).
func withinDir(dir, target string) bool {
	dir = filepath.Clean(dir)
	target = filepath.Clean(target)
	return target == dir || strings.HasPrefix(target, dir+string(os.PathSeparator))
}

// extractTarGz unpacks a gzip tarball (already sha256-verified) into destDir,
// atomically (via a .tmp dir + rename). Hardened against path traversal — every
// entry must resolve inside destDir — and it skips symlinks/hardlinks/devices
// so a crafted (but here, verified) archive cannot plant links outside the tree
// or redirect a later write. Regular-file modes are preserved (so the binary
// keeps its +x bit); the gzip/tar content is trusted because the digest matched.
func extractTarGz(tgzPath, destDir string) error {
	f, err := os.Open(tgzPath)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()

	tmpDir := destDir + ".extract.tmp"
	_ = os.RemoveAll(tmpDir)
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		return err
	}

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			_ = os.RemoveAll(tmpDir)
			return err
		}
		clean := filepath.Clean(hdr.Name)
		if clean == "." || filepath.IsAbs(clean) || strings.HasPrefix(clean, "..") {
			continue
		}
		target := filepath.Join(tmpDir, clean)
		if !withinDir(tmpDir, target) {
			_ = os.RemoveAll(tmpDir)
			return fmt.Errorf("archive entry %q escapes destination", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				_ = os.RemoveAll(tmpDir)
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				_ = os.RemoveAll(tmpDir)
				return err
			}
			mode := os.FileMode(hdr.Mode).Perm() | 0o600
			out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, mode)
			if err != nil {
				_ = os.RemoveAll(tmpDir)
				return err
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				_ = os.RemoveAll(tmpDir)
				return err
			}
			out.Close()
		default:
			// symlink / hardlink / char / block / fifo — skipped for safety.
		}
	}

	_ = os.RemoveAll(destDir)
	if err := os.Rename(tmpDir, destDir); err != nil {
		_ = os.RemoveAll(tmpDir)
		return err
	}
	return nil
}

// renderPlist builds a minimal LaunchAgent plist. All dynamic values are XML
// escaped; the spec validator already rejects control characters.
func renderPlist(label, binary string, args []string, env map[string]string, logDir string) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	b.WriteString(`<plist version="1.0">` + "\n<dict>\n")
	b.WriteString("  <key>Label</key><string>" + xmlEscape(label) + "</string>\n")
	b.WriteString("  <key>ProgramArguments</key>\n  <array>\n")
	b.WriteString("    <string>" + xmlEscape(binary) + "</string>\n")
	for _, a := range args {
		b.WriteString("    <string>" + xmlEscape(a) + "</string>\n")
	}
	b.WriteString("  </array>\n")
	if len(env) > 0 {
		b.WriteString("  <key>EnvironmentVariables</key>\n  <dict>\n")
		for k, v := range env {
			b.WriteString("    <key>" + xmlEscape(k) + "</key><string>" + xmlEscape(v) + "</string>\n")
		}
		b.WriteString("  </dict>\n")
	}
	b.WriteString("  <key>RunAtLoad</key><true/>\n")
	b.WriteString("  <key>KeepAlive</key><true/>\n")
	b.WriteString("  <key>StandardOutPath</key><string>" + xmlEscape(filepath.Join(logDir, label+".out.log")) + "</string>\n")
	b.WriteString("  <key>StandardErrorPath</key><string>" + xmlEscape(filepath.Join(logDir, label+".err.log")) + "</string>\n")
	b.WriteString("</dict>\n</plist>\n")
	return b.String()
}

func xmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;")
	return r.Replace(s)
}

// writeIfDifferent writes data to path only if the content differs, atomically
// and refusing to follow a symlink at the temp path. Returns true if it wrote.
func writeIfDifferent(path string, data []byte, mode os.FileMode) (bool, error) {
	if existing, err := os.ReadFile(path); err == nil && string(existing) == string(data) {
		_ = os.Chmod(path, mode)
		return false, nil
	}
	tmp := path + ".tmp"
	_ = os.Remove(tmp)
	fh, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY|os.O_TRUNC|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return false, err
	}
	if _, err := fh.Write(data); err != nil {
		fh.Close()
		_ = os.Remove(tmp)
		return false, err
	}
	if err := fh.Close(); err != nil {
		_ = os.Remove(tmp)
		return false, err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return false, err
	}
	return true, nil
}
