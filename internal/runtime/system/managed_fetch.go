package system

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/obacht-dev/obacht-agent/internal/unitpolicy"
)

// maxManagedDownloadBytes caps a managed-service artifact download. MediaMTX
// is ~15 MiB; 512 MiB leaves room without letting a bad URL fill the disk.
const maxManagedDownloadBytes = 512 << 20

// EnsureManagedBinary makes sure the digest-pinned binary for a managed
// service exists at its content-addressed path and returns that path.
// Mirrors the darwin host-service contract: https from an allowlisted host
// (re-checked on every redirect hop), full sha256 verification BEFORE any
// extract/exec, tgz-only archives. Runs entirely unprivileged (the bin root
// is agent-owned); the root helper never downloads anything.
//
// The layout is content-addressed (<BinRoot>/<digest>/<binary>), so a
// version bump lands in a fresh directory and the running unit keeps its
// binary until the regenerated unit is installed — updates are atomic.
//
// Trust note: a cache hit (the content-addressed file already exists) is
// returned without re-hashing. The bin root is agent-writable, so this does
// NOT defend against a compromised agent — which can already run arbitrary
// code via the docker socket, a strictly greater capability than a confined
// DynamicUser workload. The sha256 check is an integrity control against a
// corrupted/substituted DOWNLOAD, not against the agent process itself.
func EnsureManagedBinary(ms ManagedServiceSpec) (string, error) {
	if err := ms.validate(); err != nil {
		return "", err
	}
	binPath := managedBinPath(ms)
	if st, err := os.Stat(binPath); err == nil && st.Mode().IsRegular() {
		return binPath, nil
	}

	destDir := filepath.Dir(binPath)
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", destDir, err)
	}

	tmp, err := os.CreateTemp(destDir, ".download-*")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	client := &http.Client{
		Timeout: 10 * time.Minute,
		// Re-validate scheme+host on every redirect hop so an allowlisted host
		// that 302s to a LAN/metadata address (169.254.169.254, …) is refused.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			if req.URL.Scheme != "https" || !RedirectHostAllowed(req.URL.Host) {
				return fmt.Errorf("redirect to disallowed target %q", req.URL.Redacted())
			}
			return nil
		},
	}
	resp, err := client.Get(ms.BinaryURL)
	if err != nil {
		tmp.Close()
		return "", fmt.Errorf("download %s: %w", ms.BinaryURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		tmp.Close()
		return "", fmt.Errorf("download %s: HTTP %d", ms.BinaryURL, resp.StatusCode)
	}

	hasher := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, hasher), io.LimitReader(resp.Body, maxManagedDownloadBytes+1))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", fmt.Errorf("download %s: %w", ms.BinaryURL, err)
	}
	if n > maxManagedDownloadBytes {
		return "", fmt.Errorf("download %s exceeds %d bytes", ms.BinaryURL, maxManagedDownloadBytes)
	}

	got := hex.EncodeToString(hasher.Sum(nil))
	want := strings.TrimPrefix(ms.BinaryDigest, "sha256:")
	if got != want {
		return "", fmt.Errorf("digest mismatch for %s: got sha256:%s want %s", ms.BinaryURL, got, ms.BinaryDigest)
	}

	// Digest verified — now materialize the binary.
	if ms.Archive == "tgz" {
		if err := extractManagedTgz(tmpName, destDir, ms.Binary); err != nil {
			return "", err
		}
	} else {
		if err := os.Rename(tmpName, binPath); err != nil {
			return "", err
		}
	}
	if err := os.Chmod(binPath, 0o755); err != nil {
		return "", err
	}
	if st, err := os.Stat(binPath); err != nil || !st.Mode().IsRegular() {
		return "", fmt.Errorf("archive did not contain binary %q", ms.Binary)
	}
	return binPath, nil
}

// extractManagedTgz extracts regular files from a verified tarball FLAT into
// destDir (basenames only — no directories are created), which removes the
// whole path-traversal class. Symlinks, devices etc. are skipped. The tar
// must contain the named binary at any depth.
func extractManagedTgz(archivePath, destDir, binary string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("gzip: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	var total int64
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		base := filepath.Base(filepath.Clean(hdr.Name))
		if base == "." || base == ".." || base == "/" || base == "" {
			continue
		}
		total += hdr.Size
		if total > maxManagedDownloadBytes {
			return fmt.Errorf("tar contents exceed %d bytes", maxManagedDownloadBytes)
		}
		out := filepath.Join(destDir, base)
		if !strings.HasPrefix(out, filepath.Clean(destDir)+string(os.PathSeparator)) {
			return fmt.Errorf("tar entry %q escapes destination", hdr.Name)
		}
		fh, err := os.OpenFile(out, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		if _, err := io.Copy(fh, io.LimitReader(tr, maxManagedDownloadBytes)); err != nil {
			fh.Close()
			return err
		}
		if err := fh.Close(); err != nil {
			return err
		}
	}
	if _, err := os.Stat(filepath.Join(destDir, binary)); err != nil {
		return fmt.Errorf("tar did not contain binary %q", binary)
	}
	return nil
}

// StagingUnitPath returns where the agent stages a generated unit for the
// root helper to pick up. The helper only ever reads from
// unitpolicy.StagingDir keyed by validated unit name — never from a caller
// supplied path.
func StagingUnitPath(unitName string) string {
	return filepath.Join(unitpolicy.StagingDir, unitName)
}
