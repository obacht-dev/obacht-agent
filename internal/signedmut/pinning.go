package signedmut

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// This file owns WRITE access to the user-keys.d trust store. Loading and
// verification live in userkeys.go / envelope.go. Pinning is deliberately
// only reachable through user-authorised channels: install.sh at provision
// time, the one-time authorized_keys import (linux), and the peer-cred
// gated IPC admin API driven by obachtctl (which the user reaches over an
// SSH session authenticated with the very key being managed). The backend
// has no runtime path into this directory — invariant I3.

// maxPubKeyLine caps the accepted OpenSSH line length. Real ed25519 lines
// are ~100 bytes; anything past 1 KiB is garbage or an attack.
const maxPubKeyLine = 1024

// PinUserKey validates line as a single OpenSSH ed25519 public key and
// writes it atomically into dir (created 0700 if missing, file 0600). The
// filename derives from the key's fingerprint, so pinning the same key
// twice is a no-op. Returns the parsed key and whether a new file was
// written.
func PinUserKey(dir, line string) (UserKey, bool, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return UserKey{}, false, errors.New("empty public key")
	}
	if len(line) > maxPubKeyLine {
		return UserKey{}, false, fmt.Errorf("public key exceeds %d bytes", maxPubKeyLine)
	}
	if strings.ContainsAny(line, "\n\r") {
		return UserKey{}, false, errors.New("public key must be a single line")
	}
	pub, err := ParseOpenSSHEd25519(line)
	if err != nil {
		return UserKey{}, false, err
	}

	// Idempotency: if any existing pin already holds this key, keep it —
	// including its original filename/label (e.g. the Mac app's default.pub).
	existing, _ := LoadUserKeys(dir)
	for _, k := range existing {
		if bytes.Equal(k.Pub, pub) {
			return k, false, nil
		}
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return UserKey{}, false, fmt.Errorf("mkdir %s: %w", dir, err)
	}
	name := pinFileName(pub)
	tmp, err := os.CreateTemp(dir, ".pin-*")
	if err != nil {
		return UserKey{}, false, fmt.Errorf("create temp pin: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.WriteString(line + "\n"); err != nil {
		_ = tmp.Close()
		cleanup()
		return UserKey{}, false, fmt.Errorf("write pin: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		cleanup()
		return UserKey{}, false, fmt.Errorf("chmod pin: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return UserKey{}, false, fmt.Errorf("close pin: %w", err)
	}
	final := filepath.Join(dir, name)
	if err := os.Rename(tmpName, final); err != nil {
		cleanup()
		return UserKey{}, false, fmt.Errorf("rename pin: %w", err)
	}
	return UserKey{Label: name, Pub: pub}, true, nil
}

// UnpinUserKey removes every pinned key whose OpenSSH SHA256 fingerprint
// matches. Returns how many files were removed. A missing dir removes
// nothing and is not an error.
func UnpinUserKey(dir, fingerprint string) (int, error) {
	fingerprint = strings.TrimSpace(fingerprint)
	if fingerprint == "" {
		return 0, errors.New("fingerprint is required")
	}
	keys, _ := LoadUserKeys(dir)
	removed := 0
	for _, k := range keys {
		if k.Fingerprint() != fingerprint {
			continue
		}
		if err := os.Remove(filepath.Join(dir, k.Label)); err != nil {
			return removed, fmt.Errorf("remove %s: %w", k.Label, err)
		}
		removed++
	}
	return removed, nil
}

// ImportAuthorizedKeys pins every bare ed25519 line found in an OpenSSH
// authorized_keys file. Lines that are comments, blank, option-prefixed
// (`restrict`, `command=`, …) or non-ed25519 are skipped — the import takes
// only what ParseOpenSSHEd25519 accepts, i.e. exactly the format install.sh
// provisions. Returns the newly pinned keys and the number of skipped
// non-empty lines. A missing file returns os.ErrNotExist.
func ImportAuthorizedKeys(dir, authorizedKeysPath string) (pinned []UserKey, skipped int, err error) {
	data, err := os.ReadFile(authorizedKeysPath)
	if err != nil {
		return nil, 0, err
	}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, created, perr := PinUserKey(dir, line)
		if perr != nil {
			skipped++
			continue
		}
		if created {
			pinned = append(pinned, key)
		}
	}
	return pinned, skipped, nil
}

// pinFileName derives a stable, filesystem-safe name from the key material
// (first 16 hex chars of the SHA256 over the SSH wire encoding).
func pinFileName(pub []byte) string {
	sum := sha256.Sum256(marshalSSHEd25519(pub))
	return hex.EncodeToString(sum[:8]) + ".pub"
}
