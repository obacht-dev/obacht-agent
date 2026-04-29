// Package trust verifies template manifest signatures so a compromised
// obacht-api or obacht-registry can't push malicious templates onto a
// Pi.
//
// Threat model: the api signs install-plans (S2.3/S3) but the
// underlying manifest content is sourced from obacht-registry. If the
// registry is compromised, the api's plan_hash would still be valid
// because plan_hash only covers the *steps* (argv), not the manifest
// payload. Minisign signing on the registry side, verified here on the
// Pi against an embedded trust bundle, closes that gap.
//
// We use minisign (aead.dev/minisign, pure Go, no cgo) because:
//   - the public-key format is short enough to embed and audit by eye
//   - signing is offline-friendly (release engineer signs on a workstation)
//   - the wire format (.minisig) is text and human-inspectable
//
// Trust bundle resolution order:
//   1. compile-time embedded keys (build tag controls which set)
//   2. /etc/obacht/trust.d/*.pub at agent startup
//   3. (none — no fallback to network)
package trust

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"aead.dev/minisign"
)

// Bundle is a set of trusted minisign public keys. A signature
// verifies if ANY key in the bundle accepts it.
type Bundle struct {
	keys []minisign.PublicKey
	// labels parallel to keys, used only for error messages and audit
	// log so a verification failure tells you which key was tried last.
	labels []string
}

// New builds a bundle from the given pubkey strings. Each string is
// the contents of a `.pub` file (single-line base64-encoded).
func New(entries []KeyEntry) (*Bundle, error) {
	if len(entries) == 0 {
		return nil, errors.New("trust bundle is empty; refusing to start")
	}
	b := &Bundle{}
	for _, e := range entries {
		var pk minisign.PublicKey
		if err := pk.UnmarshalText([]byte(strings.TrimSpace(e.PubKey))); err != nil {
			return nil, fmt.Errorf("trust key %q: %w", e.Label, err)
		}
		b.keys = append(b.keys, pk)
		b.labels = append(b.labels, e.Label)
	}
	return b, nil
}

// KeyEntry pairs a label (for diagnostics) with a pubkey string.
type KeyEntry struct {
	Label  string
	PubKey string
}

// LoadFromDir reads every *.pub file under dir and returns key
// entries. Missing dir is not an error — it returns an empty slice so
// the caller can combine with embedded keys.
func LoadFromDir(dir string) ([]KeyEntry, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []KeyEntry
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".pub") {
			continue
		}
		p := filepath.Join(dir, ent.Name())
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", p, err)
		}
		out = append(out, KeyEntry{Label: ent.Name(), PubKey: string(data)})
	}
	return out, nil
}

// Verify returns nil if sig is a valid minisign signature for content
// under any key in the bundle.
//
// We try every key; the first that accepts wins. If none accept, we
// return an error naming the *last* key tried plus the underlying
// error from minisign — that's enough to figure out whether the file
// is corrupt vs. signed by an unknown key.
func (b *Bundle) Verify(content, sig []byte) error {
	if len(b.keys) == 0 {
		return errors.New("trust bundle empty")
	}
	var lastErr error
	var lastLabel string
	for i, pk := range b.keys {
		if minisign.Verify(pk, content, sig) {
			return nil
		}
		// minisign.Verify returns bool, no detail. We synthesise a
		// generic error so the audit log still has SOMETHING to record.
		lastErr = errors.New("signature did not verify")
		lastLabel = b.labels[i]
	}
	return fmt.Errorf("template signature rejected by all %d trusted keys (last tried: %s): %w",
		len(b.keys), lastLabel, lastErr)
}

// Size returns the number of trusted keys, useful for /system/status.
func (b *Bundle) Size() int { return len(b.keys) }

// Labels returns the labels of all trusted keys in order.
func (b *Bundle) Labels() []string {
	out := make([]string, len(b.labels))
	copy(out, b.labels)
	return out
}
