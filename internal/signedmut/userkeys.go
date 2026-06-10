package signedmut

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// UserKey is one pinned user public key, loaded from <state>/user-keys.d/.
type UserKey struct {
	Label string // file name, e.g. "a1b2c3d4.pub" (ssh_keys.id by convention)
	Pub   ed25519.PublicKey
}

// Fingerprint returns the OpenSSH-style SHA256 fingerprint
// ("SHA256:<base64-no-padding>") so logs and the Mac app's confirm dialog
// show the same string as `ssh-keygen -lf` and the web dashboard.
func (k UserKey) Fingerprint() string {
	wire := marshalSSHEd25519(k.Pub)
	sum := sha256.Sum256(wire)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// LoadUserKeys reads every *.pub file under dir (OpenSSH single-line
// "ssh-ed25519 AAAA... comment" format — exactly what the webapp generates
// and stores in ssh_keys.public_key). A missing dir returns an empty set:
// the device then simply does not advertise the signed-mutation capability.
// Files that fail to parse are skipped with an error in the returned slice
// of problems, never fatal — one corrupt pin must not lock out the rest.
func LoadUserKeys(dir string) ([]UserKey, []error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, []error{fmt.Errorf("read user-keys dir %s: %w", dir, err)}
	}
	var keys []UserKey
	var problems []error
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".pub") {
			continue
		}
		p := filepath.Join(dir, ent.Name())
		data, err := os.ReadFile(p)
		if err != nil {
			problems = append(problems, fmt.Errorf("read %s: %w", p, err))
			continue
		}
		pub, err := ParseOpenSSHEd25519(string(data))
		if err != nil {
			problems = append(problems, fmt.Errorf("parse %s: %w", p, err))
			continue
		}
		keys = append(keys, UserKey{Label: ent.Name(), Pub: pub})
	}
	return keys, problems
}

// ParseOpenSSHEd25519 parses a single-line OpenSSH public key
// ("ssh-ed25519 <base64-wire> [comment]") into the raw 32-byte key.
// The wire blob is two length-prefixed fields: the algorithm name and the
// key bytes (RFC 4251 string encoding). Implemented by hand to keep the
// agent free of an x/crypto dependency for 30 lines of parsing.
func ParseOpenSSHEd25519(line string) (ed25519.PublicKey, error) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 2 {
		return nil, errors.New("expected 'ssh-ed25519 <base64> [comment]'")
	}
	if fields[0] != "ssh-ed25519" {
		return nil, fmt.Errorf("unsupported key type %q (only ssh-ed25519)", fields[0])
	}
	wire, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return nil, fmt.Errorf("base64: %w", err)
	}
	algo, rest, err := readSSHString(wire)
	if err != nil {
		return nil, fmt.Errorf("wire algo field: %w", err)
	}
	if string(algo) != "ssh-ed25519" {
		return nil, fmt.Errorf("wire algo %q != ssh-ed25519", algo)
	}
	keyBytes, rest, err := readSSHString(rest)
	if err != nil {
		return nil, fmt.Errorf("wire key field: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("trailing bytes after key field")
	}
	if len(keyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("key is %d bytes, want %d", len(keyBytes), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(keyBytes), nil
}

func readSSHString(b []byte) (val, rest []byte, err error) {
	if len(b) < 4 {
		return nil, nil, errors.New("short length prefix")
	}
	n := binary.BigEndian.Uint32(b)
	if uint32(len(b)-4) < n {
		return nil, nil, errors.New("length prefix exceeds buffer")
	}
	return b[4 : 4+n], b[4+n:], nil
}

func marshalSSHEd25519(pub ed25519.PublicKey) []byte {
	algo := []byte("ssh-ed25519")
	out := make([]byte, 0, 4+len(algo)+4+len(pub))
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(algo)))
	out = append(out, l[:]...)
	out = append(out, algo...)
	binary.BigEndian.PutUint32(l[:], uint32(len(pub)))
	out = append(out, l[:]...)
	out = append(out, pub...)
	return out
}
