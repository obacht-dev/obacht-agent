package selfupdate

import (
	"errors"
	"fmt"

	"github.com/obacht-dev/obacht-agent/internal/trust"
)

// ErrNoKeys is returned by VerifyFile when no release keys are trusted
// (empty embedded set and empty release-trust.d). Callers distinguish it
// from a genuine signature failure: "cannot verify" is a migration-phase
// skip, a real failure is fatal.
var ErrNoKeys = errors.New("no release signing keys trusted")

// LoadReleaseKeys returns the embedded release keys plus any operator keys
// dropped under ReleaseTrustDir. A missing dir is not an error.
func LoadReleaseKeys() ([]trust.KeyEntry, error) {
	keys := make([]trust.KeyEntry, 0, len(EmbeddedReleaseKeys))
	keys = append(keys, EmbeddedReleaseKeys...)
	extra, err := trust.LoadFromDir(ReleaseTrustDir)
	if err != nil {
		return nil, fmt.Errorf("load %s: %w", ReleaseTrustDir, err)
	}
	keys = append(keys, extra...)
	return keys, nil
}

// VerifyFile checks that sig is a valid minisign signature over content
// under a trusted release key. Returns ErrNoKeys when nothing is trusted
// (so the caller can choose to skip during the signing-migration window),
// nil on success, and a non-nil, non-ErrNoKeys error on a real signature
// rejection (which must be fatal).
func VerifyFile(content, sig []byte) error {
	keys, err := LoadReleaseKeys()
	if err != nil {
		return err
	}
	return verifyWithKeys(keys, content, sig)
}

// verifyWithKeys is the testable core of VerifyFile: it keeps the
// ErrNoKeys-vs-rejection contract independent of the (now populated)
// embedded key set.
func verifyWithKeys(keys []trust.KeyEntry, content, sig []byte) error {
	if len(keys) == 0 {
		return ErrNoKeys
	}
	bundle, err := trust.New(keys)
	if err != nil {
		return err
	}
	return bundle.Verify(content, sig)
}
