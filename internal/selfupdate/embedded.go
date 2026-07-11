// Package selfupdate verifies that an agent release tarball (and the
// install.sh that installs it) was signed by the offline obacht release
// key, so a compromised GitHub org / release publisher cannot push a
// malicious agent binary to the fleet.
//
// Threat model closed here: the self-update path (obachtctl system
// update-agent → obacht-self-update wrapper → install.sh → download
// tarball) previously trusted only a sha256 fetched from the SAME GitHub
// release. Anyone who could publish a release could replace both the
// binary and its checksum. Minisign signatures made with an OFFLINE key
// (never in CI — same model as the registry manifest key) that the agent
// verifies against an EMBEDDED public key close that gap: the attacker
// would additionally need the offline secret key.
//
// This mirrors internal/trust (template manifests); we reuse its minisign
// Bundle but keep a SEPARATE key set — release signing and template
// signing are different responsibilities with independent rotation.
package selfupdate

import "github.com/obacht-dev/obacht-agent/internal/trust"

// ReleaseTrustDir is an operator-managed drop-in for additional release
// verification keys (rotation without a new binary). Optional.
const ReleaseTrustDir = "/etc/obacht/release-trust.d"

// EmbeddedReleaseKeys is the compile-time set of trusted release-signing
// public keys. EMPTY BY DESIGN until the offline release key is generated
// (fail-closed: an empty set means "cannot verify", which the installer
// treats as a migration-phase skip, never as "verified OK").
//
// To enable signed releases:
//  1. Generate the offline key on the release engineer's workstation:
//     minisign -G -s ~/.config/obacht/obacht-agent-release-1.key \
//     -p ~/.config/obacht/obacht-agent-release-1.pub
//     Back the SECRET key up off-machine immediately (password manager).
//     The key NEVER goes into CI — releases are signed locally with
//     scripts/sign-release.sh.
//  2. Paste the .pub contents below (both lines, incl. the untrusted
//     comment), set Label to the key id, and cut an agent release.
//  3. From that release on, scripts/sign-release.sh attaches .minisig
//     assets and the installer verifies them.
//
// Rotation: append the new key here, ship the agent, re-sign releases
// with both keys for one cycle, then remove the old entry.
var EmbeddedReleaseKeys = []trust.KeyEntry{
	{
		// Key id 2E7980BE136B606D. Generated 2026-07-11 on the release
		// engineer's workstation; secret key at
		// ~/.config/obacht/obacht-agent-release-1.key (passphrase in the
		// password manager, backed up off-machine). Releases are signed
		// locally with scripts/sign-release.sh — the secret NEVER enters CI.
		Label: "obacht-agent-release-1",
		PubKey: "untrusted comment: minisign public key 2E7980BE136B606D\n" +
			"RWRtYGsTvoB5Ls75rzAz2E/agbhUA7JLnBnapCSZAhrmJOWBqKCStm+N\n",
	},
}
