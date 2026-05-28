package trust

// Embedded compile-time trust bundle.
//
// During development we ship NO embedded keys — every Pi must drop a
// .pub file under /etc/obacht/trust.d/ before installs work. The
// release pipeline will replace this slice with the production
// obacht-registry signing key once minisign signing is wired up in
// S4.2.
//
// Why empty by default: we never want a stale dev key shipping in a
// release binary. Better to fail closed.
var EmbeddedKeys = []KeyEntry{
	{
		Label: "obacht-registry-prod-1",
		// Fingerprint 7263DA4AA71D7A3A. Generated 2026-05-28 (recovery
		// after loss of obacht-registry-2026 secret key). Private key
		// lives at ~/.config/obacht/obacht-registry-prod-1.key on the
		// release engineer's workstation; back it up immediately to
		// the password manager. Rotation: generate a new key, append
		// to this slice, sign all versions with both keys, ship the
		// new agent, then remove the old entry in the next release.
		PubKey: "untrusted comment: minisign public key 7263DA4AA71D7A3A\n" +
			"RWQ6eh2nStpjcld2gQQl2cSn4Hm7J4nHJ3uQzOZWlMRz1riY7+uRhcW4\n",
	},
}
