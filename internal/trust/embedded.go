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
		Label: "obacht-registry-2026",
		// Fingerprint E8A98BCECC0397B0. Generated 2026-04-29 by
		// scripts/sign-template-version --generate-key. Private key
		// lives at ~/.config/obacht/obacht-registry-2026.key on the
		// release engineer's workstation (passphrase in 1Password).
		// Rotation: generate a new key, append to this slice, sign all
		// versions with both keys, ship the new agent, then remove the
		// old entry in the next release.
		PubKey: "untrusted comment: minisign public key: E8A98BCECC0397B0\n" +
			"RWSwlwPMzoup6CUZxhIqYsRS2p7x0wIi99GB+dv0aDMeqToF2UvJ0YX6\n",
	},
}
