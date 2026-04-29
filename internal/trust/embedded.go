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
	// Example after S4.2 release engineering:
	// { Label: "obacht-registry-2026", PubKey: "RWQ..." },
}
