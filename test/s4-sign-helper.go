//go:build ignore

// s4-sign-helper: standalone script that generates two minisign
// keypairs (trusted + untrusted) and writes:
//   <work>/trusted.pub
//   <work>/manifest.b64           (base64 of the canonical manifest bytes)
//   <work>/tampered-manifest.b64  (base64 of a near-identical but
//                                   semantically-different manifest)
//   <work>/trusted-sig.b64        (base64 of the minisign sig made by trusted)
//   <work>/untrusted-sig.b64      (base64 of the minisign sig made by untrusted)
//
// Used by test/S4-signing.sh; not part of the production build.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"

	"aead.dev/minisign"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: s4-sign-helper <work-dir>")
		os.Exit(2)
	}
	work := os.Args[1]

	manifest := []byte("kind: container\nimage: caddy:2-alpine\n")
	tampered := []byte("kind: container\nimage: evil/cryptominer:latest\n")

	trustedPub, trustedPriv, err := minisign.GenerateKey(rand.Reader)
	must(err)
	_, untrustedPriv, err := minisign.GenerateKey(rand.Reader)
	must(err)

	pubText, err := trustedPub.MarshalText()
	must(err)
	must(os.WriteFile(filepath.Join(work, "trusted.pub"), pubText, 0o644))

	must(os.WriteFile(filepath.Join(work, "manifest.b64"),
		[]byte(base64.StdEncoding.EncodeToString(manifest)), 0o644))
	must(os.WriteFile(filepath.Join(work, "tampered-manifest.b64"),
		[]byte(base64.StdEncoding.EncodeToString(tampered)), 0o644))

	trustedSig := minisign.Sign(trustedPriv, manifest)
	untrustedSig := minisign.Sign(untrustedPriv, manifest)
	must(os.WriteFile(filepath.Join(work, "trusted-sig.b64"),
		[]byte(base64.StdEncoding.EncodeToString(trustedSig)), 0o644))
	must(os.WriteFile(filepath.Join(work, "untrusted-sig.b64"),
		[]byte(base64.StdEncoding.EncodeToString(untrustedSig)), 0o644))

	fmt.Println("ok")
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
