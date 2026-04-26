package ingress

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ScanCerts walks the Caddy data dir for issued certificates, parses each
// PEM, and writes (cert_not_after, cert_issuer) back to the SSOT for the
// matching domain. We never copy the cert or its key off disk — only the
// metadata (subject, expiry, issuer common name) is observed and shipped
// upstream as telemetry.
//
// Layout we expect (Caddy 2 default):
//
//	<CaddyData>/caddy/certificates/<acme-dir>/<domain>/<domain>.crt
func (m *Manager) ScanCerts(ctx context.Context) error {
	root := filepath.Join(m.paths.CaddyData, "caddy", "certificates")
	domains, err := m.store.ListDomains(ctx)
	if err != nil {
		return fmt.Errorf("list domains: %w", err)
	}

	// Build a quick index of known domains so we don't waste time on stale
	// cert dirs left over from removed domains.
	want := make(map[string]struct{}, len(domains))
	for _, d := range domains {
		want[d.Domain] = struct{}{}
	}

	if _, err := os.Stat(root); err != nil {
		return nil // no certs issued yet — nothing to do
	}

	_ = filepath.WalkDir(root, func(path string, dEntry os.DirEntry, err error) error {
		if err != nil || dEntry.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".crt") {
			return nil
		}
		base := strings.TrimSuffix(filepath.Base(path), ".crt")
		if _, ok := want[base]; !ok {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			m.log.Debug("read cert", "path", path, "err", err)
			return nil
		}
		block, _ := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			m.log.Debug("parse cert", "domain", base, "err", err)
			return nil
		}
		issuer := cert.Issuer.CommonName
		if issuer == "" && len(cert.Issuer.Organization) > 0 {
			issuer = cert.Issuer.Organization[0]
		}
		if err := m.store.SetDomainCert(ctx, base, cert.NotAfter, issuer); err != nil {
			m.log.Warn("set domain cert", "domain", base, "err", err)
		}
		return nil
	})
	return nil
}
