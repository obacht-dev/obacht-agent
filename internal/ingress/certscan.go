package ingress

import (
	"archive/tar"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
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

	if m.cfg.Containerized {
		// Certs live in the named docker volume inside the VM — not on a host
		// path we can read. Stream them out of the Caddy container via the
		// docker archive API and parse the same metadata (expiry/issuer).
		return m.scanCertsContainerized(ctx, want)
	}

	root := filepath.Join(m.paths.CaddyData, "caddy", "certificates")
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
		m.recordCert(ctx, base, data)
		return nil
	})
	return nil
}

// scanCertsContainerized reads issued certs out of the Caddy container's
// /data volume (in the VM) via the docker archive API and records the same
// expiry/issuer metadata as the host path. The archive endpoint streams a
// tar of /data/caddy/certificates; we parse the leaf of each <domain>.crt.
func (m *Manager) scanCertsContainerized(ctx context.Context, want map[string]struct{}) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://docker/v1.43/containers/"+ContainerName+
			"/archive?path=/data/caddy/certificates", nil)
	resp, err := m.docker.HTTP().Do(req)
	if err != nil {
		// transient docker/bridge blip — try again next pass, don't error-spam
		m.log.Debug("scan certs: archive request", "err", err)
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return nil // no certs issued yet
	}
	if resp.StatusCode != 200 {
		m.log.Debug("scan certs: archive status", "status", resp.StatusCode)
		return nil
	}
	tr := tar.NewReader(resp.Body)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			m.log.Debug("scan certs: tar read", "err", err)
			return nil
		}
		if h.FileInfo().IsDir() || !strings.HasSuffix(h.Name, ".crt") {
			continue
		}
		base := strings.TrimSuffix(filepath.Base(h.Name), ".crt")
		if _, ok := want[base]; !ok {
			continue
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			continue
		}
		m.recordCert(ctx, base, data)
	}
	return nil
}

// recordCert parses the leaf certificate from a PEM blob and writes its
// expiry + issuer to the SSOT for the given domain. Shared by the host and
// containerized scanners.
func (m *Manager) recordCert(ctx context.Context, domain string, pemData []byte) {
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "CERTIFICATE" {
		return
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		m.log.Debug("parse cert", "domain", domain, "err", err)
		return
	}
	issuer := cert.Issuer.CommonName
	if issuer == "" && len(cert.Issuer.Organization) > 0 {
		issuer = cert.Issuer.Organization[0]
	}
	if err := m.store.SetDomainCert(ctx, domain, cert.NotAfter, issuer); err != nil {
		m.log.Warn("set domain cert", "domain", domain, "err", err)
	}
}
