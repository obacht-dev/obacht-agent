package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// DomainStatus values (used for both desired_status and observed_status).
const (
	DomainStatusPending  = "pending"  // user requested it, not yet checked
	DomainStatusClaiming = "claiming" // ACME challenge in progress
	DomainStatusReady    = "ready"    // cert issued, default site served
	DomainStatusBound    = "bound"    // cert issued + has an ingress_binding
	DomainStatusError    = "error"    // last attempt failed
	DomainStatusRemoved  = "removed"  // user requested removal
)

// Domain is one row in `domains`.
type Domain struct {
	Domain          string
	DesiredStatus   string
	ObservedStatus  string
	CertNotAfter    time.Time
	CertIssuer      string
	LastError       string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// IngressBinding is one row in `ingress_bindings`.
//
// Either (InstanceID + ServiceName) OR LocalPort identifies the upstream:
//   - service binding:  InstanceID + ServiceName set, LocalPort == 0
//   - local-port proxy: LocalPort > 0,  InstanceID/ServiceName empty
type IngressBinding struct {
	Domain      string
	InstanceID  string
	ServiceName string
	LocalPort   int
	Mode        string
	PathPrefix  string
}

// InstanceService is one row in `instance_services`.
type InstanceService struct {
	InstanceID  string
	ServiceName string
	TargetType  string
	Target      string
}

// UpsertDomain inserts a new domain or updates the desired status. The legacy
// `status` column is set to mirror desired so v1 readers stay sane.
func (s *Store) UpsertDomain(ctx context.Context, domain, desired string) error {
	if domain == "" {
		return errors.New("domain is required")
	}
	if desired == "" {
		desired = DomainStatusPending
	}
	now := time.Now().Unix()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO domains(domain, status, desired_status, observed_status, created_at, updated_at)
		VALUES(?, ?, ?, ?, ?, ?)
		ON CONFLICT(domain) DO UPDATE SET
			desired_status = excluded.desired_status,
			status         = excluded.status,
			updated_at     = excluded.updated_at
	`, domain, desired, desired, DomainStatusPending, now, now)
	if err != nil {
		return fmt.Errorf("upsert domain %s: %w", domain, err)
	}
	return nil
}

// SetDomainObserved records the latest observed status (and optional error).
func (s *Store) SetDomainObserved(ctx context.Context, domain, observed, lastErr string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE domains
		   SET observed_status = ?, last_error = ?, updated_at = ?
		 WHERE domain = ?`, observed, lastErr, time.Now().Unix(), domain)
	return err
}

// SetDomainCertNotAfter records the cert expiry timestamp Caddy reported.
func (s *Store) SetDomainCertNotAfter(ctx context.Context, domain string, notAfter time.Time) error {
	v := int64(0)
	if !notAfter.IsZero() {
		v = notAfter.Unix()
	}
	_, err := s.db.ExecContext(ctx, `UPDATE domains SET cert_not_after = ?, updated_at = ? WHERE domain = ?`,
		v, time.Now().Unix(), domain)
	return err
}

// SetDomainCert records the cert expiry timestamp + issuer the agent
// observed (by parsing Caddy's on-disk PEM, never by exfiltrating the key).
func (s *Store) SetDomainCert(ctx context.Context, domain string, notAfter time.Time, issuer string) error {
	v := int64(0)
	if !notAfter.IsZero() {
		v = notAfter.Unix()
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE domains SET cert_not_after = ?, cert_issuer = ?, updated_at = ? WHERE domain = ?`,
		v, issuer, time.Now().Unix(), domain)
	return err
}

// DeleteDomain removes the domain row (cascades to ingress_bindings).
func (s *Store) DeleteDomain(ctx context.Context, domain string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM domains WHERE domain = ?`, domain)
	return err
}

// ListDomains returns every domain.
func (s *Store) ListDomains(ctx context.Context) ([]Domain, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT domain,
		       COALESCE(desired_status, status, ''),
		       COALESCE(observed_status, ''),
		       COALESCE(cert_not_after, 0),
		       COALESCE(cert_issuer, ''),
		       COALESCE(last_error, ''),
		       created_at, updated_at
		FROM domains ORDER BY domain ASC`)
	if err != nil {
		return nil, fmt.Errorf("list domains: %w", err)
	}
	defer rows.Close()
	var out []Domain
	for rows.Next() {
		var (
			d           Domain
			notAfter    int64
			created, ua int64
		)
		if err := rows.Scan(&d.Domain, &d.DesiredStatus, &d.ObservedStatus, &notAfter, &d.CertIssuer, &d.LastError, &created, &ua); err != nil {
			return nil, err
		}
		if notAfter > 0 {
			d.CertNotAfter = time.Unix(notAfter, 0)
		}
		d.CreatedAt = time.Unix(created, 0)
		d.UpdatedAt = time.Unix(ua, 0)
		out = append(out, d)
	}
	return out, rows.Err()
}

// GetDomain returns a single domain or ErrNotFound.
func (s *Store) GetDomain(ctx context.Context, domain string) (*Domain, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT domain,
		       COALESCE(desired_status, status, ''),
		       COALESCE(observed_status, ''),
		       COALESCE(cert_not_after, 0),
		       COALESCE(cert_issuer, ''),
		       COALESCE(last_error, ''),
		       created_at, updated_at
		FROM domains WHERE domain = ?`, domain)
	var (
		d           Domain
		notAfter    int64
		created, ua int64
	)
	if err := row.Scan(&d.Domain, &d.DesiredStatus, &d.ObservedStatus, &notAfter, &d.CertIssuer, &d.LastError, &created, &ua); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if notAfter > 0 {
		d.CertNotAfter = time.Unix(notAfter, 0)
	}
	d.CreatedAt = time.Unix(created, 0)
	d.UpdatedAt = time.Unix(ua, 0)
	return &d, nil
}

// --- ingress_bindings ---

// UpsertBinding sets the ingress binding for a domain. Replaces any prior
// binding (one binding per domain in v1).
func (s *Store) UpsertBinding(ctx context.Context, b IngressBinding) error {
	if b.Domain == "" {
		return errors.New("domain required")
	}
	hasService := b.InstanceID != "" && b.ServiceName != ""
	hasLocal := b.LocalPort > 0
	if !hasService && !hasLocal {
		return errors.New("binding needs either instance_id+service_name or local_port")
	}
	if hasService && hasLocal {
		return errors.New("binding cannot set both instance/service and local_port")
	}
	if b.Mode == "" {
		b.Mode = "root"
	}
	var instPtr, svcPtr any
	if hasService {
		instPtr = b.InstanceID
		svcPtr = b.ServiceName
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO ingress_bindings(domain, instance_id, service_name, local_port, mode, path_prefix)
		VALUES(?, ?, ?, ?, ?, ?)
		ON CONFLICT(domain) DO UPDATE SET
			instance_id  = excluded.instance_id,
			service_name = excluded.service_name,
			local_port   = excluded.local_port,
			mode         = excluded.mode,
			path_prefix  = excluded.path_prefix
	`, b.Domain, instPtr, svcPtr, b.LocalPort, b.Mode, b.PathPrefix)
	if err != nil {
		return fmt.Errorf("upsert binding %s: %w", b.Domain, err)
	}
	return nil
}

// DeleteBinding removes the binding for a domain (domain row stays).
func (s *Store) DeleteBinding(ctx context.Context, domain string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM ingress_bindings WHERE domain = ?`, domain)
	return err
}

// ListBindings returns every binding.
func (s *Store) ListBindings(ctx context.Context) ([]IngressBinding, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT domain,
		       COALESCE(instance_id,''),
		       COALESCE(service_name,''),
		       COALESCE(local_port,0),
		       mode,
		       COALESCE(path_prefix,'')
		FROM ingress_bindings ORDER BY domain ASC`)
	if err != nil {
		return nil, fmt.Errorf("list bindings: %w", err)
	}
	defer rows.Close()
	var out []IngressBinding
	for rows.Next() {
		var b IngressBinding
		if err := rows.Scan(&b.Domain, &b.InstanceID, &b.ServiceName, &b.LocalPort, &b.Mode, &b.PathPrefix); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// --- instance_services ---

// UpsertService registers a named service (e.g. "web") on an instance with a
// connection target the ingress can route to.
func (s *Store) UpsertService(ctx context.Context, svc InstanceService) error {
	if svc.InstanceID == "" || svc.ServiceName == "" || svc.TargetType == "" || svc.Target == "" {
		return errors.New("instance_id, service_name, target_type, target required")
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO instance_services(instance_id, service_name, target_type, target)
		VALUES(?, ?, ?, ?)
		ON CONFLICT(instance_id, service_name) DO UPDATE SET
			target_type = excluded.target_type,
			target      = excluded.target
	`, svc.InstanceID, svc.ServiceName, svc.TargetType, svc.Target)
	return err
}

// ListInstanceServices returns every service known to the agent.
func (s *Store) ListInstanceServices(ctx context.Context) ([]InstanceService, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT instance_id, service_name, target_type, target FROM instance_services`)
	if err != nil {
		return nil, fmt.Errorf("list services: %w", err)
	}
	defer rows.Close()
	var out []InstanceService
	for rows.Next() {
		var s InstanceService
		if err := rows.Scan(&s.InstanceID, &s.ServiceName, &s.TargetType, &s.Target); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// GetInstanceService looks up one (instance_id, service_name) target.
func (s *Store) GetInstanceService(ctx context.Context, instanceID, serviceName string) (*InstanceService, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT instance_id, service_name, target_type, target
		   FROM instance_services WHERE instance_id = ? AND service_name = ?`, instanceID, serviceName)
	var svc InstanceService
	if err := row.Scan(&svc.InstanceID, &svc.ServiceName, &svc.TargetType, &svc.Target); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &svc, nil
}
