package store

import (
	"context"
	"path/filepath"
	"testing"
)

func TestStoreUpsertAndList(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "agent.db")
	ctx := context.Background()

	st, err := Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	v, err := st.GetMeta(ctx, "schema_version")
	if err != nil {
		t.Fatalf("get schema_version: %v", err)
	}
	if v != "3" {
		t.Fatalf("expected schema_version=3, got %q", v)
	}

	inst := Instance{
		ID:           "demo-1",
		TemplateID:   "static-site",
		Runtime:      RuntimeContainer,
		Version:      "1.0.0",
		DesiredState: DesiredInstalled,
		ConfigJSON:   `{"foo":"bar"}`,
	}
	if err := st.UpsertInstance(ctx, inst); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	got, err := st.GetInstance(ctx, "demo-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.TemplateID != "static-site" || got.Runtime != RuntimeContainer || got.DesiredState != DesiredInstalled {
		t.Fatalf("unexpected instance: %+v", got)
	}

	// Update path: change desired state to removed.
	inst.DesiredState = DesiredRemoved
	if err := st.UpsertInstance(ctx, inst); err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	got, err = st.GetInstance(ctx, "demo-1")
	if err != nil {
		t.Fatalf("get after update: %v", err)
	}
	if got.DesiredState != DesiredRemoved {
		t.Fatalf("expected removed, got %s", got.DesiredState)
	}

	all, err := st.ListInstances(ctx)
	if err != nil || len(all) != 1 {
		t.Fatalf("list: %v len=%d", err, len(all))
	}

	if err := st.DeleteInstance(ctx, "demo-1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := st.GetInstance(ctx, "demo-1"); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}
