package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestExclusivityLocks(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	st, err := Open(ctx, filepath.Join(dir, "agent.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	// Locks have a FK to instances(id); seed the rows first.
	for _, id := range []string{"inst-A", "inst-B"} {
		if err := st.UpsertInstance(ctx, Instance{
			ID: id, TemplateID: "tpl", Runtime: RuntimeSystem, DesiredState: DesiredInstalled,
		}); err != nil {
			t.Fatalf("upsert %s: %v", id, err)
		}
	}

	// First acquirer wins.
	if err := st.TryAcquireLock(ctx, "display-output", "inst-A"); err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	// Same instance re-acquiring is idempotent.
	if err := st.TryAcquireLock(ctx, "display-output", "inst-A"); err != nil {
		t.Fatalf("re-acquire same: %v", err)
	}
	// Different instance is denied.
	if err := st.TryAcquireLock(ctx, "display-output", "inst-B"); !errors.Is(err, ErrLockHeld) {
		t.Fatalf("expected ErrLockHeld for inst-B, got %v", err)
	}
	// Holder lookup matches.
	holder, err := st.GetLockHolder(ctx, "display-output")
	if err != nil {
		t.Fatalf("holder: %v", err)
	}
	if holder != "inst-A" {
		t.Fatalf("expected holder inst-A, got %q", holder)
	}
	// Release frees it.
	if err := st.ReleaseLock(ctx, "display-output", "inst-A"); err != nil {
		t.Fatalf("release: %v", err)
	}
	// Now inst-B can take it.
	if err := st.TryAcquireLock(ctx, "display-output", "inst-B"); err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	// ReleaseLocksForInstance covers all groups for that instance.
	if err := st.TryAcquireLock(ctx, "audio-output", "inst-B"); err != nil {
		t.Fatalf("acquire 2nd group: %v", err)
	}
	if err := st.ReleaseLocksForInstance(ctx, "inst-B"); err != nil {
		t.Fatalf("release-all: %v", err)
	}
	for _, g := range []string{"display-output", "audio-output"} {
		holder, _ := st.GetLockHolder(ctx, g)
		if holder != "" {
			t.Fatalf("expected %q free after release-all, got holder %q", g, holder)
		}
	}
}
