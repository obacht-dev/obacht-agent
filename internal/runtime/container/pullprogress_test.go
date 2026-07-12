package container

import (
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

type recordingReporter struct {
	mu    sync.Mutex
	calls []struct {
		id, phase string
		pct       int
	}
}

func (r *recordingReporter) Report(id, phase string, pct int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, struct {
		id, phase string
		pct       int
	}{id, phase, pct})
}

func TestConsumePullStreamAggregatesPercent(t *testing.T) {
	stream := strings.Join([]string{
		`{"status":"Pulling from library/nginx","id":"latest"}`,
		`{"status":"Downloading","id":"aaa","progressDetail":{"current":50,"total":100}}`,
		`{"status":"Downloading","id":"bbb","progressDetail":{"current":25,"total":100}}`,
		`{"status":"Download complete","id":"aaa"}`,
		`{"status":"Downloading","id":"bbb","progressDetail":{"current":100,"total":100}}`,
		`{"status":"Pull complete","id":"bbb"}`,
	}, "\n")

	rep := &recordingReporter{}
	d := &Driver{prog: rep, log: testLogger()}
	d.consumePullStream("inst1", "nginx", strings.NewReader(stream))

	if len(rep.calls) == 0 {
		t.Fatal("expected progress reports")
	}
	first := rep.calls[0]
	if first.id != "inst1" || first.phase != "pulling" {
		t.Fatalf("unexpected first report: %+v", first)
	}
	last := rep.calls[len(rep.calls)-1]
	if last.pct != 100 {
		t.Fatalf("expected final percent 100, got %d", last.pct)
	}
	// Percent must be monotonically sensible (never decrease below prior).
	prev := -1
	for _, c := range rep.calls {
		if c.pct != -1 && c.pct < prev {
			t.Fatalf("percent went backwards: %+v (prev %d)", c, prev)
		}
		if c.pct != -1 {
			prev = c.pct
		}
	}
}

func TestConsumePullStreamNoInstanceDrains(t *testing.T) {
	rep := &recordingReporter{}
	d := &Driver{prog: rep, log: testLogger()}
	d.consumePullStream("", "nginx", strings.NewReader(`{"status":"Downloading","id":"x","progressDetail":{"current":1,"total":2}}`))
	if len(rep.calls) != 0 {
		t.Fatalf("expected no reports without instance attribution, got %d", len(rep.calls))
	}
}

func TestConsumePullStreamMalformedIsSilent(t *testing.T) {
	rep := &recordingReporter{}
	d := &Driver{prog: rep, log: testLogger()}
	d.consumePullStream("inst1", "nginx", strings.NewReader(`{"status":"Downloading","id":"a","progressDetail":{"current":1,"total":2}}garbage{{{`))
	// Must not panic; the valid prefix may or may not have reported. Nothing
	// else to assert — the contract is "never fails the pull".
}
