package compose

import (
	"reflect"
	"testing"
)

func TestImageRefs(t *testing.T) {
	body := `
services:
  app:
    image: ghcr.io/example/app:1.2.3@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  db:
    image: "postgres:16"
  cache:
    image: 'redis:7'
  dup:
    image: "postgres:16"
`
	got := imageRefs(body)
	want := []string{
		"ghcr.io/example/app:1.2.3@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"postgres:16",
		"redis:7",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("imageRefs mismatch:\n got %v\nwant %v", got, want)
	}
}

func TestImageRefsEmptyBody(t *testing.T) {
	if refs := imageRefs("services: {}\n"); len(refs) != 0 {
		t.Fatalf("expected no refs, got %v", refs)
	}
}
