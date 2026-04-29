package redact

import (
	"reflect"
	"sort"
	"testing"
)

func TestIsSecretKey(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{
		"DB_PASSWORD":     true,
		"db_password":     true,
		"API_TOKEN":       true,
		"apiToken":        true, // contains TOKEN
		"GITHUB_TOKEN":    true,
		"PRIVATE_KEY":     true,
		"AWS_SECRET":      true,
		"FOO_API_KEY":     true,
		"KEY":             true,
		"SOMETHING_KEY":   true,
		"PUBLIC_KEY":      true, // contains KEY suffix
		"PORT":            false,
		"HOST":            false,
		"USERNAME":        false,
		"DATABASE_URL":    false,
		"monkey":          false, // KEY substring should not match here
		"DEBUG":           false,
	}
	for k, want := range cases {
		got := IsSecretKey(k)
		if got != want {
			t.Errorf("IsSecretKey(%q) = %v, want %v", k, got, want)
		}
	}
}

func TestEnvMap(t *testing.T) {
	t.Parallel()
	in := map[string]string{
		"DB_PASSWORD":  "hunter2",
		"PORT":         "8080",
		"CUSTOM_THING": "ok",
		"OTHER":        "leak-me",
	}
	out := EnvMap(in, []string{"OTHER"})
	if out["DB_PASSWORD"] != Placeholder {
		t.Errorf("DB_PASSWORD not redacted: %q", out["DB_PASSWORD"])
	}
	if out["OTHER"] != Placeholder {
		t.Errorf("manifest-declared OTHER not redacted: %q", out["OTHER"])
	}
	if out["PORT"] != "8080" {
		t.Errorf("PORT was wrongly redacted: %q", out["PORT"])
	}
	if out["CUSTOM_THING"] != "ok" {
		t.Errorf("CUSTOM_THING wrongly redacted: %q", out["CUSTOM_THING"])
	}
	// input must not be mutated
	if in["DB_PASSWORD"] != "hunter2" {
		t.Errorf("EnvMap mutated its input")
	}
}

func TestEnvSlice(t *testing.T) {
	t.Parallel()
	in := []string{
		"DB_PASSWORD=hunter2",
		"PORT=8080",
		"OTHER=leak-me",
		"NO_EQUAL_SIGN",
	}
	got := EnvSlice(in, []string{"OTHER"})
	want := []string{
		"DB_PASSWORD=" + Placeholder,
		"PORT=8080",
		"OTHER=" + Placeholder,
		"NO_EQUAL_SIGN",
	}
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("EnvSlice mismatch\n got: %v\nwant: %v", got, want)
	}
}

func TestEnvMapNilSafe(t *testing.T) {
	t.Parallel()
	got := EnvMap(nil, nil)
	if got == nil || len(got) != 0 {
		t.Errorf("EnvMap(nil) = %v, want empty map", got)
	}
}
