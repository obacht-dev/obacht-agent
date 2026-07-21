package system

import (
	"strings"
	"testing"

	"github.com/obacht-dev/obacht-agent/internal/unitpolicy"
)

// The generator and the helper's unitpolicy are two halves of one contract:
// every unit the generator can emit must pass the policy, for every valid
// spec shape.
func TestGeneratedUnitAlwaysPassesPolicy(t *testing.T) {
	instanceID := "0af3c1d2-77aa-4bcd-9e00-1234567890ab"
	base := validManaged()
	variants := []func(*ManagedServiceSpec){
		func(m *ManagedServiceSpec) {},
		func(m *ManagedServiceSpec) { m.Args = []string{"/etc/obacht/svc/" + instanceID + "/mediamtx.yml"} },
		func(m *ManagedServiceSpec) {
			m.Hardware = &ManagedHardware{Groups: []string{"video", "render"}, Devices: []string{"/dev/video*", "/dev/media*", "/dev/dri/*"}}
		},
		func(m *ManagedServiceSpec) { m.Env = map[string]string{"MTX_LOGLEVEL": "info", "MTX_HLS": "yes"} },
		func(m *ManagedServiceSpec) { m.Kind = "" },
	}
	for i, fn := range variants {
		ms := *base
		fn(&ms)
		unit, err := GenerateManagedUnit(instanceID, ms)
		if err != nil {
			t.Fatalf("variant %d: generate: %v", i, err)
		}
		if err := unitpolicy.Validate(ManagedUnitName(instanceID), []byte(unit)); err != nil {
			t.Errorf("variant %d: generated unit fails policy: %v\n%s", i, err, unit)
		}
	}
}

func TestGeneratedUnitIsDeterministic(t *testing.T) {
	instanceID := "abc-123"
	ms := *validManaged()
	ms.Env = map[string]string{"B": "2", "A": "1", "C": "3"}
	ms.Hardware = &ManagedHardware{Groups: []string{"render", "video"}, Devices: []string{"/dev/media*", "/dev/video*"}}
	first, err := GenerateManagedUnit(instanceID, ms)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		again, err := GenerateManagedUnit(instanceID, ms)
		if err != nil {
			t.Fatal(err)
		}
		if again != first {
			t.Fatal("unit generation is not deterministic (map iteration leak?)")
		}
	}
}

// Hostile spec values must be stopped by the generator's own policy check
// even when spec validate() alone would let the string shape through.
func TestGeneratorRejectsPolicyViolatingArgs(t *testing.T) {
	instanceID := "abc-123"
	for label, args := range map[string][]string{
		"shell substitution": {"$(id)"},
		"semicolon":          {"a;b"},
		"quote":              {`"x"`},
		"specifier":          {"%h/.ssh"},
	} {
		ms := *validManaged()
		ms.Args = args
		if _, err := GenerateManagedUnit(instanceID, ms); err == nil {
			t.Errorf("%s: generator accepted hostile arg %v", label, args)
		}
	}
}

func TestManagedUnitName(t *testing.T) {
	name := ManagedUnitName("0af3-77")
	if name != "obacht-svc-0af3-77.service" {
		t.Fatalf("unexpected unit name %q", name)
	}
	if err := unitpolicy.ValidateName(name); err != nil {
		t.Fatalf("unit name fails policy: %v", err)
	}
	if !strings.HasPrefix(name, "obacht-") {
		t.Fatal("unit name must keep the obacht- prefix (svc verb regex)")
	}
}
