package compose

import "testing"

func TestValidateComposeBodyAllows(t *testing.T) {
	body := `services:
  web:
    image: traefik/whoami:latest
    restart: unless-stopped
    environment:
      FOO: bar
    volumes:
      - data:/data
volumes:
  data:
`
	if err := ValidateComposeBody(body); err != nil {
		t.Fatalf("expected valid body, got %v", err)
	}
}

func TestValidateComposeBodyRejectsForbidden(t *testing.T) {
	cases := map[string]string{
		"ports": `services:
  web:
    image: nginx:1
    ports:
      - "80:80"
`,
		"privileged": `services:
  web:
    image: nginx:1
    privileged: true
`,
		"build": `services:
  web:
    build: .
`,
		"host bind mount": `services:
  web:
    image: nginx:1
    volumes:
      - /etc:/etc
`,
		"undeclared volume": `services:
  web:
    image: nginx:1
    volumes:
      - data:/data
`,
		"forbidden top-level": `secrets:
  x:
    file: ./x
services:
  web:
    image: nginx:1
`,
	}
	for name, body := range cases {
		if err := ValidateComposeBody(body); err == nil {
			t.Errorf("%s: expected rejection, got nil", name)
		}
	}
}

// TestValidateComposeBodyRejectsTopLevelEscapes covers the sandbox escapes that
// slipped past the earlier allowlist because it never inspected top-level
// volume/network DEFINITIONS or the env_file service key.
func TestValidateComposeBodyRejectsTopLevelEscapes(t *testing.T) {
	cases := map[string]string{
		// driver_opts local bind = full host filesystem into the container.
		"volume host bind via driver_opts": `services:
  web:
    image: nginx:1
    volumes:
      - hostroot:/host
volumes:
  hostroot:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: /
`,
		"external volume steals other instance data": `services:
  web:
    image: nginx:1
    volumes:
      - shared:/data
volumes:
  shared:
    external: true
    name: obacht-archived-something
`,
		"network joins obacht-edge": `services:
  web:
    image: nginx:1
    networks:
      - edge
networks:
  edge:
    external: true
    name: obacht-edge
`,
		"macvlan network raw LAN presence": `services:
  web:
    image: nginx:1
    networks:
      - lan
networks:
  lan:
    driver: macvlan
    driver_opts:
      parent: eth0
`,
		"env_file reads arbitrary host file": `services:
  web:
    image: nginx:1
    env_file:
      - /var/lib/obacht/agent/secrets.env
`,
	}
	for name, body := range cases {
		if err := ValidateComposeBody(body); err == nil {
			t.Errorf("%s: expected rejection, got nil", name)
		}
	}
}

// TestValidateComposeBodyAllowsSafeDefs confirms the hardening didn't break the
// legitimate shapes: an x-obacht-data volume, a plain named network, and
// label-only / empty definitions.
func TestValidateComposeBodyAllowsSafeDefs(t *testing.T) {
	body := `services:
  web:
    image: nginx:1
    networks:
      - internal
    volumes:
      - data:/data
networks:
  internal:
volumes:
  data:
    x-obacht-data: true
    labels:
      keep: "true"
`
	if err := ValidateComposeBody(body); err != nil {
		t.Fatalf("expected valid body, got %v", err)
	}
}

func TestValidateComposeBodyRequiresServices(t *testing.T) {
	if err := ValidateComposeBody("volumes:\n  data:\n"); err == nil {
		t.Error("expected error when services missing")
	}
}
