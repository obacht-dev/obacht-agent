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

func TestValidateComposeBodyRequiresServices(t *testing.T) {
	if err := ValidateComposeBody("volumes:\n  data:\n"); err == nil {
		t.Error("expected error when services missing")
	}
}
