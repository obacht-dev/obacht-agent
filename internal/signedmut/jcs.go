// Package signedmut implements user-signed device mutations received over
// the backend WebSocket relay (`agent:signed_mutation`).
//
// Security model (see docs/SIGNED-MUTATION-AUTH-PLAN.md in obacht-macapp):
// every mutation is an ed25519 signature by the USER's key over the JCS
// (RFC 8785) canonicalization of the mutation object. The backend merely
// relays the envelope — it holds no signing key, so a compromised backend
// can replay-attempt or drop mutations but never forge or alter them. The
// agent verifies locally against pubkeys pinned at enrollment time
// (user-keys.d/), checks the device binding, an expiry window and a
// persistent nonce store before dispatching to the same internal mutators
// obachtctl uses.
//
// The package is platform-neutral on purpose: a later Pi agent release
// activates the same path (SSH→WS migration stage 1) without changes here.
package signedmut

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// canonicalize renders a decoded JSON value (as produced by decodeJSON in
// envelope.go: map[string]any / []any / string / int64 / bool / nil) into
// its RFC 8785 (JCS) canonical form.
//
// We deliberately support only the subset our mutation objects use:
// objects, arrays, strings, booleans, null and INTEGERS within the
// JavaScript safe range. Non-integer numbers are rejected — ES6 float
// serialization is the one genuinely hairy part of JCS and nothing in a
// mutation needs floats. Rejecting beats canonicalizing wrongly.
func canonicalize(v any) ([]byte, error) {
	var b strings.Builder
	if err := writeCanonical(&b, v); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

func writeCanonical(b *strings.Builder, v any) error {
	switch t := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if t {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case int64:
		if t > maxSafeInteger || t < -maxSafeInteger {
			return fmt.Errorf("integer %d outside JS safe range", t)
		}
		b.WriteString(strconv.FormatInt(t, 10))
	case string:
		if err := validateUTF8(t); err != nil {
			return err
		}
		writeJCSString(b, t)
	case []any:
		b.WriteByte('[')
		for i, el := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeCanonical(b, el); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sortUTF16(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := validateUTF8(k); err != nil {
				return err
			}
			writeJCSString(b, k)
			b.WriteByte(':')
			if err := writeCanonical(b, t[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("unsupported JSON value of type %T", v)
	}
	return nil
}

const maxSafeInteger = int64(1)<<53 - 1 // Number.MAX_SAFE_INTEGER

// sortUTF16 sorts keys by their UTF-16 code unit sequence as RFC 8785
// requires. For pure-ASCII keys (everything we emit today) this equals
// byte order, but doing it properly costs little.
func sortUTF16(keys []string) {
	sort.Slice(keys, func(i, j int) bool {
		a, b := utf16.Encode([]rune(keys[i])), utf16.Encode([]rune(keys[j]))
		for k := 0; k < len(a) && k < len(b); k++ {
			if a[k] != b[k] {
				return a[k] < b[k]
			}
		}
		return len(a) < len(b)
	})
}

// writeJCSString escapes exactly like ES6 JSON.stringify (RFC 8785 §3.2.2.2):
// backslash, double quote, and control chars — \b \t \n \f \r get their
// two-char escapes, every other char < 0x20 becomes lowercase \u00xx.
// Everything else (including non-ASCII) is emitted literally as UTF-8.
// Note: Go's encoding/json would additionally escape <, >, & and
// U+2028/U+2029, which would break cross-language byte identity.
func writeJCSString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\f':
			b.WriteString(`\f`)
		case '\r':
			b.WriteString(`\r`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

// validateUTF8 guards against mutation payloads that are not valid UTF-8 —
// utf16.Encode would silently replace bad bytes and two parties could then
// "agree" on different canonical forms.
func validateUTF8(s string) error {
	if !utf8.ValidString(s) {
		return errors.New("invalid UTF-8 in JSON string")
	}
	return nil
}
