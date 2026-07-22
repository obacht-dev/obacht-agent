// Package basicauth validates and hashes per-domain HTTP Basic Auth
// credentials. Username and bcrypt hash are rendered into the Caddyfile as
// unquoted tokens inside a `basic_auth` block, so both are strictly
// whitelisted here (same defense-in-depth stance as ingress.isValidDomain,
// SEC-12): a value with whitespace, braces or newlines could otherwise
// inject arbitrary Caddy directives.
package basicauth

import (
	"errors"
	"fmt"
	"regexp"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
)

// userRe: printable, shell/Caddyfile-safe, no whitespace or quoting chars.
var userRe = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,64}$`)

// hashRe matches a bcrypt hash as produced by golang.org/x/crypto/bcrypt
// (and accepted by Caddy's basic_auth directive).
var hashRe = regexp.MustCompile(`^\$2[abxy]\$[0-9]{2}\$[./A-Za-z0-9]{53}$`)

// MinPasswordLen is deliberately modest: this guards a personal service
// behind an extra door, it is not an account-password policy.
const MinPasswordLen = 8

// bcrypt silently truncates beyond 72 bytes; reject instead of truncating.
const maxPasswordBytes = 72

// ValidUsername reports whether u is safe to render into the Caddyfile.
func ValidUsername(u string) bool { return userRe.MatchString(u) }

// ValidHash reports whether h looks like a well-formed bcrypt hash.
func ValidHash(h string) bool { return hashRe.MatchString(h) }

// ValidateCredentials checks a username/password pair prior to hashing.
func ValidateCredentials(username, password string) error {
	if !ValidUsername(username) {
		return errors.New("username must be 1-64 characters of [A-Za-z0-9._@-]")
	}
	if !utf8.ValidString(password) {
		return errors.New("password must be valid UTF-8")
	}
	if utf8.RuneCountInString(password) < MinPasswordLen {
		return fmt.Errorf("password must be at least %d characters", MinPasswordLen)
	}
	if len(password) > maxPasswordBytes {
		return fmt.Errorf("password must be at most %d bytes", maxPasswordBytes)
	}
	for _, r := range password {
		if r < 0x20 || r == 0x7f {
			return errors.New("password must not contain control characters")
		}
	}
	return nil
}

// Hash bcrypt-hashes the password with the library default cost (10).
// Caddy verifies this hash on requests; hashing happens once, on set.
func Hash(password string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return string(h), nil
}
