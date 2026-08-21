package security

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// ErrInvalidEndpoint is returned when an endpoint cannot be normalized.
var ErrInvalidEndpoint = errors.New("invalid endpoint")

// Endpoint is a normalized host and port used to bind a Credential.
//
// It is deliberately minimal and lives in this package rather than in the
// future domain model, because credential binding must not wait for the domain
// package to exist. It is a comparison key, not a connection target: it carries
// no scheme, no address family preference, and no resolution result.
//
// The zero Endpoint is invalid. Use NewEndpoint.
type Endpoint struct {
	host string // normalized; see NewEndpoint
	port uint16
}

// NewEndpoint normalizes host and port into an Endpoint.
//
// Normalization rules:
//
//   - An IP literal is canonicalized through net/netip, so "::1" and
//     "0:0:0:0:0:0:0:1" compare equal, and an IPv6 zone such as "fe80::1%eth0"
//     is preserved and significant.
//   - Any other host is treated as a DNS name and lowercased using ASCII rules
//     only, because DNS case insensitivity is defined for ASCII (RFC 4343).
//     Non-ASCII bytes are left untouched rather than passed through Unicode
//     case folding, which would not match DNS semantics.
//   - A single trailing dot is removed, so "kafka.internal." and
//     "kafka.internal" compare equal.
//
// Port 0 is rejected: svcdoctor always inspects a concrete port, and rejecting
// it keeps the zero Endpoint unambiguously invalid.
func NewEndpoint(host string, port uint16) (Endpoint, error) {
	if host == "" {
		return Endpoint{}, fmt.Errorf("%w: empty host", ErrInvalidEndpoint)
	}
	if port == 0 {
		return Endpoint{}, fmt.Errorf("%w: port 0 is not a valid target", ErrInvalidEndpoint)
	}
	return Endpoint{host: normalizeHost(host), port: port}, nil
}

// Host returns the normalized host.
func (e Endpoint) Host() string { return e.host }

// Port returns the port.
func (e Endpoint) Port() uint16 { return e.port }

// IsZero reports whether e is the invalid zero Endpoint.
func (e Endpoint) IsZero() bool { return e == Endpoint{} }

// String returns "host:port", bracketing IPv6 literals.
//
// This deliberately does not use net.JoinHostPort. Importing net would link the
// standard library's network stack, including the DNS resolver, into the
// package that holds secrets, and the only thing needed from it is the
// bracketing rule below. A host containing a colon is an IPv6 literal, possibly
// with a zone; a DNS name never contains one.
func (e Endpoint) String() string {
	if e.IsZero() {
		return "<invalid endpoint>"
	}
	port := strconv.FormatUint(uint64(e.port), 10)
	if strings.Contains(e.host, ":") {
		return "[" + e.host + "]:" + port
	}
	return e.host + ":" + port
}

// Equal reports whether e and other denote the same endpoint.
//
// Comparison is over the normalized host string and the port. It is
// deliberately name based: two endpoints are not equal merely because their
// hostnames resolve to the same IP address. Resolution is a runtime fact that
// can change, can differ per vantage point, and can be attacker influenced, so
// it must never widen the scope of a credential.
func (e Endpoint) Equal(other Endpoint) bool {
	return e == other
}

// normalizeHost applies the rules documented on NewEndpoint.
func normalizeHost(host string) string {
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.String()
	}
	if len(host) > 1 && strings.HasSuffix(host, ".") {
		host = host[:len(host)-1]
	}
	return asciiLower(host)
}

// asciiLower lowercases A-Z only, leaving every other byte untouched.
func asciiLower(s string) string {
	var b []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			if b == nil {
				b = []byte(s)
			}
			b[i] = c + ('a' - 'A')
		}
	}
	if b == nil {
		return s
	}
	return string(b)
}
