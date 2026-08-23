package probe_test

import (
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/probe"
)

// Phase 6.7 — what an operator's `--host` value is, decided once.
//
// The classification decides whether an L1 measurement happens at all, so a
// mistake here is not a rendering defect: it is either a fabricated DNS node for
// an address, or a name handed to no resolver. Both are pinned below.

func TestAnAddressLiteralIsRecognizedInBothFamilies(t *testing.T) {
	for _, in := range []string{
		"10.0.0.1",
		"127.0.0.1",
		"192.168.1.10",
		"0.0.0.0",
		"255.255.255.255",
		"::1",
		"2001:db8::1",
		"fe80::1",
		"::",
	} {
		t.Run(in, func(t *testing.T) {
			h, err := probe.ParseHost(in)
			if err != nil {
				t.Fatalf("ParseHost(%q): %v", in, err)
			}
			if !h.IsLiteral() {
				t.Fatalf("ParseHost(%q).IsLiteral() = false, want true", in)
			}
			if _, ok := h.Addr(); !ok {
				t.Fatal("a literal host returned no address")
			}
		})
	}
}

// A name is anything netip.ParseAddr refuses, including strings that look like
// addresses. Each of these must reach a resolver rather than become a literal,
// because only the resolver is entitled to say whether it names anything.
func TestAHostThatOnlyLooksLikeAnAddressIsAName(t *testing.T) {
	for _, in := range []string{
		"broker-1.internal",
		"localhost",
		"10.0.0.256",   // out of range
		"1.2.3",        // too few octets
		"1.2.3.4.5",    // too many
		"010.0.0.1",    // leading zero: refused, never read as octal
		"::gg",         // not hex
		"2001:db8::1:", // trailing separator
		"10.0.0.1:80",  // an endpoint, not a host
		"[::1]",        // bracketed: brackets belong to endpoint formatting
		"1.2.3.4 ",     // trailing space
	} {
		t.Run(in, func(t *testing.T) {
			h, err := probe.ParseHost(in)
			if err != nil {
				t.Fatalf("ParseHost(%q): %v", in, err)
			}
			if h.IsLiteral() {
				t.Fatalf("ParseHost(%q).IsLiteral() = true, want false: it must be resolved, not dialled", in)
			}
			if h.String() != in {
				t.Fatalf("a name was rewritten: %q -> %q", in, h.String())
			}
			if _, ok := h.Addr(); ok {
				t.Fatal("a name reported an address")
			}
		})
	}
}

// Canonicalization is what stops one address becoming two evidence identities.
// Every input in a group must produce the same canonical spelling.
func TestSpellingsOfOneAddressConverge(t *testing.T) {
	groups := [][]string{
		{"2001:db8::1", "2001:0db8:0:0:0:0:0:1", "2001:DB8::1", "2001:0db8::0001"},
		{"::1", "0:0:0:0:0:0:0:1"},
		{"10.0.0.1"},
		// An IPv4-mapped IPv6 literal is the same peer as the IPv4 address, and
		// unmapping is the rule the DNS probe already applies to answers.
		{"192.0.2.1", "::ffff:192.0.2.1", "::ffff:c000:201"},
	}
	for _, group := range groups {
		want, err := probe.ParseHost(group[0])
		if err != nil {
			t.Fatalf("ParseHost(%q): %v", group[0], err)
		}
		for _, in := range group[1:] {
			got, err := probe.ParseHost(in)
			if err != nil {
				t.Fatalf("ParseHost(%q): %v", in, err)
			}
			if got.String() != want.String() {
				t.Errorf("ParseHost(%q) = %q, want %q: one address, one spelling",
					in, got.String(), want.String())
			}
		}
	}
}

// The canonical spelling is the standard library's, so IPv6 is RFC 5952 and IPv4
// is dotted decimal. Pinned literally, because every subject, identifier and
// rendered endpoint in a report is derived from it.
func TestTheCanonicalSpellingIsPinned(t *testing.T) {
	for in, want := range map[string]string{
		"2001:0db8:0:0:0:0:0:1": "2001:db8::1",
		"::ffff:192.0.2.1":      "192.0.2.1",
		"0:0:0:0:0:0:0:1":       "::1",
		"10.0.0.1":              "10.0.0.1",
		"FE80::A":               "fe80::a",
	} {
		h, err := probe.ParseHost(in)
		if err != nil {
			t.Fatalf("ParseHost(%q): %v", in, err)
		}
		if h.String() != want {
			t.Errorf("ParseHost(%q) = %q, want %q", in, h.String(), want)
		}
	}
}

// ParseHost is idempotent: feeding its own output back must not move.
func TestCanonicalizationIsIdempotent(t *testing.T) {
	for _, in := range []string{
		"2001:0db8:0:0:0:0:0:1", "::ffff:192.0.2.1", "10.0.0.1", "broker.internal",
	} {
		once, err := probe.ParseHost(in)
		if err != nil {
			t.Fatalf("ParseHost(%q): %v", in, err)
		}
		twice, err := probe.ParseHost(once.String())
		if err != nil {
			t.Fatalf("ParseHost(%q): %v", once.String(), err)
		}
		if twice.String() != once.String() || twice.IsLiteral() != once.IsLiteral() {
			t.Errorf("ParseHost is not idempotent for %q: %q then %q", in, once.String(), twice.String())
		}
	}
}

// The canonical spelling is never bracketed. Brackets belong to endpoint
// formatting, which happens once when a host and a port are joined; a bracketed
// host would be double-bracketed there and would reach TLS as an identity no
// certificate can carry.
func TestACanonicalHostIsNeverBracketed(t *testing.T) {
	for _, in := range []string{"::1", "2001:db8::1", "fe80::a", "10.0.0.1"} {
		h, err := probe.ParseHost(in)
		if err != nil {
			t.Fatalf("ParseHost(%q): %v", in, err)
		}
		if strings.ContainsAny(h.String(), "[]") {
			t.Errorf("ParseHost(%q) = %q: a canonical host carries no brackets", in, h.String())
		}
		endpoint := net.JoinHostPort(h.String(), strconv.Itoa(9092))
		if strings.Count(endpoint, "[") > 1 || strings.Count(endpoint, "]") > 1 {
			t.Errorf("joining %q produced %q: double brackets", h.String(), endpoint)
		}
		if _, _, err := net.SplitHostPort(endpoint); err != nil {
			t.Errorf("the endpoint %q built from %q does not round-trip: %v", endpoint, in, err)
		}
	}
}

// An IPv6 zone identifier is refused rather than accepted or silently dropped.
//
// Accepting it would carry a vantage-local interface name into the evidence
// subject, the credential binding key, the TLS identity and the pseudonym
// namespace, none of which has a decision recorded for it. Leaving it alone was
// measured and is worse: Go's resolver strips the zone, so the run named one
// endpoint and measured another.
func TestAZonedAddressIsRefused(t *testing.T) {
	for _, in := range []string{"fe80::1%en0", "fe80::1%lo0", "fe80::1%25"} {
		h, err := probe.ParseHost(in)
		if !errors.Is(err, probe.ErrUnsupportedHost) {
			t.Fatalf("ParseHost(%q) error = %v, want ErrUnsupportedHost", in, err)
		}
		if !h.IsZero() {
			t.Errorf("ParseHost(%q) returned a usable host alongside its error", in)
		}
		if !strings.Contains(err.Error(), "zone") {
			t.Errorf("the refusal does not name the limitation: %v", err)
		}
	}
}

// The refusal is not a general IPv6 refusal.
func TestRefusingZonesDoesNotRefuseIPv6(t *testing.T) {
	h, err := probe.ParseHost("fe80::1")
	if err != nil {
		t.Fatalf("an unzoned link-local address was refused: %v", err)
	}
	if !h.IsLiteral() {
		t.Fatal("fe80::1 is an address literal")
	}
}

func TestAnEmptyHostIsRefused(t *testing.T) {
	if _, err := probe.ParseHost(""); !errors.Is(err, probe.ErrUnsupportedHost) {
		t.Fatalf("ParseHost(\"\") error = %v, want ErrUnsupportedHost", err)
	}
}

// The address a literal yields is the canonical one, so a caller that dials it
// reaches the endpoint the report names.
func TestTheAddressMatchesTheCanonicalSpelling(t *testing.T) {
	h, err := probe.ParseHost("2001:0db8:0:0:0:0:0:1")
	if err != nil {
		t.Fatalf("ParseHost: %v", err)
	}
	addr, ok := h.Addr()
	if !ok {
		t.Fatal("no address")
	}
	if addr.String() != h.String() {
		t.Fatalf("address %q disagrees with canonical host %q", addr.String(), h.String())
	}
	if addr != netip.MustParseAddr("2001:db8::1") {
		t.Fatalf("addr = %v, want 2001:db8::1", addr)
	}
	if addr.Zone() != "" {
		t.Fatal("a canonical address carries no zone")
	}
}
