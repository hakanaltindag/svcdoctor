package probe

import (
	"errors"
	"fmt"
	"net/netip"
)

// ErrUnsupportedHost reports a host svcdoctor declines to measure, because it
// cannot represent the result truthfully.
//
// It is deliberately distinct from "this host does not resolve", which is a
// diagnostic fact about the target and comes back as evidence. This is a
// statement about svcdoctor: the input is well formed, and the run would produce
// a report that says something the run did not do.
var ErrUnsupportedHost = errors.New("unsupported host")

// Host is the one place svcdoctor decides what an operator's `--host` value is.
//
// A host is either an IP address literal or a name to resolve, and the two lead
// to different work: a literal is already the address, so there is nothing to
// look up, while a name needs a resolver before any socket exists. That is not a
// rendering distinction — it decides whether an L1 measurement happens at all,
// and therefore whether an L1 node belongs in the graph.
//
// # Why the classification lives here rather than in each caller
//
// Three layers need the same answer: input normalization mints the requested
// target from it, the transport chain decides whether to resolve, and the
// credential binding key is built from the same canonical spelling. Three
// implementations of "is this an IP" would eventually disagree, and the report
// that disagreement produces is one where the anchor, the connection subject and
// the credential endpoint name three different things — which this repository
// has already measured happening for a non-canonical IPv6 literal.
//
// The zero Host is invalid. Use ParseHost.
type Host struct {
	// name is the canonical spelling. For a literal it is addr.String(); for a
	// name it is the input verbatim, because normalizing a name changes the
	// question that gets asked and evidence must record the question asked.
	name string

	addr    netip.Addr
	literal bool
}

// ParseHost classifies host and returns its canonical form.
//
// # Detection is net/netip and nothing else
//
// netip.ParseAddr is the whole rule. It was chosen over net.ParseIP because it
// yields a canonical *value* rather than a byte slice: netip.Addr.String emits
// dotted decimal for IPv4 and the RFC 5952 form for IPv6, so canonicalization is
// the same standard-library function that performed the detection and the two
// cannot drift apart. It is also the type the DNS probe, the TCP probe and
// security.Endpoint already speak, so a literal keeps one representation from
// input to socket.
//
// Anything netip.ParseAddr rejects is a name. That includes strings that merely
// look like addresses — "10.0.0.256", "1.2.3", "::gg" and an IPv4 form with a
// leading zero such as "010.0.0.1", which netip refuses rather than reinterpret
// as octal. Each of those is handed to the resolver, which is the component
// entitled to say whether it names anything, and none of them becomes a literal
// by accident.
//
// # An IPv4-mapped IPv6 literal is unmapped
//
// "::ffff:192.0.2.1" canonicalizes to "192.0.2.1". It is the same peer, and this
// is the rule the DNS probe already applies to resolver answers so that one
// address has one canonical spelling. Keeping the mapped form would also render
// an IPv4 address inside IPv6 brackets — "[::ffff:192.0.2.1]:9092" — which is
// syntactically correct and reads as a different endpoint from the one the
// operator typed.
//
// # A zone identifier is refused, not accepted and not silently dropped
//
// "fe80::1%en0" parses, and svcdoctor declines it.
//
// The zone is a vantage-local interface name, and every layer below this one
// would have to carry it truthfully: the evidence subject, the credential
// binding key, the TLS identity presented for verification, and the
// pseudonymization namespace a shareable report puts it in. None of those has a
// decision recorded for it, and inventing four at once inside a phase about
// address literals is how a half-supported form ships.
//
// It is refused rather than left alone because the alternative was measured and
// is worse. Go's resolver strips the zone from a literal it is handed, so before
// this rule `--host fe80::1%lo0` produced a report whose anchor said
// "[fe80::1%lo0]:1" and whose connection attempt said "[fe80::1]:1" — svcdoctor
// naming one endpoint and measuring another. An error naming the limitation is
// the honest outcome; a report that measures a different address is not.
//
// Support is deferred, not rejected. See ADR 0059.
func ParseHost(host string) (Host, error) {
	if host == "" {
		return Host{}, fmt.Errorf("%w: host must not be empty", ErrUnsupportedHost)
	}

	addr, err := netip.ParseAddr(host)
	if err != nil {
		return Host{name: host}, nil
	}
	if addr.Zone() != "" {
		return Host{}, fmt.Errorf(
			"%w: %s carries an IPv6 zone identifier, which svcdoctor cannot yet measure "+
				"truthfully; supply the address without %%zone", ErrUnsupportedHost, host)
	}

	addr = addr.Unmap()
	return Host{name: addr.String(), addr: addr, literal: true}, nil
}

// String returns the canonical spelling.
//
// It is the value every later layer must use: the requested-target label, the
// logical endpoint a connection is scoped by, the credential binding key and the
// identity a TLS handshake verifies. For a literal it is bare — never bracketed
// — because bracketing belongs to endpoint formatting, which happens once, in
// net.JoinHostPort, at the point a host and a port are joined.
func (h Host) String() string { return h.name }

// IsLiteral reports whether the host is an IP address rather than a name.
//
// A caller reads this to decide whether resolution is work that needs doing, and
// for no other purpose. It is not a rendering flag and not a policy switch: a
// literal and a name reach exactly the same TCP, TLS and protocol code.
func (h Host) IsLiteral() bool { return h.literal }

// Addr returns the address a literal host denotes.
//
// The second result is false for a name, which has no address until something
// resolves it. Calling this on a name and using the zero Addr would dial
// "invalid IP", which is why the answer is two values rather than one.
func (h Host) Addr() (netip.Addr, bool) { return h.addr, h.literal }

// IsZero reports whether h is the invalid zero Host.
func (h Host) IsZero() bool { return h.name == "" }
