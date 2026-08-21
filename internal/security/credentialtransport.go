package security

// CredentialTransportPolicy controls whether credential-derived material may be
// written to a connection, given what that connection proved about its peer.
//
// It is the sibling of ForwardingPolicy and follows it deliberately.
// ForwardingPolicy answers "may this credential be used against an endpoint
// svcdoctor discovered?"; this answers "may it be written to a channel with
// these properties?". Both are value types with a safe zero value, both are
// decided by whoever configures a run, and neither is a policy engine.
//
//	var policy security.CredentialTransportPolicy       // require verified TLS
//	if !policy.PermitsCredentials(session.Channel()) {
//	    // record that nothing was sent, and why
//	}
//
// # It has exactly one value today, and that is the point
//
// docs/SECURITY.md permits an unsafe transport mode only as an explicit,
// per-run, recorded opt-in, and no layer can express one: there is no CLI, no
// configuration input and no application orchestration. A weaker member added
// now would be a bypass with no owner, reachable by any future caller without
// review. So the set is one member wide, and widening it is a visible change to
// this file with an ADR attached rather than a value somebody sets.
//
// See ADR 0029 for the reopen condition.
//
// # What it must never become
//
// It performs no I/O, holds no state, reads no evidence, knows no graph, and
// names no service. It cannot see a net.Conn and does not want to: it is handed
// a fact somebody else established and returns a yes or a no. Deciding what a
// refusal *means* for the user is diagnosis, and happens somewhere else entirely.
type CredentialTransportPolicy int

const (
	// RequireVerifiedTLS permits credential material only on a connection whose
	// peer identity was verified.
	//
	// It is the zero value, so a policy that was never set, never parsed, or
	// never threaded through a call chain requires verified TLS rather than
	// permitting anything. That is the same choice ForwardingPolicy makes for
	// the same reason: the failure mode of forgetting must be refusal.
	RequireVerifiedTLS CredentialTransportPolicy = iota
)

// String implements fmt.Stringer.
//
// The policy in force is intended to be reportable once a layer exists that can
// choose one, so it needs a stable textual form rather than a bare integer.
func (p CredentialTransportPolicy) String() string {
	if p == RequireVerifiedTLS {
		return "require-verified-tls"
	}
	// An undefined value denies, so it reads as the strictest policy rather
	// than as a number nobody can act on.
	return "require-verified-tls"
}

// PermitsCredentials reports whether credential-derived material may be written
// to a connection with this channel.
//
// Anything other than a verified identity is refused, including ChannelUnknown
// and any undefined value of either type. Both directions of "I do not know"
// therefore fail closed, which is what makes it safe for this to be the only
// question a caller asks.
//
// A false answer is not an error and not a finding. It is a fact the caller
// records: nothing was sent, and the channel is why.
func (p CredentialTransportPolicy) PermitsCredentials(channel Channel) bool {
	if p != RequireVerifiedTLS {
		return false
	}
	return channel.IdentityVerified()
}
