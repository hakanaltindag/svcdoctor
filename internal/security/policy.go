package security

// ForwardingPolicy controls whether a credential may be used against an
// endpoint discovered through topology discovery rather than supplied by the
// user.
//
// The zero value is ForwardDeny. That is the entire point of the type: a policy
// that was never set, never parsed, or never threaded through a call chain
// denies forwarding rather than permitting it. See docs/SECURITY.md item 8.
//
// This is a value type, not a policy engine. Topology discovery does not exist
// yet; this establishes the vocabulary and the safe default so that the
// discovery code cannot be written without confronting the decision.
type ForwardingPolicy int

const (
	// ForwardDeny refuses to use credentials against discovered endpoints.
	// Discovered endpoints are verified with credential-free checks instead.
	// This is the zero value and the default.
	ForwardDeny ForwardingPolicy = iota

	// ForwardAllowExplicit permits authenticated follow-up against discovered
	// endpoints. It requires a deliberate opt-in and is recorded in the report.
	ForwardAllowExplicit
)

// String implements fmt.Stringer.
//
// The policy in force is recorded in the report's security section, so it needs
// a stable textual form rather than a bare integer.
func (p ForwardingPolicy) String() string {
	switch p {
	case ForwardDeny:
		return "deny"
	case ForwardAllowExplicit:
		return "allow-explicit"
	default:
		return "deny"
	}
}

// AllowsForwarding reports whether credentials may be forwarded to a
// topology-discovered endpoint.
//
// Unknown values deny, so a policy that arrives from a future parser or a
// corrupted value fails closed rather than open.
func (p ForwardingPolicy) AllowsForwarding() bool {
	return p == ForwardAllowExplicit
}
