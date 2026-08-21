package security

import "testing"

// TestZeroForwardingPolicyIsDeny is the reason this type exists. A policy that
// was never set, never parsed, or never threaded through a call chain must deny.
func TestZeroForwardingPolicyIsDeny(t *testing.T) {
	var p ForwardingPolicy

	if p != ForwardDeny {
		t.Errorf("zero ForwardingPolicy = %d, want ForwardDeny", p)
	}
	if p.AllowsForwarding() {
		t.Error("the zero ForwardingPolicy must not allow forwarding")
	}
	if p.String() != "deny" {
		t.Errorf("String() = %q, want %q", p.String(), "deny")
	}
}

func TestForwardingPolicyAllows(t *testing.T) {
	tests := []struct {
		name   string
		policy ForwardingPolicy
		allows bool
		text   string
	}{
		{"deny", ForwardDeny, false, "deny"},
		{"allow explicit", ForwardAllowExplicit, true, "allow-explicit"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.policy.AllowsForwarding(); got != tt.allows {
				t.Errorf("AllowsForwarding() = %v, want %v", got, tt.allows)
			}
			if got := tt.policy.String(); got != tt.text {
				t.Errorf("String() = %q, want %q", got, tt.text)
			}
		})
	}
}

// TestUnknownForwardingPolicyFailsClosed covers a value arriving from a future
// parser or a corrupted source: it must deny rather than permit.
func TestUnknownForwardingPolicyFailsClosed(t *testing.T) {
	for _, p := range []ForwardingPolicy{-1, 42} {
		if p.AllowsForwarding() {
			t.Errorf("ForwardingPolicy(%d) must not allow forwarding", p)
		}
		if p.String() != "deny" {
			t.Errorf("ForwardingPolicy(%d).String() = %q, want %q", p, p.String(), "deny")
		}
	}
}
