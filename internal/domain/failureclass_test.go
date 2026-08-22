package domain

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// TestFailureClassString covers a representative class from every category.
func TestFailureClassString(t *testing.T) {
	tests := []struct {
		class FailureClass
		want  string
	}{
		{FailureNone, "NONE"},
		{FailureDNSNXDomain, "DNS_NXDOMAIN"},
		{FailureDNSResolverFailure, "DNS_RESOLVER_FAILURE"},
		{FailureTCPConnectionRefused, "TCP_CONNECTION_REFUSED"},
		{FailureTCPHostUnreachable, "TCP_HOST_UNREACHABLE"},
		{FailureTLSCertificateExpired, "TLS_CERTIFICATE_EXPIRED"},
		{FailureTLSHostnameMismatch, "TLS_HOSTNAME_MISMATCH"},
		{FailureTLSClientCertificateRejected, "TLS_CLIENT_CERTIFICATE_REJECTED"},
		{FailureProtocolUnsupportedVersion, "PROTOCOL_UNSUPPORTED_VERSION"},
		{FailureProtocolPeerClosed, "PROTOCOL_PEER_CLOSED"},
		{FailureAuthCredentialsRejected, "AUTH_CREDENTIALS_REJECTED"},
		{FailureAuthMechanismNotOffered, "AUTH_MECHANISM_NOT_OFFERED"},
		{FailureAuthzDenied, "AUTHZ_DENIED"},
		{FailureAuthzScopeInsufficient, "AUTHZ_SCOPE_INSUFFICIENT"},
		{FailureExecLocalTimeout, "EXEC_LOCAL_TIMEOUT"},
		{FailureExecUnsupportedBySvcdoctor, "EXEC_UNSUPPORTED_BY_SVCDOCTOR"},
		{FailureExecInsufficientPrivilege, "EXEC_INSUFFICIENT_PRIVILEGE"},
		{FailureExecSkippedPrerequisiteFailed, "EXEC_SKIPPED_PREREQUISITE_FAILED"},
		{FailureExecDepthLimit, "EXEC_DEPTH_LIMIT"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.class.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
			if !tt.class.Valid() {
				t.Error("class must be valid")
			}
		})
	}
}

func TestFailureClassJSON(t *testing.T) {
	got, err := json.Marshal(FailureTCPConnectionRefused)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if string(got) != `"TCP_CONNECTION_REFUSED"` {
		t.Errorf("json.Marshal = %s, want \"TCP_CONNECTION_REFUSED\"", got)
	}
}

// TestFailureClassZeroIsNone pins the decision that an unset class means "no
// failure", which is correct on a PASS node per docs/REPORT_SCHEMA.md.
func TestFailureClassZeroIsNone(t *testing.T) {
	var f FailureClass

	if f != FailureNone {
		t.Errorf("zero FailureClass = %d, want FailureNone", f)
	}
	if !f.Valid() {
		t.Error("FailureNone must be valid")
	}
	if f.String() != "NONE" {
		t.Errorf("String() = %q, want %q", f.String(), "NONE")
	}

	got, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if string(got) != `"NONE"` {
		t.Errorf("json.Marshal = %s, want \"NONE\"", got)
	}
}

func TestInvalidFailureClass(t *testing.T) {
	invalid := FailureClass(200)

	if invalid.Valid() {
		t.Error("FailureClass(200) must not be valid")
	}
	if got := invalid.String(); got != "FailureClass(200)" {
		t.Errorf("String() = %q, want %q", got, "FailureClass(200)")
	}

	_, err := json.Marshal(invalid)
	if !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("json.Marshal error = %v, want ErrInvalidValue", err)
	}
}

// TestTransportCategoriesStayDistinct guards first-broken-layer accuracy: DNS,
// TCP and TLS failures must never be conflated.
func TestTransportCategoriesStayDistinct(t *testing.T) {
	groups := map[string][]FailureClass{
		"DNS_": {FailureDNSNXDomain, FailureDNSNoAddress, FailureDNSTimeout, FailureDNSResolverFailure},
		"TCP_": {
			FailureTCPConnectionRefused, FailureTCPConnectionTimeout, FailureTCPConnectionReset,
			FailureTCPNetworkUnreachable, FailureTCPHostUnreachable, FailureTCPConnectionFailed,
		},
		"TLS_": {
			FailureTLSHandshakeFailure, FailureTLSCertificateExpired, FailureTLSCertificateNotYetValid,
			FailureTLSUnknownAuthority, FailureTLSHostnameMismatch, FailureTLSVersionMismatch,
			FailureTLSClientCertificateRequired, FailureTLSClientCertificateRejected,
			FailureTLSPeerNotTLS,
		},
	}

	seen := map[FailureClass]string{}
	for prefix, classes := range groups {
		for _, c := range classes {
			if !strings.HasPrefix(c.String(), prefix) {
				t.Errorf("%s should carry the %q prefix", c, prefix)
			}
			if other, dup := seen[c]; dup {
				t.Errorf("%s appears in both %q and %q", c, other, prefix)
			}
			seen[c] = prefix
		}
	}
}

// TestAuthAndAuthzStayDistinct guards the difference between "your credentials
// are wrong" and "your credentials are fine but you lack permission". The two
// lead to different actions and must never share a class.
func TestAuthAndAuthzStayDistinct(t *testing.T) {
	auth := []FailureClass{
		FailureAuthMechanismUnsupported,
		FailureAuthMechanismNotOffered,
		FailureAuthCredentialsRejected,
	}
	authz := []FailureClass{
		FailureAuthzDenied,
		FailureAuthzScopeInsufficient,
	}

	for _, c := range auth {
		if !strings.HasPrefix(c.String(), "AUTH_") {
			t.Errorf("%s should carry the AUTH_ prefix", c)
		}
	}
	for _, c := range authz {
		if !strings.HasPrefix(c.String(), "AUTHZ_") {
			t.Errorf("%s should carry the AUTHZ_ prefix", c)
		}
		for _, a := range auth {
			if c == a {
				t.Errorf("%s must not be shared between auth and authz", c)
			}
		}
	}
}

// TestToolGapsAreNotTargetFailures guards the rule that a limitation of
// svcdoctor is classified separately from anything the target did. These
// classes exist so that a gap in the tool can never be reported as a defect in
// the service.
func TestToolGapsAreNotTargetFailures(t *testing.T) {
	toolGaps := []FailureClass{
		FailureExecLocalTimeout,
		FailureExecCancelled,
		FailureExecUnsupportedBySvcdoctor,
		FailureExecInsufficientPrivilege,
		FailureExecSkippedByPolicy,
		FailureExecSkippedPrerequisiteFailed,
		FailureExecDepthLimit,
	}

	for _, c := range toolGaps {
		if !strings.HasPrefix(c.String(), "EXEC_") {
			t.Errorf("%s should carry the EXEC_ prefix", c)
		}
	}

	// A local timeout is not the same fact as a remote one.
	if FailureExecLocalTimeout == FailureTCPConnectionTimeout {
		t.Error("a local execution timeout must be distinct from a remote connection timeout")
	}
	if FailureExecLocalTimeout == FailureDNSTimeout {
		t.Error("a local execution timeout must be distinct from a resolver timeout")
	}
}

// TestFailureClassNamesCoverAllClasses fails if a class is added without a name
// and catches duplicated strings.
func TestFailureClassNamesCoverAllClasses(t *testing.T) {
	// FailureNone plus 39 classes. Updating this number is meant to be a
	// deliberate act: the count exists so that adding a class without a name, or
	// adding one at all, is a decision somebody made on purpose. Phase 2.2 added
	// FailureTCPConnectionFailed, Phase 2.3 added FailureTLSPeerNotTLS, Phase 4.3
	// added FailureAuthzNotPermitted for a refusal that evaluates no credential
	// (ADR 0036 section 16), Phase 4.5b added FailureResourceNotFound — the
	// second class ADR 0036 section 16 authorized, held back until PostgreSQL
	// session establishment became its first reachable producer (ADR 0039
	// section 8) — and Phase 4.6a.5 added FailureAuthPeerVerificationFailed,
	// because a mutual mechanism's two directions had been normalized into one
	// class and one of them was inverted by it (ADR 0040 section 5.1).
	const wantCount = 40

	if len(failureClassNames) != wantCount {
		t.Fatalf("failureClassNames has %d entries, want %d", len(failureClassNames), wantCount)
	}

	seen := map[string]int{}
	for i, name := range failureClassNames {
		if name == "" {
			t.Errorf("FailureClass(%d) has no name", i)
			continue
		}
		if prev, dup := seen[name]; dup {
			t.Errorf("FailureClass(%d) and FailureClass(%d) share the name %q", prev, i, name)
		}
		seen[name] = i
	}
}

// TestFailureClassCarriesNoJudgement pins the boundary against diagnosis:
// FailureClass is factual normalization and must not grow severity, confidence,
// or a mapping to findings. This test documents the rule; the compiler enforces
// it by the absence of those methods.
func TestFailureClassCarriesNoJudgement(t *testing.T) {
	var f any = FailureTCPConnectionRefused

	if _, ok := f.(interface{ Severity() string }); ok {
		t.Error("FailureClass must not carry severity")
	}
	if _, ok := f.(interface{ Confidence() string }); ok {
		t.Error("FailureClass must not carry confidence")
	}
	if _, ok := f.(interface{ Finding() string }); ok {
		t.Error("FailureClass must not map to a finding")
	}
}
