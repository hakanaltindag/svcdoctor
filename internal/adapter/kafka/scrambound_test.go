package kafka

import (
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/adapter/kafka/wire"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// TestABoundRefusalClassifiesAsACapabilityGap pins ADR 0061 §19 at the point
// where the claim becomes evidence.
//
// A SCRAM value above svcdoctor's defensive ceiling is legal protocol svcdoctor
// declined to read. Until ADR 0061 it arrived here as ErrMalformedResponse and
// was classified PROTOCOL_MALFORMED_RESPONSE — *the broker sent something that
// could not be decoded* — which a real Redpanda broker disproved by sending a
// perfectly legal 130-byte salt.
//
// UNKNOWN rather than FAIL, because docs/ARCHITECTURE.md requires that an
// unsupported capability is never reported as a failure of the thing being
// inspected.
func TestABoundRefusalClassifiesAsACapabilityGap(t *testing.T) {
	o := authObservation{err: wire.ErrSCRAMParametersUnsupported}

	state, class := o.classify()
	if state != domain.StateUnknown {
		t.Errorf("state = %v, want UNKNOWN: svcdoctor's own ceiling is not a broker defect", state)
	}
	if class != domain.FailureExecUnsupportedBySvcdoctor {
		t.Errorf("failure class = %v, want EXEC_UNSUPPORTED_BY_SVCDOCTOR", class)
	}
	if class == domain.FailureProtocolMalformedResponse {
		t.Error("a legal broker message is still reported as malformed")
	}
	if class == domain.FailureAuthCredentialsRejected {
		t.Error("a refusal svcdoctor made is reported as the broker rejecting the credential")
	}
}

// TestAMalformedResponseIsStillTheBrokersDefect is the other direction: the fix
// must not turn every parser refusal into a capability gap.
func TestAMalformedResponseIsStillTheBrokersDefect(t *testing.T) {
	o := authObservation{err: wire.ErrMalformedResponse}

	state, class := o.classify()
	if state != domain.StateFail {
		t.Errorf("state = %v, want FAIL", state)
	}
	if class != domain.FailureProtocolMalformedResponse {
		t.Errorf("failure class = %v, want PROTOCOL_MALFORMED_RESPONSE: a broker that "+
			"announced a grammar it did not follow really did send a defective response", class)
	}
}
