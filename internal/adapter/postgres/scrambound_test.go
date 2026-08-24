package postgres

import (
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/adapter/postgres/wire"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// TestABoundRefusalClassifiesAsACapabilityGap pins ADR 0061 §19 for PostgreSQL.
//
// The shared SCRAM core serves both services, so the same legal-but-over-policy
// message can arrive here. It used to be translated to ErrFrameTooLarge and
// classified PROTOCOL_MALFORMED_RESPONSE, which asserts the peer sent something
// undecodable — untrue of a value that was structurally legal and refused by
// svcdoctor's own ceiling.
func TestABoundRefusalClassifiesAsACapabilityGap(t *testing.T) {
	o := authObservation{err: wire.ErrSCRAMParametersUnsupported}

	state, class := o.classify()
	if state != domain.StateUnknown {
		t.Errorf("state = %v, want UNKNOWN: svcdoctor's own ceiling is not a target defect", state)
	}
	if class != domain.FailureExecUnsupportedBySvcdoctor {
		t.Errorf("failure class = %v, want EXEC_UNSUPPORTED_BY_SVCDOCTOR", class)
	}
	if class == domain.FailureProtocolMalformedResponse {
		t.Error("a legal peer message is still reported as malformed")
	}
	if class == domain.FailureAuthCredentialsRejected {
		t.Error("a refusal svcdoctor made is reported as the peer rejecting the credential")
	}
}

// TestFrameTooLargeIsStillAFramingFact keeps the sentinel this one was split
// away from doing its own job.
//
// ErrFrameTooLarge is about a PostgreSQL message header announcing a body larger
// than svcdoctor reads. That is a framing observation and keeps its existing
// classification; only the SCRAM-core translation moved.
func TestFrameTooLargeIsStillAFramingFact(t *testing.T) {
	if got := wireFailureClass(wire.ErrFrameTooLarge); got != domain.FailureProtocolMalformedResponse {
		t.Errorf("wireFailureClass(ErrFrameTooLarge) = %v, want PROTOCOL_MALFORMED_RESPONSE; "+
			"ADR 0061 moved the SCRAM translation, not this sentinel's own meaning", got)
	}
}
