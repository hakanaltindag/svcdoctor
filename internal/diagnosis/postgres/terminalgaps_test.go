package postgres

import (
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicepostgres "github.com/hakanaltindag/svcdoctor/internal/service/postgres"
)

// The two final PostgreSQL BASIC gaps: ADR 0046's missing authentication input
// and ADR 0045's negotiation floor.
//
// The rule-level semantics are here. The half that cannot be tested from a graph
// — that the *producer* records the missing-input node only in the right
// circumstances, and that a cancelled run produces a different graph — lives in
// internal/adapter/postgres and internal/app, because a hand-built graph can
// assert any shape and would prove nothing about which one a run makes.

// --- ADR 0046: no credential ---------------------------------------------------

// noCredential builds the shape the producer records: a startup that passed and
// asked for authentication, and an authentication step that did not run.
func noCredential(t *testing.T, authMethod string) domain.Graph {
	t.Helper()

	b := newBuilder(t)
	b.sslNode(domain.StatePass, domain.FailureNone, boolPtr(true))
	b.startupNode(domain.StatePass, domain.FailureNone, "", nil, authMethod)
	b.authNode(domain.StateSkipped, domain.FailureExecRequiredInputMissing, "", nil, "")
	return b.freeze()
}

func TestAMissingCredentialIsDiagnosed(t *testing.T) {
	finding := only(t, allFindings(noCredential(t, "scram-sha-256")))

	if got := finding.Code(); got != CodeCredentialNotConfigured {
		t.Fatalf("code = %s, want %s", got, CodeCredentialNotConfigured)
	}
	if got := finding.Kind(); got != domain.FindingKindConfirmed {
		t.Errorf("kind = %s, want CONFIRMED", got)
	}
	if got := finding.Severity(); got != domain.SeverityWarn {
		t.Errorf("severity = %s, want WARN: the endpoint is not proven unhealthy", got)
	}
	if got := finding.Confidence(); got != domain.ConfidenceHigh {
		t.Errorf("confidence = %s, want HIGH", got)
	}
	if !finding.VantageDependent() {
		t.Error("vantageDependent = false; the claim names what this endpoint required, " +
			"and pg_hba selects that by source")
	}
	if got := finding.Layer(); got != domain.LayerAuth {
		t.Errorf("layer = %s, want L5", got)
	}
	if got := finding.Subject().Ref(); got != addr {
		t.Errorf("subject = %q, want the concrete endpoint %q", got, addr)
	}

	// Both halves of the claim are cited: the authentication node proves the step
	// did not run, the startup node proves the endpoint asked.
	refs := map[domain.EvidenceID]bool{}
	for _, ref := range finding.EvidenceRefs() {
		refs[ref] = true
	}
	if !refs[idAuth] || !refs[idStartup] {
		t.Errorf("refs = %v, want the authentication and startup nodes",
			finding.EvidenceRefs())
	}
}

// TestAMissingCredentialIsNotConfusedWithAnythingElse pins the whole
// authentication step's disjointness at once.
//
// Every row is a different reason this step did not produce a session, and each
// has its own claim and its own next action. Collapsing any two would send a
// reader to the wrong place.
func TestAMissingCredentialIsNotConfusedWithAnythingElse(t *testing.T) {
	cases := []struct {
		name  string
		state domain.State
		class domain.FailureClass
		want  domain.FindingCode
	}{
		{"no credential existed", domain.StateSkipped,
			domain.FailureExecRequiredInputMissing, CodeCredentialNotConfigured},
		{"a credential existed and policy refused it", domain.StateSkipped,
			domain.FailureExecSkippedByPolicy, CodeCredentialWithheld},
		{"the peer refused what was presented", domain.StateFail,
			domain.FailureAuthCredentialsRejected, CodeCredentialsRejected},
		{"the peer could not prove itself", domain.StateFail,
			domain.FailureAuthPeerVerificationFailed, CodePeerVerificationFailed},
		{"the endpoint offers nothing svcdoctor performs", domain.StateFail,
			domain.FailureAuthMechanismNotOffered, CodeMechanismUnavailable},
		{"svcdoctor cannot perform what was asked", domain.StateUnknown,
			domain.FailureAuthMechanismUnsupported, CodeMechanismUnavailable},
		{"a prerequisite failed earlier", domain.StateSkipped,
			domain.FailureExecSkippedPrerequisiteFailed, ""},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := newBuilder(t)
			b.sslNode(domain.StatePass, domain.FailureNone, boolPtr(true))
			b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "scram-sha-256")
			b.authNode(c.state, c.class, "", nil, "")
			graph := b.freeze()

			findings := Authentication(rctx(graph))
			if c.want == "" {
				if len(findings) != 0 {
					t.Fatalf("got %v, want no finding", codesOf(findings))
				}
				return
			}
			if got := only(t, findings).Code(); got != c.want {
				t.Errorf("code = %s, want %s", got, c.want)
			}
		})
	}
}

// TestTrustProducesNoMissingCredentialFinding pins the case where the absence of
// a credential is irrelevant.
//
// A `trust` endpoint asks for nothing, so a run without a credential is not
// limited by anything. The producer records no authentication node at all here,
// and this asserts the rule set says nothing even if one somehow existed.
func TestTrustProducesNoMissingCredentialFinding(t *testing.T) {
	b := newBuilder(t)
	b.sslNode(domain.StatePass, domain.FailureNone, boolPtr(true))
	b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "ok")
	b.sessionNode(domain.StatePass, domain.FailureNone, "", nil, idStartup)

	if got := allFindings(b.freeze()); len(got) != 0 {
		t.Errorf("a trust path produced %v", codesOf(got))
	}
}

// TestAnAuthenticationStepThatNeverRanProducesNothing is the shape a cancelled
// run leaves, and the reason ADR 0046 rejected absence inference.
//
// Startup passed and asked for authentication; nothing followed. Before ADR 0046
// this was indistinguishable from a run with no credential, and it still is —
// from the graph alone. That is precisely why the rule requires an explicit node
// and infers nothing from its absence.
func TestAnAuthenticationStepThatNeverRanProducesNothing(t *testing.T) {
	b := newBuilder(t)
	b.sslNode(domain.StatePass, domain.FailureNone, boolPtr(true))
	b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "scram-sha-256")

	if got := allFindings(b.freeze()); len(got) != 0 {
		t.Errorf("absence produced %v; the rule must infer nothing from a missing node",
			codesOf(got))
	}
}

// --- ADR 0045: the negotiation floor -------------------------------------------

func TestTheNegotiationFloorMapping(t *testing.T) {
	cases := []struct {
		name  string
		class domain.FailureClass
		want  domain.FindingCode
	}{
		{"an answer the protocol does not define", domain.FailureProtocolUnexpectedResponse,
			CodeSSLNegotiationFailed},
		{"the peer closed", domain.FailureProtocolPeerClosed, CodeSSLNegotiationFailed},
		{"the reply could not be decoded", domain.FailureProtocolMalformedResponse,
			CodeSSLNegotiationFailed},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := newBuilder(t)
			b.sslNode(domain.StateFail, c.class, nil)
			graph := b.freeze()

			finding := only(t, allFindings(graph))
			if got := finding.Code(); got != c.want {
				t.Fatalf("code = %s, want %s", got, c.want)
			}
			if got := finding.Severity(); got != domain.SeverityError {
				t.Errorf("severity = %s, want ERROR", got)
			}
			if !finding.VantageDependent() {
				t.Error("vantageDependent = false; a floor attributes nothing and cannot " +
					"exclude a cause keyed on where the connection came from")
			}
			if got := finding.Subject().Ref(); got != addr {
				t.Errorf("subject = %q, want the concrete endpoint", got)
			}
			// The node alone. Its blocked handshake child is never a cause.
			if refs := finding.EvidenceRefs(); len(refs) != 1 || refs[0] != idSSL {
				t.Errorf("refs = %v, want the negotiation node alone", refs)
			}
		})
	}
}

// TestTheNegotiationFloorIsDisjointFromTheDeclinedFinding proves on class alone
// what ADR 0045 argues.
func TestTheNegotiationFloorIsDisjointFromTheDeclinedFinding(t *testing.T) {
	b := newBuilder(t)
	b.sslNode(domain.StateFail, domain.FailureProtocolUnsupportedCapability, boolPtr(false))

	finding := only(t, allFindings(b.freeze()))
	if got := finding.Code(); got != CodeTLSDeclined {
		t.Errorf("code = %s, want %s; the declined class is not in the floor's set",
			got, CodeTLSDeclined)
	}
	// And the two carry opposite vantage values, deliberately.
	if finding.VantageDependent() {
		t.Error("the declined finding is vantage-dependent; it names a server-wide setting")
	}
}

// TestTheNegotiationFloorDoesNotFireOnAPassingNegotiation pins the separation
// from ADR 0044's in-band TLS findings.
func TestTheNegotiationFloorDoesNotFireOnAPassingNegotiation(t *testing.T) {
	b := newBuilder(t)
	b.sslNode(domain.StatePass, domain.FailureNone, boolPtr(true))
	b.tlsNode(domain.StateFail, domain.FailureTLSUnknownAuthority)

	finding := only(t, allFindings(b.freeze()))
	if got := finding.Code(); got != CodeTLSChainNotTrusted {
		t.Errorf("code = %s, want the in-band TLS finding; the negotiation passed", got)
	}
}

// TestTheNegotiationFloorRequiresAFailedNegotiation isolates the state check.
//
// Every non-FAIL state a producer emits carries a class the floor's map rejects
// anyway, so without these shapes a rule that dropped the state gate would still
// pass — the two conditions would be testing each other. These are graphs no
// producer makes, built to separate them.
func TestTheNegotiationFloorRequiresAFailedNegotiation(t *testing.T) {
	// PASS is absent: the domain refuses a passing node carrying a failure class,
	// which is a stronger guarantee than a test.
	for _, state := range []domain.State{
		domain.StateUnknown, domain.StateSkipped, domain.StateDegraded,
	} {
		t.Run(state.String(), func(t *testing.T) {
			b := newBuilder(t)
			b.sslNode(state, domain.FailureProtocolUnexpectedResponse, nil)

			if got := SSLRequest(rctx(b.freeze())); len(got) != 0 {
				t.Errorf("got %v, want none: only a failed negotiation is a failure",
					codesOf(got))
			}
		})
	}
}

// TestTheNegotiationFloorMappingIsClosed pins that an unrecognized class
// produces nothing.
func TestTheNegotiationFloorMappingIsClosed(t *testing.T) {
	authorized := map[domain.FailureClass]bool{
		domain.FailureProtocolUnexpectedResponse: true,
		domain.FailureProtocolPeerClosed:         true,
		domain.FailureProtocolMalformedResponse:  true,
	}

	if len(negotiationFloorClasses) != len(authorized) {
		t.Fatalf("the floor covers %d classes, want %d",
			len(negotiationFloorClasses), len(authorized))
	}
	for class := range negotiationFloorClasses {
		if !authorized[class] {
			t.Errorf("%s is in the floor and ADR 0045 does not authorize it", class)
		}
	}
	if negotiationFloorClasses[domain.FailureProtocolUnsupportedCapability] {
		t.Error("the declined class is in the floor; the two rules would overlap")
	}
}

// --- claim discipline for both new findings ------------------------------------

func bothNewFindings(t *testing.T) []domain.Finding {
	t.Helper()

	var out []domain.Finding
	out = append(out, allFindings(noCredential(t, "scram-sha-256"))...)

	b := newBuilder(t)
	b.sslNode(domain.StateFail, domain.FailureProtocolUnexpectedResponse, nil)
	out = append(out, allFindings(b.freeze())...)

	if len(out) != 2 {
		t.Fatalf("got %d findings, want one of each", len(out))
	}
	return out
}

// TestNeitherNewFindingClaimsMoreThanTheEvidence is the prose guard.
func TestNeitherNewFindingClaimsMoreThanTheEvidence(t *testing.T) {
	banned := map[string]string{
		"wrong":           "no credential was presented, so none can be wrong",
		"rejected":        "nothing was presented and nothing was refused",
		"invalid":         "svcdoctor evaluated nothing",
		"denied":          "no authorization decision was made",
		"is not postgres": "the endpoint's implementation was never established",
		"wrong port":      "likely, unobserved, and not a claim",
		"firewall":        "svcdoctor observed no filtering",
		"proxy":           "svcdoctor observed no intermediary",
		"load balancer":   "svcdoctor observed no topology",
		"is down":         "nothing here establishes an outage",
		"misconfigured":   "svcdoctor observed values, never how they were produced",
		"certificate":     "no certificate was reached in either case",
	}

	for _, finding := range bothNewFindings(t) {
		text := strings.ToLower(finding.Summary() + " " + finding.Detail())
		for _, r := range finding.Recommendations() {
			text += " " + strings.ToLower(r.Action())
		}
		for phrase, why := range banned {
			if strings.Contains(text, phrase) {
				t.Errorf("%s says %q: %s", finding.Code(), phrase, why)
			}
		}
	}
}

// TestTheNewProseScanWouldCatchABannedPhrase is the control.
func TestTheNewProseScanWouldCatchABannedPhrase(t *testing.T) {
	sample := strings.ToLower(
		"The wrong credential was rejected as invalid and denied, the peer is not postgres " +
			"on the wrong port, a firewall or proxy or load balancer is misconfigured, " +
			"the service is down and the certificate expired")
	for _, phrase := range []string{
		"wrong", "rejected", "invalid", "denied", "is not postgres", "wrong port",
		"firewall", "proxy", "load balancer", "is down", "misconfigured", "certificate",
	} {
		if !strings.Contains(sample, phrase) {
			t.Errorf("the scan cannot see %q; the guard above is vacuous", phrase)
		}
	}
}

// TestNeitherNewFindingCarriesIdentityInProse keeps a shared report safe.
func TestNeitherNewFindingCarriesIdentityInProse(t *testing.T) {
	for _, finding := range bothNewFindings(t) {
		text := finding.Summary() + " " + finding.Detail()
		for _, r := range finding.Recommendations() {
			text += " " + r.Action()
		}
		for _, identity := range []string{"10.0.0.5", "db.internal", "tenantrole", "5432"} {
			if strings.Contains(text, identity) {
				t.Errorf("%s puts %q in prose", finding.Code(), identity)
			}
		}
	}
}

// TestTheMissingInputClassIsServiceNeutral pins ADR 0046's vocabulary contract at
// the point of use.
//
// The class lives in internal/domain and must name no service, no protocol and
// no kind of input. A PostgreSQL rule reads it; the class itself knows nothing
// about PostgreSQL.
func TestTheMissingInputClassIsServiceNeutral(t *testing.T) {
	name := domain.FailureExecRequiredInputMissing.String()
	if name != "EXEC_REQUIRED_INPUT_MISSING" {
		t.Fatalf("name = %q, want EXEC_REQUIRED_INPUT_MISSING", name)
	}
	for _, word := range []string{
		"POSTGRES", "PASSWORD", "CREDENTIAL", "SCRAM", "AUTH", "KAFKA", "TLS",
	} {
		if strings.Contains(name, word) {
			t.Errorf("the class name contains %q; it must be service-neutral", word)
		}
	}
	// And it is not one of the three it sits beside.
	for _, other := range []domain.FailureClass{
		domain.FailureExecSkippedByPolicy,
		domain.FailureExecUnsupportedBySvcdoctor,
		domain.FailureExecInsufficientPrivilege,
		domain.FailureExecCancelled,
		domain.FailureExecLocalTimeout,
	} {
		if domain.FailureExecRequiredInputMissing == other {
			t.Errorf("the class collides with %s", other)
		}
	}
}

// TestTheStepVocabularyIsUnchanged guards that neither gap needed a new step.
func TestTheStepVocabularyIsUnchanged(t *testing.T) {
	for _, step := range []domain.Step{
		servicepostgres.StepSSLRequest, servicepostgres.StepStartup,
		servicepostgres.StepAuthentication, servicepostgres.StepSession,
	} {
		if !step.Valid() {
			t.Errorf("%s is not a valid step", step)
		}
	}
}
