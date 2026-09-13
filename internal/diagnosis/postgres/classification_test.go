package postgres

import (
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// Phase 13.1B: the classification the production rules actually attach.
//
// See internal/diagnosis/redis/classification_test.go for why a table-only guard
// set is insufficient.
//
// `recommendAdmissionUnmeasured` is absent: it is conditional on an *incomplete*
// multi-address admission shape, and it is the only self-collectable
// recommendation PostgreSQL has, which this file's shared body forbids. The
// test/security corpus guard covers it.
var postgresClassification = map[string]classificationExpectation{
	recommendStartupFailed:              {diagnosis.SafetyObserve, false},
	recommendNotPermitted:               {diagnosis.SafetyObserve, false},
	recommendSSLNegotiationFailed:       {diagnosis.SafetyVerify, false},
	recommendTLSDeclined:                {diagnosis.SafetyObserve, false},
	recommendAuthenticationFailed:       {diagnosis.SafetyObserve, false},
	recommendCredentialNotConfigured:    {diagnosis.SafetyObserve, false},
	recommendCredentialsRejected:        {diagnosis.SafetyVerify, false},
	recommendPeerVerificationFailed:     {diagnosis.SafetyVerify, false},
	recommendMechanismNotOffered:        {diagnosis.SafetyObserve, false},
	recommendDatabaseNotFound:           {diagnosis.SafetyVerify, false},
	recommendDatabaseConnectDenied:      {diagnosis.SafetyVerify, false},
	recommendSessionEstablishmentFailed: {diagnosis.SafetyObserve, false},
	recommendTLSUpgradeNotHonored:       {diagnosis.SafetyObserve, false},
	recommendTLSIdentityMismatch:        {diagnosis.SafetyCompare, false},
	recommendTLSChainNotTrusted:         {diagnosis.SafetyCompare, false},
	recommendTLSCertificateNotValidNow:  {diagnosis.SafetyCompare, false},
	recommendTLSHandshakeFailed:         {diagnosis.SafetyObserve, false},
	// Shipped classified in Phase 10.3 and reached by this matrix, so it is
	// asserted here too rather than left to the corpus guard alone.
	recommendConnectionLimitReached: {diagnosis.SafetyCompare, false},
	recommendAdmissionContrast:      {diagnosis.SafetyCompare, false},
}

// postgresDeferred are the three Phase 13.1C owns.
var postgresDeferred = map[string]string{
	recommendCredentialWithheld:     "REC-031",
	recommendMechanismUnsupported:   "REC-034",
	recommendUnsupportedBySvcdoctor: "REC-036",
}

func TestEveryProducedRecommendationCarriesItsFrozenClassification(t *testing.T) {
	assertFrozenClassification(t, everyPostgresFinding(t),
		postgresClassification, postgresDeferred, nil)
}

// everyPostgresFinding joins the two matrices this package already enumerates.
func everyPostgresFinding(t *testing.T) []domain.Finding {
	t.Helper()
	var out []domain.Finding
	for _, f := range shapes(t) {
		out = append(out, f)
	}
	out = append(out, everyTLSFinding(t)...)

	// Three shapes neither existing matrix builds. Added here rather than to
	// shapes(), whose callers depend on its exact membership.
	add := func(graph func(b *builder)) {
		b := newBuilder(t)
		graph(b)
		out = append(out, allFindings(b.freeze())...)
	}
	add(func(b *builder) {
		b.sslNode(domain.StateFail, domain.FailureProtocolMalformedResponse, nil)
	})
	add(func(b *builder) {
		b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "sasl")
		b.authNode(domain.StateSkipped, domain.FailureExecRequiredInputMissing, "", nil, "")
	})
	// Two failure classes share CodeMechanismUnavailable and differ only in their
	// action, so shapes() — which is keyed by code — keeps whichever it built
	// last. Both are driven here.
	add(func(b *builder) {
		b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "sasl")
		b.authNode(domain.StateFail, domain.FailureAuthMechanismNotOffered, "", nil, "")
	})
	return out
}

// classificationExpectation is what one action must carry.
//
// The maps above use unkeyed literals — `{safety, selfCollectable}` — because a
// keyed one triples the width of a fifty-row table and the two fields are never
// ambiguous about which is which.
type classificationExpectation struct {
	safety          diagnosis.SafetyClass
	selfCollectable bool
}

// assertFrozenClassification is the shared body. It lives in each rule package
// rather than in one place because a rule package may not import another's
// constants, and a generic helper elsewhere would need the whole expectation
// passed in anyway.
//
// `mayCarryNone` names the codes for which an empty recommendation list is the
// designed answer. Everything else with none is the silent-drop shape:
// diagnosis.Recommend returns nil on any error, so a misclassification deletes a
// recommendation rather than failing a build.
func assertFrozenClassification(
	t *testing.T,
	findings []domain.Finding,
	want map[string]classificationExpectation,
	deferred map[string]string,
	mayCarryNone map[domain.FindingCode]string,
) {
	t.Helper()
	if len(findings) == 0 {
		t.Fatal("the producer matrix yielded no finding; this guard would pass vacuously")
	}

	seen := map[string]bool{}
	for _, f := range findings {
		if len(f.Recommendations()) == 0 {
			if _, allowed := mayCarryNone[f.Code()]; !allowed {
				t.Errorf("%s carries no recommendation at all, and it is not one of the "+
					"codes for which that is the designed answer; diagnosis.Recommend "+
					"drops an invalid classification silently, so an absent "+
					"recommendation is the shape this guard exists to catch", f.Code())
			}
			continue
		}
		for _, r := range f.Recommendations() {
			action := r.Action()
			seen[action] = true

			if rec, isDeferred := deferred[action]; isDeferred {
				if r.Classified() {
					t.Errorf("%s carries %s classified %s/%s; Phase 13.1C owns that "+
						"sentence and 13.1B is read-only for it",
						f.Code(), rec, r.Kind(), r.Safety())
				}
				continue
			}

			expect, known := want[action]
			if !known {
				t.Errorf("%s produced the action %q, which is in neither the frozen "+
					"classification nor the deferred list.\n\n"+
					"ADR 0097 section 2.1: a production rule may not decline to classify "+
					"its own advice. Add it to one list, deliberately.", f.Code(), action)
				continue
			}
			if !r.Classified() {
				t.Errorf("%s produced %q unclassified; it was classified at the "+
					"Phase 13.1B baseline, so a call site stopped passing the "+
					"classification", f.Code(), action)
				continue
			}
			if r.Kind() != domain.RecommendationKindNextEvidence {
				t.Errorf("%s produced %q as %s, want NEXT_EVIDENCE", f.Code(), action, r.Kind())
			}
			if r.Safety() != expect.safety {
				t.Errorf("%s produced %q classified %s, want %s",
					f.Code(), action, r.Safety(), expect.safety)
			}
			if !r.Safety().ChangesNothing() {
				t.Errorf("%s produced %q classified %s, which changes the target",
					f.Code(), action, r.Safety())
			}
			if r.SelfCollectable() != expect.selfCollectable {
				t.Errorf("%s produced %q with selfCollectable=%v, want %v; "+
					"true means svcdoctor can take the observation under its current "+
					"authority, never that it could be programmed to",
					f.Code(), action, r.SelfCollectable(), expect.selfCollectable)
			}
			if r.Rationale() == "" {
				t.Errorf("%s produced %q with no rationale", f.Code(), action)
			}
		}
	}

	for action := range want {
		if !seen[action] {
			t.Errorf("the producer matrix never produced %q, so its row asserts nothing; "+
				"either the matrix lost a shape or the constant is unreachable", action)
		}
	}
	for action, rec := range deferred {
		if !seen[action] {
			t.Errorf("the producer matrix never produced %s (%q), so its exemption "+
				"asserts nothing", rec, action)
		}
	}
}
