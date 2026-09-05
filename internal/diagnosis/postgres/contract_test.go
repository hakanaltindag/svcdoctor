package postgres

import (
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// shapes drives every authorized producer shape through the rules, so that the
// contract tests below are exhaustive rather than a sample.
//
// Each entry is a graph the adapter can really emit, plus the code it must
// produce. Adding a code without adding a shape here fails
// TestEveryAuthorizedCodeIsExercised.
func shapes(t *testing.T) map[domain.FindingCode]domain.Finding {
	t.Helper()

	built := map[domain.FindingCode]domain.Finding{}
	add := func(graph func(b *builder)) {
		b := newBuilder(t)
		graph(b)
		for _, f := range allFindings(b.freeze()) {
			built[f.Code()] = f
		}
	}

	add(func(b *builder) {
		b.sslNode(domain.StateFail, domain.FailureProtocolUnsupportedCapability, boolPtr(false))
	})
	add(func(b *builder) {
		b.startupNode(domain.StateFail, domain.FailureProtocolUnexpectedResponse, "08P01", boolPtr(false), "")
	})
	add(func(b *builder) {
		b.startupNode(domain.StateFail, domain.FailureAuthzNotPermitted, "28000", boolPtr(true), "")
	})
	add(func(b *builder) {
		b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "sasl")
		b.authNode(domain.StateFail, domain.FailureAuthCredentialsRejected, "28P01", boolPtr(true), "")
	})
	add(func(b *builder) {
		b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "sasl")
		b.authNode(domain.StateFail, domain.FailureAuthPeerVerificationFailed, "", nil, "")
	})
	add(func(b *builder) {
		b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "sasl")
		b.authNode(domain.StateFail, domain.FailureAuthMechanismNotOffered, "", nil, "")
	})
	add(func(b *builder) {
		b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "md5")
		b.authNode(domain.StateUnknown, domain.FailureAuthMechanismUnsupported, "", nil, "")
	})
	add(func(b *builder) {
		b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "sasl")
		b.authNode(domain.StateUnknown, domain.FailureExecUnsupportedBySvcdoctor, "", nil, "")
	})
	add(func(b *builder) {
		b.sslNode(domain.StateSkipped, domain.FailureExecSkippedByPolicy, nil)
		b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "sasl")
		b.authNode(domain.StateSkipped, domain.FailureExecSkippedByPolicy, "", nil, idSSL)
	})
	add(func(b *builder) {
		b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "sasl")
		b.authNode(domain.StateFail, domain.FailureProtocolUnexpectedResponse, "08P01", boolPtr(false), "")
	})
	add(func(b *builder) {
		b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "sasl")
		b.authNode(domain.StatePass, domain.FailureNone, "", nil, "")
		b.sessionNode(domain.StateFail, domain.FailureResourceNotFound, "3D000", boolPtr(true), idAuth)
	})
	add(func(b *builder) {
		b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "sasl")
		b.authNode(domain.StatePass, domain.FailureNone, "", nil, "")
		b.sessionNode(domain.StateFail, domain.FailureAuthzDenied, "42501", boolPtr(true), idAuth)
	})
	add(func(b *builder) {
		b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "sasl")
		b.authNode(domain.StatePass, domain.FailureNone, "", nil, "")
		// 53300 reaches RESOURCE_LIMIT_REACHED from Phase 8.1 (ADR 0069), and
		// Phase 10.3 escalates that class to a claim of its own (ADR 0085 §3).
		b.sessionNode(domain.StateFail, domain.FailureResourceLimitReached, "53300", boolPtr(true), idAuth)
	})
	add(func(b *builder) {
		// The session floor now needs a class the three escalations do not
		// claim. 08P01 is pgBouncer's default for everything and is exactly
		// that: a refusal svcdoctor cannot normalize.
		b.startupNode(domain.StatePass, domain.FailureNone, "", nil, "sasl")
		b.authNode(domain.StatePass, domain.FailureNone, "", nil, "")
		b.sessionNode(domain.StateFail, domain.FailureProtocolUnexpectedResponse, "08P01", boolPtr(false), idAuth)
	})
	add(func(b *builder) {
		// The admission scope, which needs two addresses and is inert on one.
		twoAddressAdmission(b, admissionContrast)
	})

	return built
}

func allCodes() []domain.FindingCode {
	return []domain.FindingCode{
		CodeTLSDeclined, CodeStartupFailed, CodeConnectionNotPermitted,
		CodeCredentialsRejected, CodePeerVerificationFailed, CodeMechanismUnavailable,
		CodeUnsupportedBySvcdoctor, CodeCredentialWithheld, CodeAuthenticationFailed,
		CodeDatabaseNotFound, CodeDatabaseConnectDenied, CodeSessionEstablishmentFailed,
		CodeConnectionLimitReached, CodeAdmissionScope,
	}
}

// TestEveryAuthorizedCodeIsExercised keeps the contract tests exhaustive.
func TestEveryAuthorizedCodeIsExercised(t *testing.T) {
	built := shapes(t)
	for _, code := range allCodes() {
		if _, ok := built[code]; !ok {
			t.Errorf("%s is never produced by any shape in this file", code)
		}
	}
}

// TestEveryAuthorizedShapeBuildsAValidFinding proves that build's error branch
// is unreachable rather than merely believed to be.
//
// A rule must not respond to a rejected finding by returning fewer: silently
// omitting a conclusion is the failure mode the project's claim discipline
// exists to prevent. This is the test that makes the omission provable.
func TestEveryAuthorizedShapeBuildsAValidFinding(t *testing.T) {
	for code, f := range shapes(t) {
		if f.IsZero() {
			t.Errorf("%s built a zero finding", code)
		}
		if f.EvidenceRefCount() == 0 {
			t.Errorf("%s references no evidence", code)
		}
		if len(f.Recommendations()) == 0 {
			t.Errorf("%s carries no recommendation", code)
		}
	}
}

// TestProseCarriesNoIdentity is the redaction bar, applied to the text.
//
// A finding whose prose must be rewritten to be shareable is a finding that will
// leak the day someone edits it. Hostnames, addresses, roles and database names
// live on the subject and on the evidence, where redaction transforms them
// structurally; none may be interpolated into a sentence.
func TestProseCarriesNoIdentity(t *testing.T) {
	// Everything the fixtures put in the graph as identity or as an address.
	forbidden := []string{"db.internal", "10.0.0.5", "5432", "tenantrole", "tenantcatalog"}

	for code, f := range shapes(t) {
		text := strings.ToLower(f.Summary() + "\n" + f.Detail())
		for _, r := range f.Recommendations() {
			text += "\n" + strings.ToLower(r.Action())
		}
		for _, needle := range forbidden {
			if strings.Contains(text, strings.ToLower(needle)) {
				t.Errorf("%s carries %q in prose; identity belongs on the subject and the evidence",
					code, needle)
			}
		}
	}
}

// TestProseNeverClaimsMoreThanTheEvidence is the wording contract.
//
// Each entry is a phrase the corresponding claim cannot support. They are
// checked against the whole of a finding's text, recommendation included,
// because a recommendation that names a cause is a cause claim wherever it sits.
func TestProseNeverClaimsMoreThanTheEvidence(t *testing.T) {
	banned := map[domain.FindingCode][]string{
		// The endpoint's answer is one setting on one peer, not a statement
		// about TLS support in general or about a certificate.
		CodeTLSDeclined: {"does not support tls", "tls is disabled", "certificate"},

		// A floor names the boundary. "Rejected" attributes agency its own
		// trigger disproves: it fires on peer closes and malformed frames too.
		CodeStartupFailed: {"rejected", "refused", "database does not", "database is not",
			"missing database", "role does not", "password"},

		// A pre-credential refusal says nothing about the credential, and
		// nothing about the role in general.
		CodeConnectionNotPermitted: {"password", "credential is", "globally", "authenticated successfully"},

		// The refusal is byte-identical for four causes; naming one is guessing.
		CodeCredentialsRejected: {"password is wrong", "password is incorrect", "invalid credential",
			"role does not exist", "account is disabled", "backend is healthy"},

		// The endpoint accepted the material and then failed to prove itself.
		// Saying it rejected anything inverts that; naming interception invents
		// a cause the evidence cannot separate from two others.
		CodePeerVerificationFailed: {"rejected", "man-in-the-middle", "interception", "attacker",
			"malicious", "impostor", "password is wrong", "signature was"},

		// No credential was presented, so nothing is known about it.
		// "No credential was presented" is the sentence that must survive; what
		// must not is any claim about the credential's validity.
		CodeMechanismUnavailable: {"credential is", "credential was rejected",
			"credential was accepted", "password", "misconfigured"},
		CodeUnsupportedBySvcdoctor: {"endpoint failed", "endpoint rejected", "defect",
			"misconfigured", "was rejected"},

		// svcdoctor withheld; the endpoint refused nothing.
		CodeCredentialWithheld: {"was rejected", "endpoint refused", "authentication failed", "invalid"},

		// The floor where a pooler's generic code lands.
		CodeAuthenticationFailed: {"credential was rejected", "password", "role does not",
			"pgbouncer", "pooler", "proxy"},

		// Three conditions share the code; the prose must be true of all three,
		// and the recommendation must not tell anyone to create anything.
		CodeDatabaseNotFound: {"does not exist", "never existed", "was dropped", "create database",
			"create the database", "catalog is healthy", "filesystem"},

		// Only the CONNECT check is reachable.
		CodeDatabaseConnectDenied: {"table", "schema", "write access", "superuser",
			"role membership", "password", "grant "},

		// The message says "out of connections"; the evidence contract does not.
		CodeSessionEstablishmentFailed: {"out of connections", "connection limit", "backend is down",
			"pool exhausted", "database is unavailable", "shutting down", "recovery"},
	}

	built := shapes(t)
	for code, phrases := range banned {
		f, ok := built[code]
		if !ok {
			t.Fatalf("%s was not built; the shape table is incomplete", code)
		}
		text := strings.ToLower(f.Summary() + "\n" + f.Detail())
		for _, r := range f.Recommendations() {
			text += "\n" + strings.ToLower(r.Action())
		}
		for _, phrase := range phrases {
			if strings.Contains(text, phrase) {
				t.Errorf("%s claims %q, which its evidence does not support", code, phrase)
			}
		}
	}
}

// TestNoRecommendationIsExecutable pins that svcdoctor suggests where to look
// and never what to run.
func TestNoRecommendationIsExecutable(t *testing.T) {
	sql := []string{"create database", "grant ", "alter role", "select ", "drop ", "psql ",
		"create role", "revoke "}

	for code, f := range shapes(t) {
		for _, r := range f.Recommendations() {
			action := strings.ToLower(r.Action())
			for _, fragment := range sql {
				if strings.Contains(action, fragment) {
					t.Errorf("%s recommends running %q", code, fragment)
				}
			}
		}
	}
}

// TestTheFloorsUseTheirExactSummaries pins the three sentences ADR 0040 fixes
// word for word, because they are the ones most likely to be "improved" into a
// stronger claim.
func TestTheFloorsUseTheirExactSummaries(t *testing.T) {
	want := map[domain.FindingCode]string{
		CodeStartupFailed: "The PostgreSQL startup exchange did not complete at this endpoint, " +
			"and no authentication was requested",
		CodeAuthenticationFailed: "The PostgreSQL authentication exchange did not complete successfully",
		CodeSessionEstablishmentFailed: "The PostgreSQL session did not reach ReadyForQuery " +
			"after authentication completed",
	}

	built := shapes(t)
	for code, sentence := range want {
		if got := built[code].Summary(); got != sentence {
			t.Errorf("%s summary =\n  %q\nwant\n  %q", code, got, sentence)
		}
	}
}

// TestTheAttributionSentenceIsClassGated is the correction ADR 0040 section 8.1
// makes normative.
//
// "svcdoctor could not attribute this outcome to a specific cause" is true of a
// generic response and false of a class that already names a stronger fact.
// Understating the evidence is a different error from overstating it, and it is
// still an error.
func TestTheAttributionSentenceIsClassGated(t *testing.T) {
	tests := []struct {
		name  string
		class domain.FailureClass
		want  bool
	}{
		{"a generic response leaves the cause unattributed", domain.FailureProtocolUnexpectedResponse, true},
		{"an unsupported version already names the fact", domain.FailureProtocolUnsupportedVersion, false},
		{"a malformed response already names the fact", domain.FailureProtocolMalformedResponse, false},
		{"a peer close already names the fact", domain.FailureProtocolPeerClosed, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := newBuilder(t)
			b.startupNode(domain.StateFail, tt.class, "", nil, "")
			f := only(t, allFindings(b.freeze()))

			got := strings.Contains(f.Detail(), sentenceUnattributable)
			if got != tt.want {
				t.Errorf("attribution sentence present = %v, want %v\ndetail: %q",
					got, tt.want, f.Detail())
			}
		})
	}
}

// TestTheSQLStateIsRenderedVerbatimAndNeverTranslated pins the one place a
// PostgreSQL code reaches prose.
//
// Five characters, exactly as received, with no English beside them. Translating
// one here would be building the shared dictionary ADR 0039 section 7.1 forbids,
// one layer up from where it forbade it.
func TestTheSQLStateIsRenderedVerbatimAndNeverTranslated(t *testing.T) {
	translations := []string{"protocol violation", "invalid password", "undefined database",
		"insufficient privilege", "too many connections", "cannot connect now"}

	for _, code := range []string{"08P01", "57P03", "53300"} {
		b := newBuilder(t)
		b.startupNode(domain.StateFail, domain.FailureProtocolUnexpectedResponse, code, boolPtr(true), "")
		f := only(t, allFindings(b.freeze()))

		if !strings.Contains(f.Detail(), code) {
			t.Errorf("SQLSTATE %s is not rendered at all", code)
		}
		lower := strings.ToLower(f.Detail())
		for _, english := range translations {
			if strings.Contains(lower, english) {
				t.Errorf("SQLSTATE %s was translated into %q", code, english)
			}
		}
	}
}

// TestErrorIsNativeChangesOnlyTheDetail is ADR 0040 section 18.1, made
// executable.
//
// The attribute is the most tempting thing in the graph. It may be stated as the
// observation it is, and it may not steer a claim: the code, kind, severity and
// confidence must be identical for both values of it on an otherwise identical
// node, and no peer implementation may be named.
func TestErrorIsNativeChangesOnlyTheDetail(t *testing.T) {
	build := func(native bool) domain.Finding {
		b := newBuilder(t)
		b.startupNode(domain.StateFail, domain.FailureProtocolUnexpectedResponse, "08P01", boolPtr(native), "")
		return only(t, allFindings(b.freeze()))
	}

	yes, no := build(true), build(false)

	if yes.Code() != no.Code() {
		t.Errorf("code differs: %s vs %s", yes.Code(), no.Code())
	}
	if yes.Kind() != no.Kind() {
		t.Errorf("kind differs: %s vs %s", yes.Kind(), no.Kind())
	}
	if yes.Severity() != no.Severity() {
		t.Errorf("severity differs: %s vs %s", yes.Severity(), no.Severity())
	}
	if yes.Confidence() != no.Confidence() {
		t.Errorf("confidence differs: %s vs %s", yes.Confidence(), no.Confidence())
	}
	if yes.VantageDependent() != no.VantageDependent() {
		t.Error("vantageDependent differs")
	}

	// The observation appears only where it is true.
	if strings.Contains(yes.Detail(), sentenceNotNative) {
		t.Error("a native response claimed the field was absent")
	}
	if !strings.Contains(no.Detail(), sentenceNotNative) {
		t.Error("a non-native response did not record the observation")
	}

	// And it never becomes an identity.
	for _, product := range []string{"pgbouncer", "haproxy", "envoy", "pooler", "proxy"} {
		if strings.Contains(strings.ToLower(no.Detail()), product) {
			t.Errorf("the detail names %q from a missing field", product)
		}
	}
}
