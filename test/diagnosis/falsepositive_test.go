package diagnosis_test

import (
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	diagnosispostgres "github.com/hakanaltindag/svcdoctor/internal/diagnosis/postgres"
	diagnosistransport "github.com/hakanaltindag/svcdoctor/internal/diagnosis/transport"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicepostgres "github.com/hakanaltindag/svcdoctor/internal/service/postgres"
	"github.com/hakanaltindag/svcdoctor/internal/vocabulary"
)

// The Phase 10.1B false-positive corpus, FP01 through FP05.
//
// These are release-blocking. Every other test in this repository asks whether
// svcdoctor said the right thing; these ask whether it refused to say the wrong
// one, and that is the property that decays silently. A diagnostic engine that
// passes its unit tests and invents causes in production is a net loss — it
// costs the trust that makes the measured half of the tool useful.
//
// # Why the forbidden list is checked against everything
//
// Each scenario renders the canonical JSON, the shareable JSON and the terminal
// output, and scans all three. A claim that appears in one and not the others is
// still a claim svcdoctor made.

// forbiddenClaim is one thing a scenario must never say, and why.
type forbiddenClaim struct {
	phrase string
	why    string
}

// assertRefuses checks a forbidden list against everything svcdoctor *claims*.
//
// # Why this scans prose and not the whole document
//
// The first version scanned the raw JSON and the raw terminal output, and the
// corpus refuted it immediately: a fixture forbidding "tcp" failed because the
// evidence records a `tcp.connect` step whose state is SKIPPED. That record is
// not a claim — it is the measurement, and reporting it is the opposite of
// overclaiming.
//
// The false-positive policy governs what svcdoctor *says*, which is a finding's
// summary, detail, discriminator and recommendations. That is the surface here,
// taken from both the local and the shareable report, because a claim that
// survives redaction is still a claim.
//
// Phrases that must appear nowhere at all — a mechanism svcdoctor never observes
// has no business in an evidence attribute either — go to assertAbsentEverywhere.
func assertRefuses(t *testing.T, r run, forbidden []forbiddenClaim) {
	t.Helper()

	for name, text := range map[string]string{
		"local finding prose":     claimProse(r.report.Findings()),
		"shareable finding prose": claimProse(r.shareable.Findings()),
	} {
		lowered := strings.ToLower(text)
		for _, claim := range forbidden {
			if strings.Contains(lowered, strings.ToLower(claim.phrase)) {
				t.Errorf("the %s contains %q.\n\n%s\n\n--- prose ---\n%s",
					name, claim.phrase, claim.why, text)
			}
		}
	}
}

// assertAbsentEverywhere is the stronger check, for a word that has no place in
// any part of the document.
//
// A mechanism svcdoctor cannot observe — a firewall, a security group, a network
// policy — must not reach an evidence attribute either, because an attribute is
// where a peer-supplied or adapter-invented string would arrive.
func assertAbsentEverywhere(t *testing.T, r run, forbidden []forbiddenClaim) {
	t.Helper()

	for name, text := range map[string]string{
		"canonical JSON": r.canonicalJSON(t),
		"shareable JSON": r.shareableJSON(t),
		"terminal":       r.terminal(t),
	} {
		lowered := strings.ToLower(text)
		for _, claim := range forbidden {
			if strings.Contains(lowered, strings.ToLower(claim.phrase)) {
				t.Errorf("the %s output contains %q.\n\n%s\n\n--- output ---\n%s",
					name, claim.phrase, claim.why, text)
			}
		}
	}
}

// claimProse concatenates every free-text field a report's findings carry.
//
// Four fields, and the list is exhaustive on purpose: a field added to
// domain.Finding without being added here would be an unchecked claim surface.
func claimProse(findings []domain.Finding) string {
	var out strings.Builder
	for _, f := range findings {
		out.WriteString(f.Summary())
		out.WriteString("\n")
		out.WriteString(f.Detail())
		out.WriteString("\n")
		out.WriteString(f.Discriminator())
		out.WriteString("\n")
		for _, rec := range f.Recommendations() {
			out.WriteString(rec.Action())
			out.WriteString("\n")
		}
	}
	return out.String()
}

// requireFindings fails when a scenario produced nothing, so a refusal assertion
// can never pass because there was no output to check.
func requireFindings(t *testing.T, r run, atLeast int) {
	t.Helper()

	if got := len(r.report.Findings()); got < atLeast {
		t.Fatalf("the scenario produced %d findings, want at least %d; the refusal "+
			"assertions below would be vacuous", got, atLeast)
	}
}

// transportAndBoundary is the generic rule set, as internal/app wires it.
func transportAndBoundary() []namedRule {
	return []namedRule{
		{"transport/dns", diagnosistransport.DNS},
		{"transport/tcp", diagnosistransport.TCP},
		{"transport/tls", diagnosistransport.TLS},
	}
}

// postgresRules adds the PostgreSQL rules, for the scenarios whose forbidden
// claims are about what a legacy service finding must not grow into.
func postgresRules() []namedRule {
	return append(transportAndBoundary(),
		namedRule{"postgres/ssl-request", diagnosispostgres.SSLRequest},
		namedRule{"postgres/tls", diagnosispostgres.TLS},
		namedRule{"postgres/startup", diagnosispostgres.Startup},
		namedRule{"postgres/authentication", diagnosispostgres.Authentication},
		namedRule{"postgres/session", diagnosispostgres.Session},
	)
}

// anchoredGraph builds a requested-target anchor with one resolved address,
// which is the shape the generic transport rules are anchored on.
func anchoredGraph(t *testing.T) (*graphSpec, domain.EvidenceID) {
	t.Helper()

	s := newGraph(t)
	anchor := s.node("fp-target", "db.example:5432", domain.LayerInput,
		string(vocabulary.StepTargetRequested), domain.StatePass)
	dns := s.node("fp-dns", "db.example:5432", domain.LayerDNS,
		string(vocabulary.StepDNSLookup), domain.StatePass)
	s.parent(dns, anchor)
	return s, dns
}

// TestFP01ATCPTimeoutProducesNoMechanismClaim is the flagship refusal.
//
// A timed-out connection is compatible with a packet filter, a policy, a dropped
// route, a host that is off, a service that is not listening and a network that
// is merely slow. svcdoctor measured none of them and can distinguish none of
// them, so the only supported claim is that nothing answered from here.
func TestFP01ATCPTimeoutProducesNoMechanismClaim(t *testing.T) {
	s, dns := anchoredGraph(t)
	tcp := s.nodeWithClass("fp-tcp", "10.0.0.1:5432", domain.LayerTCP,
		string(vocabulary.StepTCPConnect), domain.StateFail, domain.FailureTCPConnectionTimeout)
	s.parent(tcp, dns)

	r := diagnose(t, s.freeze(), false, transportAndBoundary()...)
	requireFindings(t, r, 1)

	// These name mechanisms svcdoctor never observes, so they must appear in no
	// part of the document — not in a claim and not in an evidence attribute.
	assertAbsentEverywhere(t, r, []forbiddenClaim{
		{"firewall", "no firewall was observed and none could be"},
		{"security group", "a cloud construct svcdoctor never queried"},
		{"network policy", "a Kubernetes construct svcdoctor never queried"},
		{"networkpolicy", "the same, unspaced"},
	})
	assertRefuses(t, r, []forbiddenClaim{
		{"routing", "routing was not measured"},
		{"the host is down", "a timeout does not distinguish a host from a path to it"},
		{"is not running", "nothing observed whether a process exists"},
		{"not listening", "a timeout is not a refusal and does not prove a closed port"},
	})
}

// TestFP02AResourceLimitProducesNoCapacityCause is the PostgreSQL 53300 refusal.
//
// The rejection itself is HIGH by direct authority: the peer said so, in a field
// its own protocol defines. Every candidate *cause* — a leak, a pool sized
// wrongly, a setting too low, an application holding connections — is
// indistinguishable from the others with what svcdoctor can see, so it emits
// none of them.
func TestFP02AResourceLimitProducesNoCapacityCause(t *testing.T) {
	s, dns := anchoredGraph(t)
	tcp := s.node("fp-tcp", "10.0.0.1:5432", domain.LayerTCP,
		string(vocabulary.StepTCPConnect), domain.StatePass)
	startup := s.nodeWithClass("fp-startup", "10.0.0.1:5432", domain.LayerProtocol,
		string(servicepostgres.StepStartup), domain.StateFail, domain.FailureResourceLimitReached)
	s.parent(tcp, dns)
	s.parent(startup, tcp)

	r := diagnose(t, s.freeze(), false, postgresRules()...)
	requireFindings(t, r, 1)

	assertRefuses(t, r, []forbiddenClaim{
		{"connection leak", "no connection lifetime was observed"},
		{"leak", "the same, in any wording"},
		{"max_connections", "no server setting was read"},
		{"pool", "no pool was observed; svcdoctor is not one and inspected none"},
		{"too many connections", "the count was never observed, only the refusal"},
		{"increase", "a capacity recommendation assumes a cause"},
		{"application bug", "nothing about an application was measured"},
		{"exhausted", "exhaustion is a cause; the refusal is the observation"},
	})
}

// TestFP03ATLSHostnameMismatchProducesNoExpiryOrCAClaim is the refusal that
// keeps one TLS failure from becoming a different one.
//
// The handshake reported that no presented name matched. That says nothing about
// the validity window and nothing about who signed the chain, and a certificate
// failing this check may be perfectly valid for another name.
func TestFP03ATLSHostnameMismatchProducesNoExpiryOrCAClaim(t *testing.T) {
	s, dns := anchoredGraph(t)
	tcp := s.node("fp-tcp", "10.0.0.1:5432", domain.LayerTCP,
		string(vocabulary.StepTCPConnect), domain.StatePass)
	tls := s.nodeWithClass("fp-tls", "10.0.0.1:5432", domain.LayerTLS,
		string(vocabulary.StepTLSHandshake), domain.StateFail, domain.FailureTLSHostnameMismatch)
	s.parent(tcp, dns)
	s.parent(tls, tcp)

	r := diagnose(t, s.freeze(), false, transportAndBoundary()...)
	requireFindings(t, r, 1)

	assertRefuses(t, r, []forbiddenClaim{
		{"expired", "the validity window was not what failed"},
		{"expiry", "the same"},
		{"not yet valid", "the same, in the other direction"},
		{"untrusted", "the chain's trust is a different check with a different class"},
		{"unknown authority", "the same"},
		{"self-signed", "who signed it was not what failed"},
		{"invalid certificate", "it may be entirely valid for another name"},
	})
}

// TestFP04AnAuthenticationRefusalDoesNotNameTheWrongHalf is the credential
// refusal.
//
// PostgreSQL's own protocol distinguishes an unknown role from a bad secret in
// its log and not on the wire, so svcdoctor cannot. Naming either half would be
// picking one of two explanations the evidence does not separate.
func TestFP04AnAuthenticationRefusalDoesNotNameTheWrongHalf(t *testing.T) {
	s, dns := anchoredGraph(t)
	tcp := s.node("fp-tcp", "10.0.0.1:5432", domain.LayerTCP,
		string(vocabulary.StepTCPConnect), domain.StatePass)
	auth := s.nodeWithClass("fp-auth", "10.0.0.1:5432", domain.LayerAuth,
		string(servicepostgres.StepAuthentication), domain.StateFail,
		domain.FailureAuthCredentialsRejected)
	s.parent(tcp, dns)
	s.parent(auth, tcp)

	r := diagnose(t, s.freeze(), false, postgresRules()...)
	requireFindings(t, r, 1)

	assertRefuses(t, r, []forbiddenClaim{
		{"the password is wrong", "the wire does not separate the two halves"},
		{"wrong password", "the same"},
		{"incorrect password", "the same"},
		{"the username is wrong", "the same, on the other half"},
		{"user does not exist", "non-existence was never observed"},
		{"role does not exist", "the same"},
		{"typo", "nothing observed how the value was produced"},
	})
}

// TestFP05IncompleteTopologyIsNeverDescribedAsComplete is the RAB18 class, and
// the one this project has made twice.
//
// Two endpoints failed and two were never attempted. "Only these two failed" is
// a claim about the two nobody measured.
func TestFP05IncompleteTopologyIsNeverDescribedAsComplete(t *testing.T) {
	s, dns := anchoredGraph(t)
	for _, addr := range []string{"10.0.0.1", "10.0.0.2"} {
		tcp := s.nodeWithClass("fp-tcp-"+addr, addr+":5432", domain.LayerTCP,
			string(vocabulary.StepTCPConnect), domain.StateFail,
			domain.FailureTCPConnectionRefused)
		s.parent(tcp, dns)
	}
	for _, addr := range []string{"10.0.0.3", "10.0.0.4"} {
		s.node("fp-tcp-"+addr, addr+":5432", domain.LayerTCP,
			string(vocabulary.StepTCPConnect), domain.StateUnknown)
	}

	r := diagnose(t, s.freeze(), true, transportAndBoundary()...)
	requireFindings(t, r, 1)

	// The two unmeasured endpoints get no boundary, so nothing claims they
	// failed and nothing claims they were fine.
	got := r.boundaries(t)
	for _, unmeasured := range []string{"10.0.0.3:5432", "10.0.0.4:5432"} {
		if _, present := got[unmeasured]; present {
			t.Errorf("the never-measured endpoint %s got a boundary", unmeasured)
		}
	}

	assertRefuses(t, r, []forbiddenClaim{
		{"all endpoints", "two of the four were never attempted"},
		{"every endpoint", "the same"},
		{"all addresses", "the same"},
		{"only 10.0.0.1", "a claim about the ones nobody measured"},
		{"the cluster is", "no cluster-level health was measured"},
		{"entirely unreachable", "an unmeasured endpoint is not an unreachable one"},
	})
}

// TestTheRefusalCorpusCanFail is the non-vacuity proof for the whole file.
//
// Every assertion above is an absence, and an absence passes for free when the
// scan is looking in the wrong place. This plants one of the forbidden phrases
// in a finding built by hand and requires the same scan to catch it.
func TestTheRefusalCorpusCanFail(t *testing.T) {
	s, dns := anchoredGraph(t)
	tcp := s.nodeWithClass("fp-tcp", "10.0.0.1:5432", domain.LayerTCP,
		string(vocabulary.StepTCPConnect), domain.StateFail, domain.FailureTCPConnectionTimeout)
	s.parent(tcp, dns)

	subject, err := domain.NewEndpointSubject("10.0.0.1:5432")
	if err != nil {
		t.Fatalf("NewEndpointSubject: %v", err)
	}
	overclaiming := func(diagnosis.RuleContext) []domain.Finding {
		f, err := domain.NewFinding(domain.FindingInput{
			Code: "TCP_CONNECTION_REFUSED", Kind: domain.FindingKindHypothesis,
			Severity: domain.SeverityError, Confidence: domain.ConfidenceHigh,
			Layer: domain.LayerTCP, Subject: subject,
			Summary:      "a firewall is blocking the connection to this endpoint",
			EvidenceRefs: []domain.EvidenceID{"fp-tcp"},
		})
		if err != nil {
			t.Fatalf("NewFinding: %v", err)
		}
		return []domain.Finding{f}
	}

	r := diagnose(t, s.freeze(), false,
		append(transportAndBoundary(), namedRule{"test/overclaims", overclaiming})...)

	// The same scan, against a report that really does contain the claim.
	surfaces := []string{r.canonicalJSON(t), r.shareableJSON(t), r.terminal(t)}
	for i, text := range surfaces {
		if !strings.Contains(strings.ToLower(text), "firewall") {
			t.Errorf("surface %d did not carry the planted claim, so the corpus above "+
				"is scanning something that cannot contain a finding's prose", i)
		}
	}
}
