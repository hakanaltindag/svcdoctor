package terminal

import (
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicekafka "github.com/hakanaltindag/svcdoctor/internal/service/kafka"
	"github.com/hakanaltindag/svcdoctor/internal/vocabulary"
)

// What the Kafka output is allowed to claim, and what it must keep apart.

// --- the hierarchy -------------------------------------------------------------

// TestAnAdvertisedTransportPathIsNotABootstrapPath is the defect ADR 0052 §5
// named in advance.
//
// `collectPaths` used to promote every `tcp.connect` in the graph. A Kafka graph
// has two populations of them, and flattening presents a broker the cluster
// named as though the operator had named it.
func TestAnAdvertisedTransportPathIsNotABootstrapPath(t *testing.T) {
	text := renderKafka(t, healthyKafka(t).report(), false)

	bootstrap, advertised := 0, 0
	var section string
	for _, line := range strings.Split(text, "\n") {
		switch {
		case strings.HasPrefix(line, "  Advertised broker"):
			section = "advertised"
		case strings.HasPrefix(line, "  Path "):
			section = "bootstrap"
			bootstrap++
		case strings.HasPrefix(line, "    Path "):
			if section != "advertised" {
				t.Errorf("an indented path appeared outside an advertisement:\n%s", line)
			}
			advertised++
		}
	}
	if bootstrap != 1 {
		t.Errorf("bootstrap paths = %d, want 1:\n%s", bootstrap, text)
	}
	if advertised != 2 {
		t.Errorf("advertised paths = %d, want 2:\n%s", advertised, text)
	}
}

// TestNoTransportNodeIsRenderedTwice is the other half of the same defect.
//
// Before the advertisement boundary, `descendants` walked from a bootstrap
// connection straight through the metadata node into every advertised sweep, so
// each discovered address appeared once in that path's unnamed stages and once
// again as a top-level path.
func TestNoTransportNodeIsRenderedTwice(t *testing.T) {
	text := renderKafka(t, healthyKafka(t).report(), false)

	for _, address := range []string{"198.51.100.21:9093", "198.51.100.22:9093"} {
		if got := strings.Count(text, "Path "+address); got != 1 {
			t.Errorf("%s appears as a path %d times, want 1:\n%s", address, got, text)
		}
	}
	// The advertisement node itself is rendered once: as a heading and its own
	// row, and never as a stage of the bootstrap path.
	for _, line := range bootstrapSection(text) {
		if strings.Contains(line, "Broker advertisement") {
			t.Errorf("an advertisement was rendered inside the bootstrap path:\n%s", line)
		}
	}
}

// bootstrapSection returns the lines from the first bootstrap path up to the
// first advertisement heading.
func bootstrapSection(text string) []string {
	var out []string
	inside := false
	for _, line := range strings.Split(text, "\n") {
		switch {
		case strings.HasPrefix(line, "  Path "):
			inside = true
		case strings.HasPrefix(line, "  Advertised broker"), line == "Findings":
			inside = false
		}
		if inside {
			out = append(out, line)
		}
	}
	return out
}

// TestAnAdvertisedBrokerCarriesNoAuthenticationRow is ADR 0050 at the output
// boundary.
//
// A discovered endpoint receives credential-free DNS, TCP and TLS and nothing
// else. A row naming authentication beneath one would tell an operator svcdoctor
// might have presented a credential there.
func TestAnAdvertisedBrokerCarriesNoAuthenticationRow(t *testing.T) {
	text := renderKafka(t, healthyKafka(t).report(), false)

	inside := false
	for _, line := range strings.Split(text, "\n") {
		switch {
		case strings.HasPrefix(line, "  Advertised broker"):
			inside = true
		case line == "Findings":
			inside = false
		}
		if !inside {
			continue
		}
		for _, forbidden := range []string{
			"Authentication", "SASL", "Kafka API versions", "Kafka metadata",
			"credential", "password",
		} {
			if strings.Contains(line, forbidden) {
				t.Errorf("an advertised broker's subtree mentions %q:\n%s", forbidden, line)
			}
		}
	}
}

// TestARowTheJourneyDoesNotPlaceIsShownRatherThanHidden is the security-visible
// half of the advertised-broker rule.
//
// The advertised journey is transport-only, so an authentication node beneath an
// advertisement is a stage no producer should ever mint — it would mean the
// sweep had grown a second hop and ADR 0050 had been broken upstream. This test
// builds that graph deliberately and requires the renderer to **show** it.
//
// A renderer that filtered the row instead would make the one output an operator
// reads look correct while svcdoctor authenticated to an endpoint a peer named.
// Hiding a security failure is worse than reporting one, and this is the
// difference between a journey table and a filter.
func TestARowTheJourneyDoesNotPlaceIsShownRatherThanHidden(t *testing.T) {
	g := metadataObtained(t)
	ad := g.advertisement(2, "broker-2.internal:9093", domain.StatePass, domain.FailureNone)
	g.sweep(ad, "broker-2.internal:9093", "198.51.100.22:9093",
		passed(vocabulary.StepDNSLookup, 160),
		[]stage{passed(tcp, 130), passed(tlsStep, 709), passed(auth, 94)})

	text := renderKafka(t, g.report(), false)

	inside, shown := false, false
	for _, line := range strings.Split(text, "\n") {
		switch {
		case strings.HasPrefix(line, "  Advertised broker"):
			inside = true
		case line == "Findings":
			inside = false
		}
		if inside && strings.Contains(line, "Authentication") {
			shown = true
		}
	}
	if !shown {
		t.Errorf("an authentication node beneath an advertisement was hidden:\n%s", text)
	}
}

// TestNoEvidenceIdentifierReachesTheOutput keeps the machine surface in the JSON.
func TestNoEvidenceIdentifierReachesTheOutput(t *testing.T) {
	text := renderKafka(t, healthyKafka(t).report(), false)

	for _, identifier := range []string{
		"kafka.broker_advertised/", "dns.lookup/", "tcp.connect/", "advertised.",
	} {
		if strings.Contains(text, identifier) {
			t.Errorf("an evidence identifier reached the output: %q\n%s", identifier, text)
		}
	}
}

// --- outcome semantics ---------------------------------------------------------

// TestTheKafkaOutcomeIsADR0052sWordingExactly pins both phrasings.
func TestTheKafkaOutcomeIsADR0052sWordingExactly(t *testing.T) {
	obtained := renderKafka(t, healthyKafka(t).report(), false)
	if !containsRow(obtained, "outcome", "Kafka metadata obtained") {
		t.Errorf("the outcome line is not ADR 0052's wording:\n%s", obtained)
	}

	g := stopAt(t, failed(meta, domain.FailureProtocolPeerClosed, 40),
		withAuth(passed(auth, 94))...)
	notObtained := renderKafka(t, g.report(), false)
	if !containsRow(notObtained, "outcome", "Kafka metadata NOT obtained") {
		t.Errorf("a broken Metadata exchange is not reported as such:\n%s", notObtained)
	}
}

// TestTheKafkaOutputNeverOverclaims sweeps every phrase ADR 0052 §3 rejected.
func TestTheKafkaOutputNeverOverclaims(t *testing.T) {
	documents := []string{
		renderKafka(t, healthyKafka(t).report(), false),
		renderKafka(t, stopAt(t, failed(auth, domain.FailureAuthCredentialsRejected, 120),
			discovery()...).report(), false),
	}

	rejected := []string{
		"session established", "session NOT established",
		"cluster metadata", "cluster reachable", "cluster usable", "cluster healthy",
		"broker healthy", "broker usable", "authenticated cluster",
		"journey completed", "connection established", "endpoints reachable",
		"endpoints usable", "wrong password", "healthy",
	}
	for _, text := range documents {
		lower := strings.ToLower(text)
		for _, phrase := range rejected {
			if strings.Contains(lower, strings.ToLower(phrase)) {
				t.Errorf("the Kafka output claims %q:\n%s", phrase, text)
			}
		}
	}
}

// TestTheOutcomeComesFromTheMetadataNodeAndNothingElse covers the wrong sources.
func TestTheOutcomeComesFromTheMetadataNodeAndNothingElse(t *testing.T) {
	// Authentication passed and Metadata is absent. A passing SaslAuthenticate
	// proves the credential was accepted and says nothing about authorization,
	// so this must not read as obtained (ADR 0052 §1).
	g := newKafkaGraph(t)
	g.bootstrapPath(addrOne, withAuth(passed(auth, 94))...)
	if text := renderKafka(t, g.report(), false); !containsRow(
		text, "outcome", "Kafka metadata NOT obtained") {
		t.Errorf("a passing authentication was read as obtained metadata:\n%s", text)
	}

	// No findings and status OK. An empty findings list is not evidence.
	g2 := newKafkaGraph(t)
	g2.bootstrapPath(addrOne, discovery()...)
	text := renderKafka(t, g2.report(), false)
	if !containsRow(text, "status", "OK  no target-side error was proven") &&
		!strings.Contains(text, "status") {
		t.Fatalf("the fixture did not produce an OK report:\n%s", text)
	}
	if !containsRow(text, "outcome", "Kafka metadata NOT obtained") {
		t.Errorf("an OK report with no findings was read as obtained metadata:\n%s", text)
	}

	// Every non-passing state, not merely FAIL. An UNKNOWN Metadata node is
	// svcdoctor's own budget expiring mid-exchange, and a SKIPPED one is a step
	// it declined to run: neither obtained anything, and reading "not FAIL" as
	// success would turn both into a claim the run cannot support.
	for _, notObtained := range []stage{
		failed(meta, domain.FailureProtocolPeerClosed, 40),
		unknownAt(meta, domain.FailureExecLocalTimeout, measured(80000)),
		unknownAt(meta, domain.FailureExecCancelled, domain.Unmeasured()),
		skipped(meta, domain.FailureExecSkippedPrerequisiteFailed),
		{step: meta, state: domain.StateDegraded, elapsed: measured(90)},
	} {
		g3 := stopAt(t, notObtained, withAuth(passed(auth, 94))...)
		text := renderKafka(t, g3.report(), false)
		if !containsRow(text, "outcome", "Kafka metadata NOT obtained") {
			t.Errorf("a %s Metadata node was read as obtained:\n%s", notObtained.state, text)
		}
	}
}

// --- topology semantics --------------------------------------------------------

// TestTheTopologyLineCountsWhatWasReached walks the counting rule.
func TestTheTopologyLineCountsWhatWasReached(t *testing.T) {
	tests := []struct {
		name  string
		build func(*testing.T) *kafkaGraph
		want  string
	}{
		{
			name:  "every endpoint reached",
			build: healthyKafka,
			want:  "2 of 2 advertised broker endpoints reached",
		},
		{
			name: "one refused",
			build: func(t *testing.T) *kafkaGraph {
				g := metadataObtained(t)
				g.reachable(1, "broker-1.internal:9093", "198.51.100.21:9093")
				g.refused(2, "broker-2.internal:9093", "198.51.100.22:9093")
				return g
			},
			want: "1 of 2 advertised broker endpoints reached",
		},
		{
			name: "none reached",
			build: func(t *testing.T) *kafkaGraph {
				g := metadataObtained(t)
				g.refused(1, "broker-1.internal:9093", "198.51.100.21:9093")
				return g
			},
			want: "0 of 1 advertised broker endpoints reached",
		},
		{
			name: "one never measured",
			build: func(t *testing.T) *kafkaGraph {
				g := metadataObtained(t)
				g.reachable(1, "broker-1.internal:9093", "198.51.100.21:9093")
				g.unmeasured(2, "broker-2.internal:9093", "198.51.100.22:9093")
				return g
			},
			want: "1 of 2 advertised broker endpoints reached, 1 not measured",
		},
		{
			name: "a TLS plan that failed is not reached",
			build: func(t *testing.T) *kafkaGraph {
				g := metadataObtained(t)
				ad := g.advertisement(1, "broker-1.internal:9093",
					domain.StatePass, domain.FailureNone)
				g.sweep(ad, "broker-1.internal:9093", "198.51.100.21:9093",
					passed(vocabulary.StepDNSLookup, 160), []stage{
						passed(tcp, 130),
						failed(tlsStep, domain.FailureTLSUnknownAuthority, 400),
					})
				return g
			},
			want: "0 of 1 advertised broker endpoints reached",
		},
		{
			name: "one working path beside one refused resolves the endpoint",
			build: func(t *testing.T) *kafkaGraph {
				g := metadataObtained(t)
				ad := g.advertisement(1, "broker-1.internal:9093",
					domain.StatePass, domain.FailureNone)
				g.sweep(ad, "broker-1.internal:9093", "198.51.100.21:9093",
					passed(vocabulary.StepDNSLookup, 160),
					[]stage{failed(tcp, domain.FailureTCPConnectionRefused, 210)},
					[]stage{passed(tcp, 130), passed(tlsStep, 709)})
				return g
			},
			want: "1 of 1 advertised broker endpoints reached",
		},
		{
			// The budget expired before this advertisement's sweep began, so the
			// advertisement node stands alone. MeasureAdvertised breaks out of
			// its loop on a done context, which is the production shape.
			name: "an advertisement whose sweep never began is not measured",
			build: func(t *testing.T) *kafkaGraph {
				g := metadataObtained(t)
				g.reachable(1, "broker-1.internal:9093", "198.51.100.21:9093")
				g.neverSwept(2, "broker-2.internal:9093")
				return g
			},
			want: "1 of 2 advertised broker endpoints reached, 1 not measured",
		},
		{
			name: "an advertisement whose lookup was cut short is not measured",
			build: func(t *testing.T) *kafkaGraph {
				g := metadataObtained(t)
				g.reachable(1, "broker-1.internal:9093", "198.51.100.21:9093")
				g.lookupCutShort(2, "broker-2.internal:9093")
				return g
			},
			want: "1 of 2 advertised broker endpoints reached, 1 not measured",
		},
		{
			name: "a resolved name nothing was attempted against is not measured",
			build: func(t *testing.T) *kafkaGraph {
				g := metadataObtained(t)
				g.reachable(1, "broker-1.internal:9093", "198.51.100.21:9093")
				g.resolvedButUnattempted(2, "broker-2.internal:9093")
				return g
			},
			want: "1 of 2 advertised broker endpoints reached, 1 not measured",
		},
		{
			name: "duplicate advertisements are counted as the cluster stated them",
			build: func(t *testing.T) *kafkaGraph {
				g := metadataObtained(t)
				g.reachable(1, "broker-1.internal:9093", "198.51.100.21:9093")
				g.reachable(2, "broker-1.internal:9093", "198.51.100.21:9093")
				return g
			},
			want: "2 of 2 advertised broker endpoints reached",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			text := renderKafka(t, tt.build(t).report(), false)
			if !containsRow(text, "topology", tt.want) {
				t.Errorf("topology line is not %q:\n%s", tt.want, text)
			}
		})
	}
}

// TestARunWithNoAdvertisementsHasNoTopologyLine keeps `0 of 0` out of the output.
func TestARunWithNoAdvertisementsHasNoTopologyLine(t *testing.T) {
	g := newKafkaGraph(t)
	g.bootstrapPath(addrOne, withAuth(passed(auth, 94), passed(meta, 90))...)

	if text := renderKafka(t, g.report(), false); strings.Contains(text, "topology") {
		t.Errorf("a run that recorded no advertisements printed a topology line:\n%s", text)
	}
}

// TestNotMeasuredIsNeverCollapsedIntoNotReached is ADR 0052's hardest rule.
//
// # It runs over every shape that leaves an advertisement unresolved
//
// classify has four ways to reach `not measured`, and until Phase 6.5 only one
// of them — an address whose connection was cut short — was asserted anywhere.
// Mutation found the other three: making an advertisement with no sweep, one
// whose lookup was cut short, or one whose resolved name nothing was attempted
// against read as `not reached` survived the whole suite.
//
// Each of those is production-reachable. `MeasureAdvertised` breaks out of its
// loop the moment the context is done, so a budget that expires part-way
// through a topology leaves later advertisements with no sweep at all, and one
// that expires inside a sweep leaves the lookup or the attempt list short.
//
// Counting any of them as unreached would assert a failure nobody observed —
// `1 of 3 reached` for two endpoints svcdoctor never looked at — which is the
// same false certainty ADR 0051's PASS-is-existential / FAIL-is-universal rule
// prevents one layer up. `internal/app`'s twin predicate has covered all four
// since ADR 0051 landed; this is the renderer half.
func TestNotMeasuredIsNeverCollapsedIntoNotReached(t *testing.T) {
	shapes := map[string]func(*kafkaGraph){
		"an address whose connection was cut short": func(g *kafkaGraph) {
			g.unmeasured(2, "broker-2.internal:9093", "198.51.100.22:9093")
		},
		"an advertisement whose sweep never began": func(g *kafkaGraph) {
			g.neverSwept(2, "broker-2.internal:9093")
		},
		"an advertisement whose lookup was cut short": func(g *kafkaGraph) {
			g.lookupCutShort(2, "broker-2.internal:9093")
		},
		"a resolved name nothing was attempted against": func(g *kafkaGraph) {
			g.resolvedButUnattempted(2, "broker-2.internal:9093")
		},
	}
	for name, build := range shapes {
		t.Run(name, func(t *testing.T) {
			g := metadataObtained(t)
			g.reachable(1, "broker-1.internal:9093", "198.51.100.21:9093")
			build(g)
			text := renderKafka(t, g.report(), true)

			if !strings.Contains(text, "1 not measured") {
				t.Errorf("an unresolved advertisement is not reported as "+
					"unmeasured:\n%s", text)
			}
			if containsRow(text, "topology",
				"1 of 2 advertised broker endpoints reached") {
				t.Errorf("an unmeasured endpoint was counted as unreached:\n%s", text)
			}
		})
	}
}

// TestALocallyCutShortSweepKeepsItsReasonLegible pins the stage row beside the
// count, so a reader can see why an endpoint was never measured.
func TestALocallyCutShortSweepKeepsItsReasonLegible(t *testing.T) {
	g := metadataObtained(t)
	g.reachable(1, "broker-1.internal:9093", "198.51.100.21:9093")
	g.unmeasured(2, "broker-2.internal:9093", "198.51.100.22:9093")
	text := renderKafka(t, g.report(), true)
	// And the stage row keeps the local class, so the reason is legible too.
	if !strings.Contains(text, "EXEC_LOCAL_TIMEOUT") {
		t.Error("the unmeasured path lost the class that says svcdoctor stopped")
	}
	if strings.Contains(text, "✗ FAIL  TCP") {
		t.Error("an unmeasured connection was rendered as a failure")
	}
}

// TestTheTopologyLineIsACountNotAJudgement pins the rejected vocabulary.
func TestTheTopologyLineIsACountNotAJudgement(t *testing.T) {
	text := renderKafka(t, healthyKafka(t).report(), false)

	for _, line := range strings.Split(text, "\n") {
		if !strings.Contains(line, "topology") {
			continue
		}
		// Whole words: "reached" contains no judgement, and "broker" contains
		// "ok" only as letters.
		for _, word := range strings.Fields(strings.ToLower(line)) {
			switch word {
			case "usable", "healthy", "reachable", "degraded", "ok", "good", "bad":
				t.Errorf("the topology line judges with %q:\n%s", word, line)
			}
		}
	}
}

// --- authentication outcomes ---------------------------------------------------

// TestEveryAuthenticationOutcomeRendersDistinctly is section 16 of the phase.
//
// Seven outcomes, seven rows, and no two of them alike. The row carries the
// recorded class and never a cause: naming one in a stage row would be a second,
// unreviewed vocabulary competing with the finding that owns the claim.
func TestEveryAuthenticationOutcomeRendersDistinctly(t *testing.T) {
	tests := []struct {
		name  string
		stage stage
		want  string
	}{
		{"credential not configured",
			skipped(auth, domain.FailureExecRequiredInputMissing),
			"EXEC_REQUIRED_INPUT_MISSING"},
		{"credential withheld",
			skipped(auth, domain.FailureExecSkippedByPolicy),
			"EXEC_SKIPPED_BY_POLICY"},
		{"credentials rejected",
			failed(auth, domain.FailureAuthCredentialsRejected, 120),
			"AUTH_CREDENTIALS_REJECTED"},
		{"mechanism unsupported by svcdoctor",
			unknownAt(auth, domain.FailureAuthMechanismUnsupported, domain.Unmeasured()),
			"AUTH_MECHANISM_UNSUPPORTED"},
		{"peer verification failed",
			failed(auth, domain.FailureAuthPeerVerificationFailed, 130),
			"AUTH_PEER_VERIFICATION_FAILED"},
		{"generic exchange not completed",
			failed(auth, domain.FailureProtocolPeerClosed, 55),
			"PROTOCOL_PEER_CLOSED"},
	}

	seen := map[string]string{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			text := renderKafka(t, stopAt(t, tt.stage, discovery()...).report(), false)
			if !strings.Contains(text, tt.want) {
				t.Errorf("the authentication row does not carry %q:\n%s", tt.want, text)
			}
			row := authenticationRow(text)
			if previous, clash := seen[row]; clash {
				t.Errorf("%q renders identically to %q: %q", tt.name, previous, row)
			}
			seen[row] = tt.name
		})
	}

	// The mechanism the endpoint never offered is a different step, so it is
	// checked apart rather than folded into the table above.
	g := stopAt(t, failed(mech, domain.FailureAuthMechanismNotOffered, 70),
		passed(tcp, 190), passed(tlsStep, 1700), passed(versions, 155))
	text := renderKafka(t, g.report(), false)
	if !strings.Contains(text, "AUTH_MECHANISM_NOT_OFFERED") {
		t.Errorf("a mechanism the endpoint does not offer is not reported:\n%s", text)
	}
	if !strings.Contains(text, "Authentication                     not reached") {
		t.Errorf("authentication after a failed negotiation is not `not reached`:\n%s", text)
	}
}

func authenticationRow(text string) string {
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, "Authentication") {
			return strings.Join(strings.Fields(line), " ")
		}
	}
	return ""
}

// TestPeerVerificationIsNeverRenderedAsARejectedCredential is the Phase 6.2
// closure result, held at the output boundary.
//
// The server's proof did not verify. That is not the operator's password being
// wrong, and saying so would send someone to rotate a credential that is
// correct.
func TestPeerVerificationIsNeverRenderedAsARejectedCredential(t *testing.T) {
	g := stopAt(t, failed(auth, domain.FailureAuthPeerVerificationFailed, 130), discovery()...)
	text := renderKafka(t, g.report(kafkaFinding(t, "KAFKA_PEER_VERIFICATION_FAILED",
		domain.SeverityError, domain.LayerAuth, addrOne)), false)

	if !strings.Contains(text, "AUTH_PEER_VERIFICATION_FAILED") {
		t.Error("the class the producer recorded is missing")
	}
	if !strings.Contains(text, "KAFKA_PEER_VERIFICATION_FAILED") {
		t.Error("the finding that owns the claim is missing")
	}
	for _, wrong := range []string{
		"CREDENTIALS_REJECTED", "wrong password", "incorrect password",
		"bad credential", "rejected the credential",
	} {
		if strings.Contains(strings.ToLower(text), strings.ToLower(wrong)) {
			t.Errorf("peer verification was rendered as %q:\n%s", wrong, text)
		}
	}
	if !containsRow(text, "first break", "L5  auth") {
		t.Errorf("the first broken layer is not L5:\n%s", text)
	}
}

// --- multi-path bootstrap ------------------------------------------------------

// TestExactlyOneBootstrapPathIsMarkedContinued is ADR 0028's cardinality, shown.
func TestExactlyOneBootstrapPathIsMarkedContinued(t *testing.T) {
	g := newKafkaGraph(t)
	g.bootstrapPath(addrOne, withAuth(passed(auth, 94), passed(meta, 90))...)
	g.bootstrapPath(addrTwo, discovery()...)
	text := renderKafka(t, g.report(), false)

	if got := strings.Count(text, "· continued"); got != 1 {
		t.Errorf("continued markers = %d, want exactly 1:\n%s", got, text)
	}
	if !strings.Contains(text, "Path "+addrOne+" · continued") {
		t.Error("the path that authenticated is not the marked one")
	}
	// The unselected path is not a failure. It carries no failure class, no
	// glyph that reads as one, and its absent stages say what is true.
	unselected := pathSection(text, addrTwo)
	for _, wrong := range []string{"✗ FAIL", "? UNKNOWN", "SKIPPED"} {
		if strings.Contains(unselected, wrong) {
			t.Errorf("an unselected bootstrap path reads as a failure:\n%s", unselected)
		}
	}
	if !strings.Contains(unselected, "not attempted on this path") {
		t.Errorf("the unselected path does not say what is true:\n%s", unselected)
	}
}

// TestTheContinuedMarkerIsNotInferredFromACredential covers the run that has
// none.
//
// A run with no credential still continues exactly one path and records a
// truthful unattempted-authentication node on it. Reading selection off the
// secret would leave this run with no marked path at all.
func TestTheContinuedMarkerIsNotInferredFromACredential(t *testing.T) {
	g := newKafkaGraph(t)
	g.bootstrapPath(addrOne, append(discovery(),
		skipped(auth, domain.FailureExecRequiredInputMissing))...)
	g.bootstrapPath(addrTwo, discovery()...)

	text := renderKafka(t, g.report(), false)
	if got := strings.Count(text, "· continued"); got != 1 {
		t.Errorf("continued markers = %d, want 1 on a run with no credential:\n%s", got, text)
	}
	if !strings.Contains(text, "Path "+addrOne+" · continued") {
		t.Error("the path that recorded the unattempted authentication is not marked")
	}
}

// TestCanonicalOrderIsPreserved pins that the renderer imposes no ranking.
func TestCanonicalOrderIsPreserved(t *testing.T) {
	g := newKafkaGraph(t)
	// The failing path first in canonical order, the continued one second. A
	// renderer that promoted the working path, or preferred an address family,
	// would reorder them.
	g.bootstrapPath(addrOne, failed(tcp, domain.FailureTCPConnectionRefused, 210))
	g.bootstrapPath(addrTwo, withAuth(passed(auth, 94), passed(meta, 90))...)

	text := renderKafka(t, g.report(), false)
	first := strings.Index(text, "Path "+addrOne)
	second := strings.Index(text, "Path "+addrTwo)
	if first < 0 || second < 0 {
		t.Fatalf("a path is missing:\n%s", text)
	}
	if first > second {
		t.Errorf("the working path was promoted above the failed one:\n%s", text)
	}
}

func pathSection(text, subject string) string {
	lines := strings.Split(text, "\n")
	var out []string
	inside := false
	for _, line := range lines {
		if strings.HasPrefix(line, "  Path ") {
			inside = strings.Contains(line, subject)
			continue
		}
		if strings.HasPrefix(line, "  Advertised") || line == "Findings" {
			inside = false
		}
		if inside {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}

// --- the four axes -------------------------------------------------------------

// TestTheFourAxesAreIndependent pins the combinations a reader might think
// impossible.
func TestTheFourAxesAreIndependent(t *testing.T) {
	tests := []struct {
		name       string
		build      func(*testing.T) *kafkaGraph
		findings   []domain.Finding
		incomplete bool
		want       map[string]string
	}{
		{
			// A. OK, no metadata, complete: the credential was never configured.
			name: "OK with no metadata and a complete run",
			build: func(t *testing.T) *kafkaGraph {
				return stopAt(t, skipped(auth, domain.FailureExecRequiredInputMissing),
					discovery()...)
			},
			findings: []domain.Finding{},
			want: map[string]string{
				"status":    "OK  no target-side error was proven",
				"outcome":   "Kafka metadata NOT obtained",
				"execution": "complete",
			},
		},
		{
			// B. PROBLEMS FOUND with metadata obtained: the core journey worked
			// and a discovered endpoint did not.
			name: "problems found with metadata obtained",
			build: func(t *testing.T) *kafkaGraph {
				g := metadataObtained(t)
				g.reachable(1, "broker-1.internal:9093", "198.51.100.21:9093")
				g.reachable(2, "broker-2.internal:9093", "198.51.100.22:9093")
				g.refused(3, "broker-3.internal:9093", "198.51.100.23:9093")
				return g
			},
			want: map[string]string{
				"status":    "PROBLEMS FOUND",
				"outcome":   "Kafka metadata obtained",
				"topology":  "2 of 3 advertised broker endpoints reached",
				"execution": "complete",
			},
		},
		{
			// C. Incomplete with metadata obtained and nothing proven wrong.
			name: "incomplete with metadata obtained",
			build: func(t *testing.T) *kafkaGraph {
				g := metadataObtained(t)
				g.reachable(1, "broker-1.internal:9093", "198.51.100.21:9093")
				g.reachable(2, "broker-2.internal:9093", "198.51.100.22:9093")
				g.unmeasured(3, "broker-3.internal:9093", "198.51.100.23:9093")
				return g
			},
			findings:   []domain.Finding{},
			incomplete: true,
			want: map[string]string{
				"status":    "OK  no target-side error was proven",
				"outcome":   "Kafka metadata obtained",
				"topology":  "2 of 3 advertised broker endpoints reached, 1 not measured",
				"execution": "INCOMPLETE  svcdoctor did not finish the intended measurement",
			},
		},
		{
			// D. Peer verification: the break is at L5 and metadata is absent.
			name: "peer verification failure",
			build: func(t *testing.T) *kafkaGraph {
				return stopAt(t, failed(auth, domain.FailureAuthPeerVerificationFailed, 130),
					discovery()...)
			},
			want: map[string]string{
				"status":      "PROBLEMS FOUND",
				"outcome":     "Kafka metadata NOT obtained",
				"execution":   "complete",
				"first break": "L5  auth",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := tt.findings
			if findings == nil {
				findings = []domain.Finding{kafkaFinding(t, "KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE",
					domain.SeverityError, layerFor(tt.want), "198.51.100.23:9093")}
			}
			text := renderKafka(t, tt.build(t).report(findings...), tt.incomplete)
			for label, want := range tt.want {
				if !containsRow(text, label, want) {
					t.Errorf("row %q is not %q:\n%s", label, want, text)
				}
			}
		})
	}
}

// layerFor picks the layer the scenario's first-break expectation implies.
func layerFor(want map[string]string) domain.Layer {
	if strings.HasPrefix(want["first break"], "L5") {
		return domain.LayerAuth
	}
	return domain.LayerTCP
}

// --- fixture helpers -----------------------------------------------------------

// metadataObtained is a run whose core journey finished, with no advertisements
// yet.
func metadataObtained(t *testing.T) *kafkaGraph {
	t.Helper()
	g := newKafkaGraph(t)
	g.bootstrapPath(addrOne, withAuth(passed(auth, 94), passed(meta, 90))...)
	return g
}

func (g *kafkaGraph) reachable(nodeID int64, name, address string) {
	g.t.Helper()
	ad := g.advertisement(nodeID, name, domain.StatePass, domain.FailureNone)
	g.sweep(ad, name, address, passed(vocabulary.StepDNSLookup, 160),
		[]stage{passed(tcp, 130), passed(tlsStep, 709)})
}

func (g *kafkaGraph) refused(nodeID int64, name, address string) {
	g.t.Helper()
	ad := g.advertisement(nodeID, name, domain.StatePass, domain.FailureNone)
	g.sweep(ad, name, address, passed(vocabulary.StepDNSLookup, 160),
		[]stage{failed(tcp, domain.FailureTCPConnectionRefused, 210)})
}

// neverSwept records an advertisement the run's budget stopped it from
// measuring at all: the node stands alone, with no lookup beneath it.
//
// It is what MeasureAdvertised leaves behind when it breaks out of its loop on a
// done context, and the advertisement node alone claims nothing about
// reachability.
func (g *kafkaGraph) neverSwept(nodeID int64, name string) {
	g.t.Helper()
	g.advertisement(nodeID, name, domain.StatePass, domain.FailureNone)
}

// lookupCutShort records an advertisement whose own name resolution ended
// undetermined because svcdoctor's budget expired.
//
// Nothing was learned about the endpoint: an unresolved name is not a name that
// does not resolve.
func (g *kafkaGraph) lookupCutShort(nodeID int64, name string) {
	g.t.Helper()
	ad := g.advertisement(nodeID, name, domain.StatePass, domain.FailureNone)
	g.sweep(ad, name, "", unknownAt(
		vocabulary.StepDNSLookup, domain.FailureExecLocalTimeout, measured(80000)))
}

// resolvedButUnattempted records an advertisement whose name resolved and
// against which nothing was tried.
//
// That is not a negative anybody proved: a client selecting one of those
// addresses might have connected.
func (g *kafkaGraph) resolvedButUnattempted(nodeID int64, name string) {
	g.t.Helper()
	ad := g.advertisement(nodeID, name, domain.StatePass, domain.FailureNone)
	g.sweep(ad, name, "", passed(vocabulary.StepDNSLookup, 160))
}

func (g *kafkaGraph) unmeasured(nodeID int64, name, address string) {
	g.t.Helper()
	ad := g.advertisement(nodeID, name, domain.StatePass, domain.FailureNone)
	g.sweep(ad, name, address, passed(vocabulary.StepDNSLookup, 160),
		[]stage{unknownAt(tcp, domain.FailureExecLocalTimeout, measured(80000))})
}

// --- the service table ---------------------------------------------------------

// TestAServiceWithNoTableStillRenders keeps a future service from vanishing.
func TestAServiceWithNoTableStillRenders(t *testing.T) {
	g := newKafkaGraph(t)
	g.b.service = "redis"
	g.bootstrapPath(addrOne, passed(tcp, 190), passed(tlsStep, 1700))

	text := renderKafka(t, g.report(), false)
	if !strings.Contains(text, "Path "+addrOne) {
		t.Errorf("an unknown service lost its path:\n%s", text)
	}
	if !strings.Contains(text, "TCP") || !strings.Contains(text, "TLS") {
		t.Errorf("an unknown service lost its stages:\n%s", text)
	}
	// No outcome line: there is no terminal fact this renderer knows to restate,
	// and inventing one would be a claim nobody authorized.
	if strings.Contains(text, "outcome") {
		t.Errorf("an unknown service was given an outcome line:\n%s", text)
	}
	if strings.Contains(text, "topology") {
		t.Errorf("an unknown service was given a topology line:\n%s", text)
	}
}

// TestTheKafkaLabelsAreTheReviewedOnes pins the presentation vocabulary.
func TestTheKafkaLabelsAreTheReviewedOnes(t *testing.T) {
	want := map[domain.Step]string{
		servicekafka.StepAPIVersions:      "Kafka API versions",
		servicekafka.StepSASLHandshake:    "SASL mechanism negotiation",
		servicekafka.StepSASLAuthenticate: "Authentication",
		servicekafka.StepMetadata:         "Kafka metadata",
		servicekafka.StepBrokerAdvertised: "Broker advertisement",
	}
	for step, label := range want {
		if got := stepLabel(step); got != label {
			t.Errorf("stepLabel(%s) = %q, want %q", step, got, label)
		}
	}
}
