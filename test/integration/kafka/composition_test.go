//go:build integration

package kafka

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/app"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe/dns"
	"github.com/hakanaltindag/svcdoctor/internal/probe/tcp"
	"github.com/hakanaltindag/svcdoctor/internal/probe/transport"
	"github.com/hakanaltindag/svcdoctor/internal/security"
	"github.com/hakanaltindag/svcdoctor/internal/security/redaction"
	servicekafka "github.com/hakanaltindag/svcdoctor/internal/service/kafka"
	"github.com/hakanaltindag/svcdoctor/internal/vocabulary"
)

// `app.DiagnoseKafka` against the real three-broker KRaft cluster.
//
// # Why this file exists beside the rest of the suite
//
// Every other test here calls `pass`, a harness that wires transport, the
// adapter, diagnosis, the report and redaction itself — because until Phase
// 6.1c there was no composition root to call, and the harness *was* the
// composition. It stays: it can reach shapes the production root deliberately
// cannot, such as stopping after authentication.
//
// These tests call the production entry point instead. That is the difference
// that matters: a defect in what `DiagnoseKafka` sequences, selects, closes or
// wires is invisible to a harness that sequences it differently, and this is the
// only place a real cluster meets the real composition.
//
// The unit suites fake the network at the resolver and dialer seams. Nothing is
// faked here.

// diagnose runs the production composition against the validation cluster.
func diagnose(t *testing.T, o options) app.Result {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	vantage, err := domain.NewLocalVantage("validation-host.svcdoctor.test")
	if err != nil {
		t.Fatalf("NewLocalVantage: %v", err)
	}

	var credential security.Credential
	if o.identity != "" {
		endpoint, eerr := security.NewEndpoint(o.host, o.port)
		if eerr != nil {
			t.Fatalf("security.NewEndpoint: %v", eerr)
		}
		credential, err = security.NewCredential(endpoint, o.identity, security.NewSecret(o.secret))
		if err != nil {
			t.Fatalf("security.NewCredential: %v", err)
		}
	}

	result, err := app.DiagnoseKafka(ctx, app.KafkaParams{
		Host: o.host, Port: o.port,
		Mechanism:  o.mechanism,
		Credential: credential,
		Resolver:   dns.SystemResolver{},
		Dialer:     tcp.SystemDialer{},
		TLS:        &transport.TLSOptions{RootCAs: o.pool, ServerName: o.serverName},
		// Bounded, so a black-holed advertised address cannot consume the budget
		// every later advertisement needs.
		StepTimeout: 10 * time.Second,
		Vantage:     vantage,
		Version:     "0.0.0-integration",
	})
	if err != nil {
		t.Fatalf("DiagnoseKafka: %v", err)
	}
	return result
}

func composed(t *testing.T) options {
	t.Helper()
	o := defaults(t)
	return o
}

// nodesOf returns every node of one step in a composed report.
func nodesOf(r app.Result, step domain.Step) []domain.Evidence {
	var out []domain.Evidence
	for _, n := range r.Report().Graph().Nodes() {
		if n.Step() == step {
			out = append(out, n)
		}
	}
	return out
}

func codesOf(r app.Result) []domain.FindingCode {
	out := make([]domain.FindingCode, 0, r.Report().FindingCount())
	for _, f := range r.Report().Findings() {
		out = append(out, f.Code())
	}
	return out
}

// TestTheProductionCompositionWalksTheWholeJourney is the Phase 6.1c
// integration gate.
//
// One socket carries the requested-target anchor, DNS, TCP, TLS, ApiVersions,
// the SASL handshake, authentication and Metadata; the advertisements the
// cluster returns are then measured at transport. Nothing here is faked.
func TestTheProductionCompositionWalksTheWholeJourney(t *testing.T) {
	result := diagnose(t, composed(t))
	logComposed(t, result)

	for _, step := range []domain.Step{
		vocabulary.StepTargetRequested,
		vocabulary.StepDNSLookup,
		vocabulary.StepTCPConnect,
		vocabulary.StepTLSHandshake,
		servicekafka.StepAPIVersions,
		servicekafka.StepSASLHandshake,
		servicekafka.StepSASLAuthenticate,
		servicekafka.StepMetadata,
	} {
		nodes := nodesOf(result, step)
		if len(nodes) == 0 {
			t.Fatalf("%s produced no node; the journey did not reach it", step)
		}
		passed := slices.ContainsFunc(nodes, func(n domain.Evidence) bool {
			return n.State() == domain.StatePass
		})
		if !passed {
			t.Errorf("%s has no PASS node: %s/%s",
				step, nodes[0].State(), nodes[0].FailureClass())
		}
	}

	// The terminal fact of ADR 0052's core journey, and the only thing a passing
	// Metadata node claims.
	if len(nodesOf(result, servicekafka.StepMetadata)) != 1 {
		t.Errorf("kafka.metadata nodes = %d, want exactly 1",
			len(nodesOf(result, servicekafka.StepMetadata)))
	}
	if got := len(nodesOf(result, servicekafka.StepBrokerAdvertised)); got != 3 {
		t.Errorf("advertisements = %d, want 3", got)
	}
}

// TestOneCredentialReachesOneBrokerOnARealCluster is the credential-cardinality
// proof against real sockets.
//
// The bootstrap name may resolve to several addresses, and every one of them is
// measured through ApiVersions and the SASL handshake. **Exactly one
// authentication node exists**, whatever the resolver returned.
func TestOneCredentialReachesOneBrokerOnARealCluster(t *testing.T) {
	result := diagnose(t, composed(t))

	auth := nodesOf(result, servicekafka.StepSASLAuthenticate)
	if len(auth) != 1 {
		t.Fatalf("kafka.sasl_authenticate nodes = %d, want exactly 1.\n\n"+
			"One credential, one attempt, whatever the target resolved to. "+
			"See ADR 0028.", len(auth))
	}
	if auth[0].State() != domain.StatePass {
		t.Errorf("authentication = %s/%s, want PASS", auth[0].State(), auth[0].FailureClass())
	}

	// Discovery was still broad: the handshake ran on every completed path, and
	// costs the broker no authentication attempt.
	if len(nodesOf(result, servicekafka.StepSASLHandshake)) <
		len(nodesOf(result, servicekafka.StepAPIVersions)) {
		t.Error("the SASL handshake did not run on every path that answered ApiVersions")
	}
}

// TestRealAdvertisedBrokersAreMeasuredOnlyAtTransport is ADR 0050 against a real
// cluster.
//
// The validation cluster advertises internal hostnames, so from this vantage the
// sweeps mostly fail — which is exactly the interesting case: a failing
// advertised endpoint must still receive **only** DNS, TCP and TLS, and must
// still be explained by a finding rather than by silence.
func TestRealAdvertisedBrokersAreMeasuredOnlyAtTransport(t *testing.T) {
	result := diagnose(t, composed(t))
	graph := result.Report().Graph()

	allowed := []domain.Step{
		vocabulary.StepDNSLookup, vocabulary.StepTCPConnect, vocabulary.StepTLSHandshake,
	}
	measured := 0
	for _, advertisement := range nodesOf(result, servicekafka.StepBrokerAdvertised) {
		for _, id := range descendantsOf(graph, advertisement.ID()) {
			node, _ := graph.Node(id)
			measured++
			if !slices.Contains(allowed, node.Step()) {
				t.Errorf("advertised sweep produced %s beneath %s.\n\n"+
					"No ApiVersions, no SaslHandshake, no SaslAuthenticate and no "+
					"second Metadata reaches a discovered broker. See ADR 0050.",
					node.Step(), advertisement.Subject().Ref())
			}
		}
	}
	if measured == 0 {
		t.Fatal("no advertised endpoint was measured at all")
	}

	// Whatever the sweeps found is owned. An unreachable advertised broker is a
	// finding, never a silent gap.
	unreachable := 0
	for _, f := range result.Report().Findings() {
		if f.Code() == "KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE" {
			unreachable++
		}
	}
	t.Logf("advertised sweep nodes=%d unreachable findings=%d codes=%v",
		measured, unreachable, codesOf(result))
}

// TestARealWrongCredentialIsAProblemAndNotSilence is the outcome that stopped
// the first attempt at this phase, measured against a real broker's refusal.
func TestARealWrongCredentialIsAProblemAndNotSilence(t *testing.T) {
	o := composed(t)
	o.secret = "definitely-not-the-password"

	result := diagnose(t, o)

	auth := nodesOf(result, servicekafka.StepSASLAuthenticate)
	if len(auth) != 1 {
		t.Fatalf("kafka.sasl_authenticate nodes = %d, want 1", len(auth))
	}
	if auth[0].State() != domain.StateFail ||
		auth[0].FailureClass() != domain.FailureAuthCredentialsRejected {
		t.Errorf("authentication = %s/%s, want FAIL/AUTH_CREDENTIALS_REJECTED",
			auth[0].State(), auth[0].FailureClass())
	}
	if result.Report().Summary().Status() == domain.SummaryStatusOK {
		t.Error("a real broker refused the credential and the report says OK")
	}
	if result.Report().FindingCount() == 0 {
		t.Error("a rejected credential produced no finding")
	}
	if result.Incomplete() {
		t.Error("the broker answered; svcdoctor finished. This is a complete run")
	}
	// The broker's own error message never leaves the wire package.
	if strings.Contains(mustJSON(t, result.Report()), "definitely-not-the-password") {
		t.Fatal("the report contains the presented secret")
	}
}

// TestARealRunWithNoCredentialSaysSoAndStaysOK is the Kafka twin of the
// PostgreSQL credential-not-configured invariant, on a listener that really does
// demand SASL.
//
// Three facts must be separately visible: status OK, a complete run, and no
// metadata obtained.
func TestARealRunWithNoCredentialSaysSoAndStaysOK(t *testing.T) {
	o := composed(t)
	o.identity, o.secret = "", ""

	result := diagnose(t, o)

	auth := nodesOf(result, servicekafka.StepSASLAuthenticate)
	if len(auth) != 1 {
		t.Fatalf("kafka.sasl_authenticate nodes = %d, want 1", len(auth))
	}
	if auth[0].State() != domain.StateSkipped ||
		auth[0].FailureClass() != domain.FailureExecRequiredInputMissing {
		t.Errorf("authentication = %s/%s, want SKIPPED/EXEC_REQUIRED_INPUT_MISSING",
			auth[0].State(), auth[0].FailureClass())
	}
	if result.Report().Summary().Status() != domain.SummaryStatusOK {
		t.Errorf("status = %s, want OK: nothing about the target was proven wrong",
			result.Report().Summary().Status())
	}
	if result.Incomplete() {
		t.Error("a run that answered the question it was asked is not incomplete")
	}
	if len(nodesOf(result, servicekafka.StepMetadata)) != 0 {
		t.Error("Kafka metadata was obtained without a credential")
	}
	if !slices.Contains(codesOf(result), "KAFKA_CREDENTIAL_NOT_CONFIGURED") {
		t.Errorf("no KAFKA_CREDENTIAL_NOT_CONFIGURED finding; got %v", codesOf(result))
	}
}

// TestARealMechanismTheClusterDoesNotOfferStopsAtTheHandshake asks the
// validation cluster for a mechanism it does not offer.
//
// # What this cluster can and cannot exercise
//
// The listener offers **PLAIN only**, so asking for SCRAM-SHA-256 is refused at
// the handshake with `UNSUPPORTED_SASL_MECHANISM` and no session survives.
// Authentication is therefore never entered, and there is no
// `kafka.sasl_authenticate` node at all.
//
// **That means Phase 6.1a's mechanism guard is not reachable here**, and saying
// so is the point of this comment. The guard fires only when a broker *accepts*
// a mechanism svcdoctor cannot perform — UNKNOWN + `AUTH_MECHANISM_UNSUPPORTED`
// — which needs a listener advertising SCRAM. This fixture has none, so that
// branch is covered where it can be: `TestAnUnsupportedMechanismSendsNothing` in
// test/security, against a peer configured to offer SCRAM-SHA-256 and accept it.
//
// What this test does prove, on real sockets, is the half the cluster can reach:
// a mechanism the endpoint does not offer stops the journey at L5, is owned by a
// finding rather than by silence, costs zero authentication attempts, and leaves
// the run complete rather than incomplete.
func TestARealMechanismTheClusterDoesNotOfferStopsAtTheHandshake(t *testing.T) {
	o := composed(t)
	o.mechanism = "SCRAM-SHA-256"

	result := diagnose(t, o)

	handshake := nodesOf(result, servicekafka.StepSASLHandshake)
	if len(handshake) == 0 {
		t.Fatal("the run never reached the SASL handshake")
	}
	if handshake[0].State() != domain.StateFail ||
		handshake[0].FailureClass() != domain.FailureAuthMechanismNotOffered {
		t.Errorf("handshake = %s/%s, want FAIL/AUTH_MECHANISM_NOT_OFFERED",
			handshake[0].State(), handshake[0].FailureClass())
	}

	// No authentication was attempted, so no credential was presented.
	if got := len(nodesOf(result, servicekafka.StepSASLAuthenticate)); got != 0 {
		t.Errorf("kafka.sasl_authenticate nodes = %d, want 0: the broker never "+
			"agreed to a mechanism, so nothing could be presented", got)
	}
	if got := len(nodesOf(result, servicekafka.StepMetadata)); got != 0 {
		t.Errorf("kafka.metadata nodes = %d, want 0", got)
	}

	// Owned, not silent. Phase 6.1c-P2's table covers the handshake outcome.
	if !slices.Contains(codesOf(result), "KAFKA_AUTH_MECHANISM_NOT_OFFERED") {
		t.Errorf("no KAFKA_AUTH_MECHANISM_NOT_OFFERED finding; got %v", codesOf(result))
	}
	if result.Incomplete() {
		t.Error("the endpoint answered; this is a complete run")
	}
}

// TestAComposedRealReportRedactsWithoutLeaking runs the output boundary over a
// graph only the production composition against a real cluster can produce.
func TestAComposedRealReportRedactsWithoutLeaking(t *testing.T) {
	result := diagnose(t, composed(t))
	local := result.Report()

	// **Without this the test passes on an empty graph.** It was written with the
	// canary scan alone, and a broken fixture — certificates regenerated against
	// already-running brokers, so every handshake failed — produced a six-node
	// report that leaked nothing because it contained nothing. A leak test whose
	// precondition is unasserted reports "no leak" for "no data".
	if len(nodesOf(result, servicekafka.StepMetadata)) != 1 {
		t.Fatalf("the run did not obtain Kafka metadata, so there is nothing to "+
			"redact and this test proves nothing. Graph: %d nodes, findings %v",
			local.Graph().Len(), codesOf(result))
	}
	if len(nodesOf(result, servicekafka.StepBrokerAdvertised)) == 0 {
		t.Fatal("the run recorded no advertisement; the advertised identities this " +
			"test exists to check are absent")
	}

	shareable, err := redaction.Redact(local)
	if err != nil {
		t.Fatalf("redaction.Redact: %v", err)
	}
	encoded := mustJSON(t, shareable)

	// **`saslIdentity` is deliberately not scanned for, and that is a statement
	// about the canary rather than about redaction.** Its value on this cluster
	// is "svcdoctor", which is also the project name, the module path, the
	// vantage label and a word in several recommendations — so finding it proves
	// nothing and not finding it would be luck. A canary has to be distinctive
	// enough that a hit is evidence. Identity absence is asserted where a
	// distinctive one exists: `identityCanary` in
	// test/security/kafka_composition_test.go, over the same composed shape.
	for _, canary := range []string{saslSecret, bootstrapHost} {
		if strings.Contains(encoded, canary) {
			t.Errorf("the shareable report leaks %q", canary)
		}
	}
	for _, advertisement := range nodesOf(result, servicekafka.StepBrokerAdvertised) {
		host, _, found := strings.Cut(advertisement.Subject().Ref(), ":")
		if found && host != "" && strings.Contains(encoded, host) {
			t.Errorf("the shareable report leaks the advertised host %q", host)
		}
	}

	if shareable.Graph().Len() != local.Graph().Len() {
		t.Errorf("shareable graph has %d nodes, local has %d",
			shareable.Graph().Len(), local.Graph().Len())
	}
	if !slices.Equal(findingCodesOf(shareable), findingCodesOf(local)) {
		t.Error("redaction changed the diagnosis")
	}

	again, err := redaction.Redact(shareable)
	if err != nil {
		t.Fatalf("redacting a redacted report: %v", err)
	}
	if mustJSON(t, again) != encoded {
		t.Error("redaction is not idempotent over a composed report")
	}
}

func findingCodesOf(r domain.Report) []domain.FindingCode {
	out := make([]domain.FindingCode, 0, r.FindingCount())
	for _, f := range r.Findings() {
		out = append(out, f.Code())
	}
	return out
}

func descendantsOf(graph domain.Graph, root domain.EvidenceID) []domain.EvidenceID {
	var out []domain.EvidenceID
	seen := map[domain.EvidenceID]bool{}

	var walk func(domain.EvidenceID)
	walk = func(id domain.EvidenceID) {
		for _, child := range graph.Children(id) {
			if seen[child] {
				continue
			}
			seen[child] = true
			out = append(out, child)
			walk(child)
		}
	}
	walk(root)
	return out
}

func logComposed(t *testing.T, r app.Result) {
	t.Helper()
	t.Logf("composed run: %d nodes, %d findings, status=%s incomplete=%v",
		r.Report().Graph().Len(), r.Report().FindingCount(),
		r.Report().Summary().Status(), r.Incomplete())
	for _, n := range r.Report().Graph().Nodes() {
		class := ""
		if n.FailureClass() != domain.FailureNone {
			class = " " + n.FailureClass().String()
		}
		t.Logf("  %-3s %-7s %-24s %s%s",
			n.Layer(), n.State(), n.Step(), n.Subject().Ref(), class)
	}
	for _, f := range r.Report().Findings() {
		t.Logf("  FINDING %s %s/%s @ %s", f.Code(), f.Severity(), f.Confidence(),
			f.Subject().Ref())
	}
	_ = json.Marshal
}
