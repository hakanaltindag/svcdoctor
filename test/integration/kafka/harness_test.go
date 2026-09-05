//go:build integration

// Package kafka runs svcdoctor against a real Apache Kafka cluster.
//
// It is excluded from `go test ./...` by the integration build tag, because it
// needs the cluster in env/ to be running. See README.md beside this file.
//
// There is no svcdoctor binary yet — internal/app and cmd/svcdoctor hold no Go
// code — so these tests are the composition root: they wire transport, the Kafka
// adapter, diagnosis, the report and redaction in the order a CLI eventually
// will. That is the point. A defect in how the layers compose shows up here and
// nowhere else, because every other test exercises one layer against a fake.
package kafka

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	adapter "github.com/hakanaltindag/svcdoctor/internal/adapter/kafka"
	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	diagnosiskafka "github.com/hakanaltindag/svcdoctor/internal/diagnosis/kafka"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe/dns"
	"github.com/hakanaltindag/svcdoctor/internal/probe/tcp"
	"github.com/hakanaltindag/svcdoctor/internal/probe/transport"
	"github.com/hakanaltindag/svcdoctor/internal/security"
	"github.com/hakanaltindag/svcdoctor/internal/security/redaction"
	servicekafka "github.com/hakanaltindag/svcdoctor/internal/service/kafka"
)

// The cluster in env/compose-sasl.yaml.
const (
	bootstrapHost = "localhost"
	bootstrapPort = 19192

	saslIdentity = "svcdoctor"
	saslSecret   = "svcdoctor-canary-secret"
)

func caPool(t *testing.T) *x509.CertPool {
	t.Helper()
	pem, err := os.ReadFile("env/certs/ca-cert.pem")
	if err != nil {
		t.Fatalf("reading the validation CA (run env/gen-certs.sh): %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("the validation CA did not parse")
	}
	return pool
}

// run is one complete svcdoctor pass against the cluster.
type run struct {
	graph     domain.Graph
	findings  []domain.Finding
	report    domain.Report
	shareable domain.Report
	brokers   []adapter.DiscoveredBroker
	elapsed   time.Duration
}

type options struct {
	host       string
	port       uint16
	identity   string
	secret     string
	pool       *x509.CertPool
	serverName string
	sweep      bool
	mechanism  string
	// stopAfterAuth ends the pass at authentication, for the scenarios that are
	// about the credential rather than the topology.
	stopAfterAuth bool

	// dialer replaces the system dialer, for scenarios that need to observe how
	// many connections were opened. It is still a real TCP dial.
	dialer tcp.Dialer
}

func defaults(t *testing.T) options {
	return options{
		host: bootstrapHost, port: bootstrapPort,
		identity: saslIdentity, secret: saslSecret,
		pool: caPool(t), sweep: true, mechanism: "PLAIN",
	}
}

// pass drives transport -> ApiVersions -> SaslHandshake -> SaslAuthenticate ->
// Metadata -> advertised reachability -> diagnosis -> report -> redaction.
//
// Every step's error is fatal; every step's *outcome* is evidence. That split is
// the adapter's own contract, and a scenario that expects a failure asserts on
// the evidence rather than on an error.
func pass(t *testing.T, o options) *run {
	t.Helper()

	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	builder := domain.NewGraphBuilder()
	tlsOptions := &transport.TLSOptions{RootCAs: o.pool, ServerName: o.serverName}

	dialer := o.dialer
	if dialer == nil {
		dialer = tcp.SystemDialer{}
	}
	paths, err := transport.Run(ctx, builder, transport.Params{
		Host: o.host, Port: o.port,
		Resolver: dns.SystemResolver{}, Dialer: dialer,
		TLS: tlsOptions,
	})
	if err != nil {
		t.Fatalf("transport.Run: %v", err)
	}
	defer func() { _ = paths.Close() }()

	out := &run{}
	finish := func() *run {
		graph, ferr := builder.Freeze()
		if ferr != nil {
			t.Fatalf("Freeze: %v", ferr)
		}
		out.graph = graph
		out.findings = engine().Diagnose(diagnosis.RuleContext{Graph: graph})
		out.report = assemble(t, graph, out.findings, o)
		out.shareable = mustRedact(t, out.report)
		out.elapsed = time.Since(started)
		return out
	}

	if len(paths.Continuations()) == 0 {
		return finish() // transport never reached the broker; the evidence says why
	}

	protocol, err := adapter.Run(ctx, builder, paths.Continuations(), adapter.Params{})
	if err != nil {
		t.Fatalf("kafka.Run: %v", err)
	}
	defer func() { _ = protocol.Close() }()
	if len(protocol.Sessions()) == 0 {
		return finish()
	}

	handshake, err := adapter.SASLHandshake(
		ctx, builder, protocol.Sessions(), adapter.SASLParams{Mechanism: o.mechanism})
	if err != nil {
		t.Fatalf("kafka.SASLHandshake: %v", err)
	}
	defer func() { _ = handshake.Close() }()
	if len(handshake.Sessions()) == 0 {
		return finish()
	}

	endpoint, err := security.NewEndpoint(o.host, o.port)
	if err != nil {
		t.Fatalf("security.NewEndpoint: %v", err)
	}
	credential, err := security.NewCredential(endpoint, o.identity, security.NewSecret(o.secret))
	if err != nil {
		t.Fatalf("security.NewCredential: %v", err)
	}

	auth, err := adapter.Authenticate(
		ctx, builder, handshake.Sessions()[0], credential, adapter.AuthParams{})
	if err != nil {
		t.Fatalf("kafka.Authenticate: %v", err)
	}
	defer func() { _ = auth.Close() }()

	session, ok := auth.Session()
	if !ok || o.stopAfterAuth {
		return finish()
	}

	topology, err := adapter.Metadata(ctx, builder, session, adapter.MetadataParams{})
	if err != nil {
		t.Fatalf("kafka.Metadata: %v", err)
	}
	defer func() { _ = topology.Close() }()
	out.brokers = topology.Brokers()

	if o.sweep {
		measured, merr := adapter.MeasureAdvertised(ctx, builder, out.brokers, adapter.TransportPlan{
			Resolver: dns.SystemResolver{}, Dialer: dialer, TLS: tlsOptions,
			StepTimeout: 5 * time.Second,
		})
		if merr != nil {
			t.Fatalf("kafka.MeasureAdvertised: %v", merr)
		}
		t.Logf("measured %d of %d advertisements", measured.Measured(), measured.Considered())
	}

	return finish()
}

// engine wires both Kafka rules, the way a composition root would.
func engine() diagnosis.Engine {
	// **Every rule internal/diagnosis/kafka exports**, under the identities
	// internal/app registers them with (ADR 0080 sections 2.4 and 2.5).
	//
	// This list said "the two advertised-broker rules" until Phase 10.2, and the
	// comment beside it claimed the harness and the production path "differ in
	// nothing but the graph". That was true when it was written and stopped
	// being true the moment a third Kafka rule existed: the suite went on
	// passing while the new rules were never evaluated against a real cluster at
	// all. The gap is the kind a phase finds only by looking, so the honest
	// statement replaces the convenient one.
	//
	// What it still does **not** wire is the generic set — the failure boundary
	// and the three transport rules — because those own evidence beneath the
	// requested-target anchor rather than beneath an advertisement, and this
	// harness exists to exercise Kafka claims. `composition_test.go` calls
	// `app.DiagnoseKafka` and therefore runs all nine.
	registry, err := diagnosis.NewRuleSet().
		Add("kafka/protocol", diagnosiskafka.Protocol).
		Add("kafka/advertised-endpoint", diagnosiskafka.AdvertisedEndpointUnreachable).
		Add("kafka/unusable-advertisement", diagnosiskafka.UnusableAdvertisement).
		Add("kafka/advertised-topology", diagnosiskafka.AdvertisedTopologyReachability).
		Add("kafka/advertised-suitability", diagnosiskafka.AdvertisedTopologyUnsuitable).
		Freeze()
	if err != nil {
		panic("integration harness: freezing the rule set: " + err.Error())
	}
	return diagnosis.NewEngine(registry)
}

func assemble(t *testing.T, g domain.Graph, f []domain.Finding, o options) domain.Report {
	t.Helper()
	run, err := domain.NewRunMetadata("0.0.0-integration", time.Now(), time.Second, "kafka")
	if err != nil {
		t.Fatal(err)
	}
	target, err := domain.NewTarget(o.host + ":" + strconv.Itoa(int(o.port)))
	if err != nil {
		t.Fatal(err)
	}
	vantage, err := domain.NewLocalVantage("validation-host.svcdoctor.test")
	if err != nil {
		t.Fatal(err)
	}
	sec, err := domain.NewReportSecurity(domain.OutputModeLocalFull, false, false)
	if err != nil {
		t.Fatal(err)
	}
	report, err := domain.NewReport(domain.ReportInput{
		Run: run, Target: target, Vantage: vantage, Graph: g, Findings: f, Security: sec,
	})
	if err != nil {
		t.Fatalf("NewReport: %v", err)
	}
	return report
}

func mustRedact(t *testing.T, r domain.Report) domain.Report {
	t.Helper()
	out, err := redaction.Redact(r)
	if err != nil {
		t.Fatalf("redaction.Redact: %v", err)
	}
	return out
}

// --- inspection helpers -----------------------------------------------------

func (r *run) nodes(step domain.Step) []domain.Evidence {
	var out []domain.Evidence
	for _, n := range r.graph.Nodes() {
		if n.Step() == step {
			out = append(out, n)
		}
	}
	return out
}

func (r *run) byLayer(layer domain.Layer) []domain.Evidence {
	var out []domain.Evidence
	for _, n := range r.graph.Nodes() {
		if n.Layer() == layer {
			out = append(out, n)
		}
	}
	return out
}

// withCode returns the findings carrying one code.
//
// It arrived in Phase 10.2, when the harness began wiring every Kafka rule and
// assertions that had counted *all* findings had to be scoped to the claim they
// were about. Scoping them was the correct move rather than raising the
// expected totals: a test asserting "exactly one finding" was asserting
// something about the reachability claim, not about how many rules exist.
func (r *run) withCode(code domain.FindingCode) []domain.Finding {
	var out []domain.Finding
	for _, f := range r.findings {
		if f.Code() == code {
			out = append(out, f)
		}
	}
	return out
}

func (r *run) codes() []domain.FindingCode {
	out := make([]domain.FindingCode, 0, len(r.findings))
	for _, f := range r.findings {
		out = append(out, f.Code())
	}
	return out
}

func (r *run) advertisedEndpoints() []string {
	var out []string
	for _, n := range r.nodes(servicekafka.StepBrokerAdvertised) {
		out = append(out, n.Subject().Ref())
	}
	return out
}

func (r *run) describe(t *testing.T) {
	t.Helper()
	t.Logf("graph: %d nodes, %d findings, %s", r.graph.Len(), len(r.findings), r.elapsed)
	for _, n := range r.graph.Nodes() {
		class := ""
		if n.FailureClass() != domain.FailureNone {
			class = " " + n.FailureClass().String()
		}
		t.Logf("  %-3s %-6s %-24s %s%s",
			n.Layer(), n.State(), n.Step(), n.Subject().Ref(), class)
	}
	for _, f := range r.findings {
		t.Logf("  FINDING %s %s/%s/%s vantageDependent=%v subject=%s",
			f.Code(), f.Kind(), f.Severity(), f.Confidence(), f.VantageDependent(), f.Subject().Ref())
		t.Logf("          %s", f.Summary())
		for _, ref := range f.EvidenceRefs() {
			node, _ := r.graph.Node(ref)
			t.Logf("          ref %s %s %s", node.Layer(), node.State(), node.Step())
		}
	}
}

// writeArtifact stores a report for the validation record.
func (r *run) writeArtifact(t *testing.T, name string) {
	t.Helper()
	dir := os.Getenv("SVCDOCTOR_ARTIFACTS")
	if dir == "" {
		return
	}
	for suffix, report := range map[string]domain.Report{
		".local.json": r.report, ".shareable.json": r.shareable,
	} {
		encoded, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			t.Fatalf("marshalling %s: %v", name, err)
		}
		if err := os.WriteFile(fmt.Sprintf("%s/%s%s", dir, name, suffix), encoded, 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	encoded, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	return string(encoded)
}
