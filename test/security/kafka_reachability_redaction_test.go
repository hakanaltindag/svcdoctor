package security

import (
	"context"
	cryptotls "crypto/tls"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/twmb/franz-go/pkg/kmsg"

	"github.com/hakanaltindag/svcdoctor/internal/adapter/kafka"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe/transport"
	"github.com/hakanaltindag/svcdoctor/internal/security"
	"github.com/hakanaltindag/svcdoctor/internal/security/redaction"
)

// The end-to-end security check for Phase 3.4: a graph in which one hostname is
// measured twice — once as the bootstrap target and once because the cluster
// advertised it — turned into a report and redacted.
//
// It exercises two things nothing before it did. Transport evidence produced by
// a *scoped* sweep, whose identifier carries a caller-chosen label; and transport
// evidence about endpoints the operator never named, reached by derivation from
// an advertisement rather than from a target.

const (
	// The addresses the advertised canaries resolve to. They appear nowhere
	// else, so finding one in a shareable report is unambiguous.
	reachCanaryIPv4     = "10.81.82.83"
	reachCanaryIPv6     = "2001:db8:beef::1"
	reachCanarySecondIP = "10.84.85.86"
)

// reachSink stands in for the advertised brokers: it accepts connections,
// completes TLS when asked, reads whatever arrives and answers nothing.
//
// It speaks no Kafka on purpose. This phase establishes transport and closes, so
// a peer that could answer a protocol request would be a peer that hides a
// boundary violation instead of exposing it.
type reachSink struct {
	addr netip.AddrPort
}

func newReachSink(t *testing.T, serverTLS *cryptotls.Config) *reachSink {
	t.Helper()

	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback listener unavailable in this environment: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			if serverTLS != nil {
				conn = cryptotls.Server(conn, serverTLS)
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_, _ = io.Copy(io.Discard, conn)
			}()
		}
	}()

	addr, err := netip.ParseAddrPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("parsing the sink address: %v", err)
	}
	return &reachSink{addr: addr}
}

// reachResolver answers per advertised hostname, so the report carries several
// distinct resolved addresses to redact.
type reachResolver struct{}

func (reachResolver) LookupAddresses(_ context.Context, host string) ([]netip.Addr, error) {
	switch host {
	case metadataCanaryBroker1:
		// Dual stack, so both address families reach the report.
		return []netip.Addr{
			netip.MustParseAddr(reachCanaryIPv4),
			netip.MustParseAddr(reachCanaryIPv6),
		}, nil
	case metadataCanaryBroker2:
		return []netip.Addr{netip.MustParseAddr(reachCanarySecondIP)}, nil
	case metadataCanaryIP:
		return []netip.Addr{netip.MustParseAddr(metadataCanaryIP)}, nil
	case authCanaryHost:
		// The bootstrap host, advertised back and measured a second time.
		return []netip.Addr{netip.MustParseAddr(authCanaryAddr)}, nil
	default:
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
}

type reachDialer struct{ target netip.AddrPort }

func (d reachDialer) DialTCP(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", d.target.String())
}

// reachabilityRun performs the whole chain, discovers the topology, and measures
// every advertised endpoint.
//
// The bootstrap host is advertised back, so the run contains two measurements of
// one hostname — the case ADR 0032 exists for, and the one a shareable report
// has never had to carry before.
func reachabilityRun(t *testing.T, withTLS bool) domain.Report {
	t.Helper()

	// The cluster advertises the bootstrap host back, alongside the three
	// canaries. That is routine for a single-listener deployment, and it is what
	// puts two measurements of one hostname into one report.
	bootstrapBroker := kmsg.NewMetadataResponseBroker()
	bootstrapBroker.NodeID, bootstrapBroker.Host, bootstrapBroker.Port = 4, authCanaryHost, 9092

	peer := newAuthPeer(t, false, append(advertisedCanaryBrokers(), bootstrapBroker)...)
	builder := domain.NewGraphBuilder()

	paths, err := transport.Run(context.Background(), builder, transport.Params{
		Host:     authCanaryHost,
		Port:     9092,
		Resolver: authResolver{},
		Dialer:   authDialer{target: peer.addr},
		TLS:      &transport.TLSOptions{RootCAs: peer.pool},
	})
	if err != nil {
		t.Fatalf("transport.Run: %v", err)
	}
	t.Cleanup(func() { _ = paths.Close() })

	protocol, err := kafka.Run(context.Background(), builder, paths.Continuations(), kafka.Params{})
	if err != nil {
		t.Fatalf("kafka.Run: %v", err)
	}
	t.Cleanup(func() { _ = protocol.Close() })

	handshake, err := kafka.SASLHandshake(
		context.Background(), builder, protocol.Sessions(), kafka.SASLParams{Mechanism: "PLAIN"})
	if err != nil {
		t.Fatalf("kafka.SASLHandshake: %v", err)
	}
	t.Cleanup(func() { _ = handshake.Close() })

	sessions := handshake.Sessions()
	if len(sessions) != 1 {
		t.Fatalf("handshake sessions = %d, want 1", len(sessions))
	}

	endpoint, err := security.NewEndpoint(authCanaryHost, 9092)
	if err != nil {
		t.Fatalf("security.NewEndpoint: %v", err)
	}
	credential, err := security.NewCredential(
		endpoint, authCanaryIdentity, security.NewSecret(authCanarySecret))
	if err != nil {
		t.Fatalf("security.NewCredential: %v", err)
	}

	auth, err := kafka.Authenticate(
		context.Background(), builder, sessions[0], credential, kafka.AuthParams{})
	if err != nil {
		t.Fatalf("kafka.Authenticate: %v", err)
	}
	t.Cleanup(func() { _ = auth.Close() })

	session, ok := auth.Session()
	if !ok {
		t.Fatal("the fixture credential was not accepted")
	}

	topology, err := kafka.Metadata(context.Background(), builder, session, kafka.MetadataParams{})
	if err != nil {
		t.Fatalf("kafka.Metadata: %v", err)
	}
	t.Cleanup(func() { _ = topology.Close() })

	brokers := topology.Brokers()
	if len(brokers) != 4 {
		t.Fatalf("brokers = %d, want 4", len(brokers))
	}

	plan := kafka.TransportPlan{Resolver: reachResolver{}, Dialer: reachDialer{}}
	if withTLS {
		// The certificate names one advertised broker, so the other two fail
		// verification. Both outcomes are evidence, and a shareable report has
		// to keep the failure classes while losing the identities.
		cert, pool := authCertificate(t, metadataCanaryBroker1)
		sink := newReachSink(t, &cryptotls.Config{
			Certificates: []cryptotls.Certificate{cert},
			MinVersion:   cryptotls.VersionTLS12,
		})
		plan.Dialer = reachDialer{target: sink.addr}
		plan.TLS = &transport.TLSOptions{RootCAs: pool}
	} else {
		plan.Dialer = reachDialer{target: newReachSink(t, nil).addr}
	}

	measured, err := kafka.MeasureAdvertised(context.Background(), builder, brokers, plan)
	if err != nil {
		t.Fatalf("kafka.MeasureAdvertised: %v", err)
	}
	if measured.Measured() != 4 {
		t.Fatalf("measured = %d, want 4: the fixture sweep did not run", measured.Measured())
	}

	return assembleReport(t, builder)
}

// reachCanaries are every identity the advertised sweeps put into a report.
func reachCanaries() []string {
	return append(topologyCanaries(),
		reachCanaryIPv4, reachCanaryIPv6, reachCanarySecondIP,
		authCanaryHost, authCanaryAddr, authCanaryVantage)
}

// sweepScopeLabels reads the sweep scope out of the report's evidence
// identifiers.
//
// Nothing in production does this, and it is only sound here because the test
// knows what it is looking for: the point is to prove the value is present in
// one report and gone from the other, which needs the value in hand.
func sweepScopeLabels(t *testing.T, report domain.Report) []string {
	t.Helper()

	seen := map[string]struct{}{}
	var labels []string
	for _, evidence := range report.Graph().Nodes() {
		for _, component := range strings.Split(evidence.ID().String(), "/") {
			if !strings.HasPrefix(component, "advertised.") {
				continue
			}
			if _, duplicate := seen[component]; duplicate {
				continue
			}
			seen[component] = struct{}{}
			labels = append(labels, component)
		}
	}
	return labels
}

// TestTheReachabilityCanariesActuallyTravel is the precondition for the leak
// matrix: values that never entered the local report prove nothing by being
// absent from the shareable one.
func TestTheReachabilityCanariesActuallyTravel(t *testing.T) {
	report := reachabilityRun(t, false)
	encoded := canonicalJSON(t, report)

	for _, canary := range reachCanaries() {
		if !strings.Contains(encoded, canary) {
			t.Errorf("the local report does not contain %q", canary)
		}
	}

	scopes := sweepScopeLabels(t, report)
	if len(scopes) != 4 {
		t.Fatalf("sweep scopes = %v, want one per advertisement", scopes)
	}
	for _, scope := range scopes {
		if !strings.Contains(encoded, scope) {
			t.Errorf("the local report does not contain the scope %q", scope)
		}
	}
}

// TestShareableReachabilityReportLeaksNothing is the leak matrix for transport
// evidence about endpoints the operator never named.
func TestShareableReachabilityReportLeaksNothing(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		withTLS bool
	}{
		{"plaintext", false},
		{"tls", true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			local := reachabilityRun(t, testCase.withTLS)
			scopes := sweepScopeLabels(t, local)

			shareable, err := redaction.Redact(local)
			if err != nil {
				t.Fatalf("Redact: %v", err)
			}
			encoded := canonicalJSON(t, shareable)

			forbidden := append(reachCanaries(), credentialCanaries()...)
			forbidden = append(forbidden, scopes...)

			for _, canary := range forbidden {
				if strings.Contains(encoded, canary) {
					t.Errorf("the shareable report leaks %q:\n%s", canary, encoded)
				}
			}
		})
	}
}

// TestTheSweepScopeGoesWithTheIdentifiers.
//
// A scope is caller-chosen text that reaches exactly one place — the evidence
// identifier — and identifiers are remapped wholesale in a shareable report. So
// no new redaction rule was needed, and this is the proof of that claim rather
// than a restatement of it.
func TestTheSweepScopeGoesWithTheIdentifiers(t *testing.T) {
	local := reachabilityRun(t, false)
	scopes := sweepScopeLabels(t, local)
	if len(scopes) == 0 {
		t.Fatal("no scoped identifiers were produced")
	}

	shareable, err := redaction.Redact(local)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}

	for _, evidence := range shareable.Graph().Nodes() {
		for _, scope := range scopes {
			if strings.Contains(evidence.ID().String(), scope) {
				t.Errorf("%s still carries the scope %q", evidence.ID(), scope)
			}
			if strings.Contains(evidence.Subject().Ref(), scope) {
				t.Errorf("%s carries the scope in its subject", evidence.ID())
			}
			for key, value := range evidence.Attributes() {
				if strings.Contains(string(key)+value.String(), scope) {
					t.Errorf("%s carries the scope in attribute %s", evidence.ID(), key)
				}
			}
		}
	}
}

// TestReachabilityStructureSurvivesRedaction is the other half: a shared report
// must still say what was measured about the cluster's own brokers, because that
// is the reason to share it.
func TestReachabilityStructureSurvivesRedaction(t *testing.T) {
	local := reachabilityRun(t, true)

	shareable, err := redaction.Redact(local)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	graph := shareable.Graph()

	// The advertisement nodes still parent the transport that measured them, so
	// "which advertised broker was this?" survives identifier remapping as a
	// relationship even though every identifier changed.
	advertisements := map[domain.EvidenceID]int64{}
	for _, evidence := range graph.Nodes() {
		if evidence.Step() != kafka.StepBrokerAdvertised {
			continue
		}
		nodeID, ok := evidence.Attribute(kafka.AttrBrokerNodeID)
		if !ok {
			t.Fatalf("%s lost its node identifier", evidence.ID())
		}
		value, _ := nodeID.Int()
		advertisements[evidence.ID()] = value
	}
	if len(advertisements) != 4 {
		t.Fatalf("advertisements = %d, want 4", len(advertisements))
	}

	// The transport root of a sweep is its DNS node when the advertisement named
	// a name, and its connection node when it named an address: node 3 advertises
	// 10.71.72.73, nothing was resolved for it, and no L1 node exists (ADR 0059).
	// Both roots carry the derivation edge, so the relationship survives for
	// either kind of advertisement.
	measured := map[int64]bool{}
	layers := map[domain.Layer]int{}
	for _, evidence := range graph.Nodes() {
		if evidence.Layer() != domain.LayerDNS && evidence.Layer() != domain.LayerTCP {
			continue
		}
		for _, parent := range graph.Parents(evidence.ID()) {
			if nodeID, ok := advertisements[parent]; ok {
				measured[nodeID] = true
			}
		}
	}
	for _, want := range []int64{1, 2, 3, 4} {
		if !measured[want] {
			t.Errorf("the sweep of advertised node %d lost its derivation edge", want)
		}
	}

	// The transport layers, the failure classes and the timings survive: they
	// carry no identity and they are the finding a reader is being shown.
	verified, failed := 0, 0
	for _, evidence := range graph.Nodes() {
		layers[evidence.Layer()]++
		if evidence.Layer() != domain.LayerTLS {
			continue
		}
		switch evidence.State() {
		case domain.StatePass:
			verified++
		case domain.StateFail:
			failed++
		}
	}
	if layers[domain.LayerDNS] == 0 || layers[domain.LayerTCP] == 0 || layers[domain.LayerTLS] == 0 {
		t.Errorf("transport layers did not survive redaction: %v", layers)
	}
	if verified == 0 {
		t.Error("no verified handshake survived redaction")
	}
	if failed == 0 {
		t.Error("no rejected handshake survived redaction; the failure classes are the finding")
	}
}

// TestBootstrapAndAdvertisedMeasurementsBothSurvive.
//
// The bootstrap host is advertised back, so the local report holds two
// measurements of one hostname. Redaction must keep both: collapsing them onto
// one pseudonymized node would erase a measurement, and the disagreement between
// two measurements of one host is exactly what a diagnostic tool exists to show.
func TestBootstrapAndAdvertisedMeasurementsBothSurvive(t *testing.T) {
	local := reachabilityRun(t, false)

	before := countLookups(local.Graph())
	shareable, err := redaction.Redact(local)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	after := countLookups(shareable.Graph())

	if before != after {
		t.Errorf("dns nodes = %d after redaction, want the %d the local report had",
			after, before)
	}
	// One bootstrap lookup plus one per advertised broker that named a *name*.
	// Node 3 advertises 10.71.72.73 and resolves nothing, so it contributes no
	// L1 node at all (ADR 0059) — which is the point: the count is 4 rather than
	// 5 because no lookup was invented for an address that was already in hand.
	if before != 4 {
		t.Fatalf("dns nodes = %d, want 4: the fixture did not measure what this test needs",
			before)
	}

	// Two of them describe the same pseudonymized host, and they are still two.
	subjects := map[string]int{}
	for _, evidence := range shareable.Graph().Nodes() {
		if evidence.Layer() == domain.LayerDNS {
			subjects[evidence.Subject().Ref()]++
		}
	}
	repeated := 0
	for _, count := range subjects {
		if count > 1 {
			repeated++
		}
	}
	if repeated != 1 {
		t.Errorf("subjects = %v, want one host measured twice", subjects)
	}
}

func countLookups(graph domain.Graph) int {
	count := 0
	for _, evidence := range graph.Nodes() {
		if evidence.Layer() == domain.LayerDNS {
			count++
		}
	}
	return count
}
