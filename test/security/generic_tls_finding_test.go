package security

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	cryptotls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	diagnosistransport "github.com/hakanaltindag/svcdoctor/internal/diagnosis/transport"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe"
	"github.com/hakanaltindag/svcdoctor/internal/probe/transport"
	"github.com/hakanaltindag/svcdoctor/internal/security/redaction"
	"github.com/hakanaltindag/svcdoctor/internal/vocabulary"
)

// Real-socket coverage for ADR 0053's generic requested-target TLS findings.
//
// The unit tests in internal/diagnosis/transport drive the rule over hand-built
// graphs, which is the only way to reach shapes no producer makes. These drive it
// over graphs a **real TLS handshake against a real loopback listener** produced,
// so the rule is exercised against the evidence internal/probe/tls actually
// writes rather than against a test's idea of it.
//
// Two classes are reachable honestly here and are covered:
//
//	TLS_HOSTNAME_MISMATCH  -> TLS_IDENTITY_MISMATCH
//	TLS_UNKNOWN_AUTHORITY  -> TLS_CHAIN_NOT_TRUSTED
//
// Expired and not-yet-valid certificates, a version mismatch and the
// client-certificate classes are **not** faked here. The first two would need a
// certificate minted outside its own validity window, and the rest have no
// producer at all; a fixture asserting them would be testing the fixture.

const (
	genericTLSHost    = "tls-canary.prod.internal"
	genericTLSAddress = "10.51.52.53"
	genericTLSOther   = "tls-other-canary.prod.internal"
	genericTLSVantage = "tls-runner-canary.local"
)

// genericTLSResolver answers with one address, so each test has exactly one
// endpoint to reason about.
type genericTLSResolver struct{}

func (genericTLSResolver) LookupAddresses(_ context.Context, _ string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr(genericTLSAddress)}, nil
}

// genericTLSDialer routes the canary address to the real loopback peer.
type genericTLSDialer struct {
	target netip.AddrPort
}

func (d genericTLSDialer) DialTCP(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", d.target.String())
}

// genericTLSPeer starts a loopback TLS listener whose leaf certificate names
// commonName, and returns its address with the pool that trusts its CA.
func genericTLSPeer(t *testing.T, commonName string) (netip.AddrPort, *x509.CertPool) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "svcdoctor generic tls test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate,
		&caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("creating CA certificate: %v", err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parsing CA certificate: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating leaf key: %v", err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: commonName},
		DNSNames:     []string{commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca,
		&leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("creating leaf certificate: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(ca)

	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				server := cryptotls.Server(conn, &cryptotls.Config{
					Certificates: []cryptotls.Certificate{{
						Certificate: [][]byte{leafDER},
						PrivateKey:  leafKey,
					}},
					MinVersion: cryptotls.VersionTLS12,
				})
				_ = server.HandshakeContext(context.Background())
				_ = server.Close()
			}()
		}
	}()

	addr, err := netip.ParseAddrPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("parsing listener address: %v", err)
	}
	return addr, pool
}

// genericTLSGraph runs the real transport chain against a real TLS peer and
// returns the frozen graph, anchored to a requested target the way internal/app
// anchors one.
func genericTLSGraph(t *testing.T, peerAddr netip.AddrPort, pool *x509.CertPool) domain.Graph {
	t.Helper()

	builder := domain.NewGraphBuilder()
	anchor := genericTLSAnchor(t, builder)

	result, err := transport.Run(context.Background(), builder, transport.Params{
		Host:     genericTLSHost,
		Port:     9093,
		Resolver: genericTLSResolver{},
		Dialer:   genericTLSDialer{target: peerAddr},
		TLS:      &transport.TLSOptions{RootCAs: pool},
		Parent:   anchor,
	})
	if err != nil {
		t.Fatalf("transport.Run: %v", err)
	}
	t.Cleanup(func() { _ = result.Close() })

	graph, err := builder.Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}
	return graph
}

// genericTLSAnchor mints the requested-target node the sweep hangs from, in the
// shape internal/app produces.
func genericTLSAnchor(t *testing.T, builder *domain.GraphBuilder) domain.EvidenceID {
	t.Helper()

	label := genericTLSHost + ":9093"
	subject, err := domain.NewTargetSubject(label)
	if err != nil {
		t.Fatalf("NewTargetSubject: %v", err)
	}
	evidence, err := domain.NewEvidence(domain.EvidenceInput{
		ID:        probe.EvidenceID(vocabulary.StepTargetRequested, label),
		Subject:   subject,
		Layer:     domain.LayerInput,
		Step:      vocabulary.StepTargetRequested,
		State:     domain.StatePass,
		StartedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	if err := builder.AddEvidence(evidence); err != nil {
		t.Fatalf("AddEvidence: %v", err)
	}
	return evidence.ID()
}

// TestRealHandshakeIdentityMismatchProducesTheGenericFinding drives the rule over
// a graph a real failed handshake produced.
//
// The peer's certificate names a different host, so internal/probe/tls records
// TLS_HOSTNAME_MISMATCH — measured, not asserted — and the rule must turn it into
// TLS_IDENTITY_MISMATCH scoped to the concrete endpoint.
func TestRealHandshakeIdentityMismatchProducesTheGenericFinding(t *testing.T) {
	peerAddr, pool := genericTLSPeer(t, genericTLSOther)
	graph := genericTLSGraph(t, peerAddr, pool)

	requireHandshakeClass(t, graph, domain.FailureTLSHostnameMismatch)

	findings := diagnosis.NewEngine(diagnosistransport.TLS).Diagnose(graph)
	finding := requireSingleFinding(t, findings, "TLS_IDENTITY_MISMATCH")

	if got := finding.Subject().Ref(); !strings.Contains(got, genericTLSAddress) {
		t.Errorf("subject = %q, want the concrete endpoint %s", got, genericTLSAddress)
	}
	if got := finding.Severity(); got != domain.SeverityError {
		t.Errorf("severity = %s, want ERROR", got)
	}
	if !finding.VantageDependent() {
		t.Error("vantageDependent = false")
	}
	for _, ref := range finding.EvidenceRefs() {
		if _, ok := graph.Node(ref); !ok {
			t.Errorf("ref %s does not resolve in the graph the chain produced", ref)
		}
	}
}

// TestRealHandshakeUnknownAuthorityProducesTheGenericFinding is the same, with a
// trust context that does not contain the peer's CA.
func TestRealHandshakeUnknownAuthorityProducesTheGenericFinding(t *testing.T) {
	peerAddr, _ := genericTLSPeer(t, genericTLSHost)
	// An empty pool: the chain the peer serves is real and this run trusts none
	// of it, which is exactly what the finding claims.
	graph := genericTLSGraph(t, peerAddr, x509.NewCertPool())

	requireHandshakeClass(t, graph, domain.FailureTLSUnknownAuthority)

	findings := diagnosis.NewEngine(diagnosistransport.TLS).Diagnose(graph)
	requireSingleFinding(t, findings, "TLS_CHAIN_NOT_TRUSTED")
}

// TestRealHandshakePassProducesNoFinding is the base case over a real socket.
func TestRealHandshakePassProducesNoFinding(t *testing.T) {
	peerAddr, pool := genericTLSPeer(t, genericTLSHost)
	graph := genericTLSGraph(t, peerAddr, pool)

	requireHandshakeState(t, graph, domain.StatePass)

	if findings := diagnosis.NewEngine(diagnosistransport.TLS).Diagnose(graph); len(findings) != 0 {
		t.Fatalf("a successful handshake produced %d findings, want none", len(findings))
	}
}

// TestGenericTLSFindingSurvivesRedaction proves the shareable projection keeps
// the diagnosis and drops the identity, using the existing machinery only.
func TestGenericTLSFindingSurvivesRedaction(t *testing.T) {
	peerAddr, pool := genericTLSPeer(t, genericTLSOther)
	graph := genericTLSGraph(t, peerAddr, pool)

	findings := diagnosis.NewEngine(diagnosistransport.TLS).Diagnose(graph)
	local := genericTLSReport(t, graph, findings)
	before := requireSingleFinding(t, local.Findings(), "TLS_IDENTITY_MISMATCH")

	shareable, err := redaction.Redact(local)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	after := requireSingleFinding(t, shareable.Findings(), "TLS_IDENTITY_MISMATCH")

	// The claim is unchanged.
	if after.Code() != before.Code() {
		t.Errorf("code changed under redaction: %s -> %s", before.Code(), after.Code())
	}
	if after.Severity() != before.Severity() {
		t.Errorf("severity changed: %s -> %s", before.Severity(), after.Severity())
	}
	if after.Confidence() != before.Confidence() {
		t.Errorf("confidence changed: %s -> %s", before.Confidence(), after.Confidence())
	}
	if after.Layer() != before.Layer() {
		t.Errorf("layer changed: %s -> %s", before.Layer(), after.Layer())
	}
	if after.VantageDependent() != before.VantageDependent() {
		t.Error("vantageDependent changed under redaction")
	}
	if len(after.EvidenceRefs()) != len(before.EvidenceRefs()) {
		t.Errorf("refs = %d, want %d", len(after.EvidenceRefs()), len(before.EvidenceRefs()))
	}
	for _, ref := range after.EvidenceRefs() {
		if _, ok := shareable.Graph().Node(ref); !ok {
			t.Errorf("ref %s does not resolve in the redacted graph", ref)
		}
	}

	// The identity is gone, from the subject and from every word of the prose.
	encoded, err := shareable.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	for _, canary := range []string{
		genericTLSHost, genericTLSOther, genericTLSAddress, genericTLSVantage,
	} {
		if strings.Contains(string(encoded), canary) {
			t.Errorf("the shareable report still contains %q", canary)
		}
	}

	// Idempotent: redacting a redacted report changes nothing further.
	again, err := redaction.Redact(shareable)
	if err == nil {
		second, mErr := again.MarshalJSON()
		if mErr != nil {
			t.Fatalf("MarshalJSON: %v", mErr)
		}
		if string(second) != string(encoded) {
			t.Error("redaction is not idempotent for a generic TLS finding")
		}
	}
}

// --- helpers -----------------------------------------------------------------

func requireHandshakeClass(t *testing.T, graph domain.Graph, want domain.FailureClass) {
	t.Helper()

	for _, node := range graph.Nodes() {
		if node.Step() != vocabulary.StepTLSHandshake {
			continue
		}
		if node.State() != domain.StateFail {
			t.Fatalf("handshake state = %s, want FAIL", node.State())
		}
		if node.FailureClass() != want {
			t.Fatalf("handshake class = %s, want %s; the fixture no longer produces "+
				"the outcome this test is about", node.FailureClass(), want)
		}
		return
	}
	t.Fatal("the chain produced no tls.handshake node")
}

func requireHandshakeState(t *testing.T, graph domain.Graph, want domain.State) {
	t.Helper()

	for _, node := range graph.Nodes() {
		if node.Step() != vocabulary.StepTLSHandshake {
			continue
		}
		if node.State() != want {
			t.Fatalf("handshake state = %s, want %s", node.State(), want)
		}
		return
	}
	t.Fatal("the chain produced no tls.handshake node")
}

func requireSingleFinding(
	t *testing.T, findings []domain.Finding, want domain.FindingCode,
) domain.Finding {
	t.Helper()

	if len(findings) != 1 {
		t.Fatalf("got %d findings, want exactly one %s", len(findings), want)
	}
	if got := findings[0].Code(); got != want {
		t.Fatalf("code = %s, want %s", got, want)
	}
	return findings[0]
}

// genericTLSReport assembles a LOCAL_FULL report around the graph and findings.
func genericTLSReport(
	t *testing.T, graph domain.Graph, findings []domain.Finding,
) domain.Report {
	t.Helper()

	service, err := domain.NewServiceID("example")
	if err != nil {
		t.Fatalf("NewServiceID: %v", err)
	}
	run, err := domain.NewRunMetadata("0.0.0-test", time.Now(), time.Second, service)
	if err != nil {
		t.Fatalf("NewRunMetadata: %v", err)
	}
	target, err := domain.NewTarget(genericTLSHost+":9093", genericTLSHost+":9093")
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	vantage, err := domain.NewLocalVantage(genericTLSVantage)
	if err != nil {
		t.Fatalf("NewLocalVantage: %v", err)
	}
	reportSecurity, err := domain.NewReportSecurity(domain.OutputModeLocalFull, false, false)
	if err != nil {
		t.Fatalf("NewReportSecurity: %v", err)
	}
	report, err := domain.NewReport(domain.ReportInput{
		Run: run, Target: target, Vantage: vantage,
		Graph: graph, Findings: findings, Security: reportSecurity,
	})
	if err != nil {
		t.Fatalf("NewReport: %v", err)
	}
	return report
}
