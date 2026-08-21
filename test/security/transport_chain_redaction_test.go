package security

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	cryptotls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe/transport"
	"github.com/hakanaltindag/svcdoctor/internal/security/redaction"
)

// This is the end-to-end security check for the transport chain: a graph built
// by real DNS, TCP and TLS execution, turned into a report, and redacted. It
// covers identity the earlier per-probe tests could not reach on their own —
// notably a BlockedBy edge that has to survive identifier remapping.
const (
	chainCanaryHost    = "chain-canary.prod.internal"
	chainCanaryReached = "10.41.42.43"
	chainCanaryBroken  = "10.41.42.44"
	chainCanaryV6      = "2001:db8::c4a1"
	chainCanarySAN     = "chain-alt-canary.prod.internal"
	chainCanaryVantage = "chain-runner-canary.local"
)

// chainResolver answers with the canary addresses, in an order the DNS probe
// will canonicalize.
type chainResolver struct{}

func (chainResolver) LookupAddresses(_ context.Context, _ string) ([]netip.Addr, error) {
	return []netip.Addr{
		netip.MustParseAddr(chainCanaryV6),
		netip.MustParseAddr(chainCanaryBroken),
		netip.MustParseAddr(chainCanaryReached),
	}, nil
}

// chainDialer routes the reachable canary addresses to a real TLS peer and
// refuses the broken one, so the graph contains a success, a failure and a
// skipped downstream node.
type chainDialer struct {
	target netip.AddrPort
}

func (d chainDialer) DialTCP(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	if addr.Addr().String() == chainCanaryBroken {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: net.ErrClosed}
	}

	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", d.target.String())
}

func chainTLSPeer(t *testing.T) (netip.AddrPort, *x509.CertPool) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "svcdoctor chain ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	if err != nil {
		t.Fatalf("creating CA certificate: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parsing CA certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating leaf key: %v", err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: chainCanaryHost},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{chainCanaryHost, chainCanarySAN},
		IPAddresses:  []net.IP{net.ParseIP(chainCanaryReached)},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, leafKey.Public(), caKey)
	if err != nil {
		t.Fatalf("creating leaf certificate: %v", err)
	}
	cert := cryptotls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}

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
			go func() {
				defer func() { _ = conn.Close() }()

				server := cryptotls.Server(conn, &cryptotls.Config{
					Certificates: []cryptotls.Certificate{cert},
					MinVersion:   cryptotls.VersionTLS12,
				})
				if server.HandshakeContext(context.Background()) != nil {
					return
				}
				_, _ = io.Copy(io.Discard, server)
			}()
		}
	}()

	addr, err := netip.ParseAddrPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("parsing the peer address: %v", err)
	}
	return addr, pool
}

// chainReport runs the real chain and assembles a LOCAL_FULL report from it.
func chainReport(t *testing.T) domain.Report {
	t.Helper()

	peerAddr, pool := chainTLSPeer(t)

	builder := domain.NewGraphBuilder()
	result, err := transport.Run(context.Background(), builder, transport.Params{
		Host:     chainCanaryHost,
		Port:     9093,
		Resolver: chainResolver{},
		Dialer:   chainDialer{target: peerAddr},
		TLS:      &transport.TLSOptions{RootCAs: pool},
	})
	if err != nil {
		t.Fatalf("transport.Run: %v", err)
	}
	t.Cleanup(func() { _ = result.Close() })

	graph, err := builder.Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}

	service, err := domain.NewServiceID("example")
	if err != nil {
		t.Fatalf("NewServiceID: %v", err)
	}
	run, err := domain.NewRunMetadata("0.0.0-dev", time.Unix(1700000000, 0).UTC(), time.Second, service)
	if err != nil {
		t.Fatalf("NewRunMetadata: %v", err)
	}
	target, err := domain.NewTarget(chainCanaryHost+":9093", chainCanaryHost+":9093")
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	vantage, err := domain.NewLocalVantage(chainCanaryVantage)
	if err != nil {
		t.Fatalf("NewLocalVantage: %v", err)
	}
	security, err := domain.NewReportSecurity(domain.OutputModeLocalFull, false, false)
	if err != nil {
		t.Fatalf("NewReportSecurity: %v", err)
	}

	report, err := domain.NewReport(domain.ReportInput{
		Run: run, Target: target, Vantage: vantage, Graph: graph, Security: security,
	})
	if err != nil {
		t.Fatalf("NewReport: %v", err)
	}
	return report
}

func chainCanaries() []string {
	return []string{
		chainCanaryHost, chainCanaryReached, chainCanaryBroken,
		chainCanaryV6, chainCanarySAN, chainCanaryVantage,
	}
}

func TestChainLocalReportContainsTheCanaries(t *testing.T) {
	encoded := canonicalJSON(t, chainReport(t))

	for _, canary := range chainCanaries() {
		if !strings.Contains(encoded, canary) {
			t.Errorf("local report does not contain %q, so the leak test would prove nothing", canary)
		}
	}
}

func TestChainReportRedactsWithoutLeaking(t *testing.T) {
	shareable, err := redaction.Redact(chainReport(t))
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}

	encoded := canonicalJSON(t, shareable)
	for _, canary := range chainCanaries() {
		if strings.Contains(encoded, canary) {
			t.Errorf("shareable report leaks %q:\n%s", canary, encoded)
		}
	}
}

// TestChainRelationshipsSurviveRedaction is the structural check redaction has
// never been exercised against before: this graph has real parent edges and a
// real BlockedBy edge, and every identifier in them is rewritten.
func TestChainRelationshipsSurviveRedaction(t *testing.T) {
	local := chainReport(t)

	localParents, localBlocked := countRelationships(local.Graph())
	if localParents == 0 {
		t.Fatal("the local graph has no parent edges, so this test proves nothing")
	}
	if localBlocked == 0 {
		t.Fatal("the local graph has no blocked-by edge, so this test proves nothing")
	}

	shareable, err := redaction.Redact(local)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}

	graph := shareable.Graph()
	if graph.Len() != local.Graph().Len() {
		t.Errorf("node count changed from %d to %d", local.Graph().Len(), graph.Len())
	}

	parents, blocked := countRelationships(graph)
	if parents != localParents {
		t.Errorf("parent edges = %d, want %d", parents, localParents)
	}
	if blocked != localBlocked {
		t.Errorf("blocked-by edges = %d, want %d", blocked, localBlocked)
	}

	// Every edge must still point at a node that exists in the redacted graph.
	for _, evidence := range graph.Nodes() {
		for _, parent := range graph.Parents(evidence.ID()) {
			if _, ok := graph.Node(parent); !ok {
				t.Errorf("node %s has a dangling parent %s after remapping", evidence.ID(), parent)
			}
		}
		for _, blocker := range graph.BlockedBy(evidence.ID()) {
			if _, ok := graph.Node(blocker); !ok {
				t.Errorf("node %s has a dangling blocker %s after remapping", evidence.ID(), blocker)
			}
		}
	}
}

// TestRedactedChainReportStaysDiagnostic checks that what survives is still
// worth reading: which layer broke where, and what TLS negotiated.
func TestRedactedChainReportStaysDiagnostic(t *testing.T) {
	shareable, err := redaction.Redact(chainReport(t))
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}

	states := map[domain.State]int{}
	layers := map[domain.Layer]int{}
	for _, evidence := range shareable.Graph().Nodes() {
		states[evidence.State()]++
		layers[evidence.Layer()]++
	}

	if states[domain.StatePass] == 0 {
		t.Error("no successful step survived redaction")
	}
	if states[domain.StateFail] == 0 {
		t.Error("the failed attempt did not survive redaction")
	}
	if states[domain.StateSkipped] == 0 {
		t.Error("the skipped handshake did not survive redaction")
	}
	for _, layer := range []domain.Layer{domain.LayerDNS, domain.LayerTCP, domain.LayerTLS} {
		if layers[layer] == 0 {
			t.Errorf("no %s evidence survived redaction", layer)
		}
	}
}

func countRelationships(graph domain.Graph) (parents, blocked int) {
	for _, evidence := range graph.Nodes() {
		parents += len(graph.Parents(evidence.ID()))
		blocked += len(graph.BlockedBy(evidence.ID()))
	}
	return parents, blocked
}
