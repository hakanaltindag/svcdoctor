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
	"github.com/hakanaltindag/svcdoctor/internal/probe/tls"
	"github.com/hakanaltindag/svcdoctor/internal/security/redaction"
)

// TLS evidence carries more identity than any other probe's: the name that was
// verified, the names and addresses the certificate carries, and the endpoint
// embedded in the identifier. Each reaches a report by a different route, so
// each needs proving.
const (
	tlsCanaryServerName = "broker-canary.tls.internal"
	tlsCanarySAN        = "alt-canary.tls.internal"
	tlsCanaryIPSAN      = "10.31.32.33"
	tlsCanaryEndpoint   = "endpoint-canary.tls.internal:9093"
	tlsCanaryVantage    = "runner-canary.local"
)

// tlsFixture serves a TLS peer on loopback whose certificate carries the canary
// identities, and returns a live connection to it.
func tlsFixture(t *testing.T) (net.Conn, netip.AddrPort, *x509.CertPool) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "svcdoctor test ca"},
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
		Subject:      pkix.Name{CommonName: tlsCanaryServerName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{tlsCanaryServerName, tlsCanarySAN},
		IPAddresses:  []net.IP{net.ParseIP(tlsCanaryIPSAN)},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, leafKey.Public(), caKey)
	if err != nil {
		t.Fatalf("creating leaf certificate: %v", err)
	}
	serverCert := cryptotls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}

	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback listener unavailable in this environment: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	served := make(chan struct{})
	go func() {
		defer close(served)

		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		server := cryptotls.Server(conn, &cryptotls.Config{
			Certificates: []cryptotls.Certificate{serverCert},
			MinVersion:   cryptotls.VersionTLS12,
		})
		if server.HandshakeContext(context.Background()) != nil {
			return
		}
		_, _ = io.Copy(io.Discard, server)
	}()
	t.Cleanup(func() { <-served })

	dialer := net.Dialer{}
	conn, err := dialer.DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dialing the fixture: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	addr, err := netip.ParseAddrPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("parsing the fixture address: %v", err)
	}
	return conn, addr, pool
}

// tlsReport builds a LOCAL_FULL report from one verified handshake.
func tlsReport(t *testing.T) domain.Report {
	t.Helper()

	conn, addr, pool := tlsFixture(t)

	result, err := tls.Handshake(context.Background(), conn, tls.Params{
		Endpoint:   tlsCanaryEndpoint,
		Address:    addr,
		ServerName: tlsCanaryServerName,
		RootCAs:    pool,
	})
	if err != nil {
		t.Fatalf("tls.Handshake: %v", err)
	}
	t.Cleanup(func() { _ = result.Close() })

	if result.Evidence().State() != domain.StatePass {
		t.Fatalf("fixture handshake did not succeed: %s", result.Evidence().FailureClass())
	}

	builder := domain.NewGraphBuilder()
	if err := builder.AddEvidence(result.Evidence()); err != nil {
		t.Fatalf("AddEvidence: %v", err)
	}
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
	target, err := domain.NewTarget(tlsCanaryEndpoint, tlsCanaryEndpoint)
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	vantage, err := domain.NewLocalVantage(tlsCanaryVantage)
	if err != nil {
		t.Fatalf("NewLocalVantage: %v", err)
	}
	security, err := domain.NewReportSecurity(domain.OutputModeLocalFull, false, false)
	if err != nil {
		t.Fatalf("NewReportSecurity: %v", err)
	}

	report, err := domain.NewReport(domain.ReportInput{
		Run:      run,
		Target:   target,
		Vantage:  vantage,
		Graph:    graph,
		Security: security,
	})
	if err != nil {
		t.Fatalf("NewReport: %v", err)
	}
	return report
}

func tlsCanaries() []string {
	return []string{
		tlsCanaryServerName, tlsCanarySAN, tlsCanaryIPSAN,
		strings.TrimSuffix(tlsCanaryEndpoint, ":9093"), tlsCanaryVantage,
	}
}

// TestLocalTLSReportContainsTheCanaries proves the leak assertions below can
// fail. Every identity the probe records must actually be in the local report.
func TestLocalTLSReportContainsTheCanaries(t *testing.T) {
	encoded := canonicalJSON(t, tlsReport(t))

	for _, canary := range tlsCanaries() {
		if !strings.Contains(encoded, canary) {
			t.Errorf("local report does not contain %q, so the leak test would prove nothing", canary)
		}
	}
}

// TestTLSEvidenceRedactsWithoutLeaking is the contract: the verified name, the
// certificate's alternative names, its IP address and the endpoint inside the
// identifier all disappear from a shareable report.
func TestTLSEvidenceRedactsWithoutLeaking(t *testing.T) {
	shareable, err := redaction.Redact(tlsReport(t))
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}

	encoded := canonicalJSON(t, shareable)
	for _, canary := range tlsCanaries() {
		if strings.Contains(encoded, canary) {
			t.Errorf("shareable report leaks %q:\n%s", canary, encoded)
		}
	}
}

// TestRedactedTLSEvidenceStaysDiagnostic checks the other half of the bargain: a
// shared report still says what was negotiated, whether identity was verified,
// and when the certificate expires. Those carry no identity and are the whole
// reason to share the report.
func TestRedactedTLSEvidenceStaysDiagnostic(t *testing.T) {
	shareable, err := redaction.Redact(tlsReport(t))
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}

	nodes := shareable.Graph().Nodes()
	if len(nodes) != 1 {
		t.Fatalf("node count = %d, want 1", len(nodes))
	}
	node := nodes[0]

	if node.Layer() != domain.LayerTLS {
		t.Errorf("layer = %s, want L3", node.Layer())
	}
	if node.Step() != tls.StepHandshake {
		t.Errorf("step = %s, want %s", node.Step(), tls.StepHandshake)
	}
	if node.State() != domain.StatePass {
		t.Errorf("state = %s, want PASS", node.State())
	}

	verified, ok := node.Attribute(tls.AttrVerified)
	if !ok {
		t.Fatal("tls.verified did not survive redaction")
	}
	if value, isBool := verified.Bool(); !isBool || !value {
		t.Error("tls.verified should still report a verified handshake")
	}
	if _, ok := node.Attribute(tls.AttrVersion); !ok {
		t.Error("tls.version did not survive redaction")
	}
	if _, ok := node.Attribute(tls.AttrPeerNotAfter); !ok {
		t.Error("tls.peer_not_after did not survive redaction")
	}
}

// TestRedactedIdentitiesArePseudonymized checks that identity was replaced
// rather than blanked: a reader must still see that the verified name and the
// certificate's first name are the same host.
func TestRedactedIdentitiesArePseudonymized(t *testing.T) {
	shareable, err := redaction.Redact(tlsReport(t))
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	node := shareable.Graph().Nodes()[0]

	serverName, ok := node.Attribute(tls.AttrServerName)
	if !ok {
		t.Fatal("tls.server_name is missing")
	}
	name, _ := serverName.Host()
	if !strings.HasPrefix(name, "host-") {
		t.Errorf("tls.server_name = %q, want a host pseudonym", name)
	}

	sans, ok := node.Attribute(tls.AttrPeerDNSNames)
	if !ok {
		t.Fatal("tls.peer_dns_names is missing")
	}
	names, _ := sans.HostList()
	for _, san := range names {
		if !strings.HasPrefix(san, "host-") {
			t.Errorf("certificate name %q was not pseudonymized", san)
		}
	}
	if !slicesContains(names, name) {
		t.Errorf("the verified name %q no longer appears among the certificate names %v: "+
			"correlation was lost", name, names)
	}

	ips, ok := node.Attribute(tls.AttrPeerIPAddresses)
	if !ok {
		t.Fatal("tls.peer_ip_addresses is missing")
	}
	addresses, _ := ips.HostList()
	for _, address := range addresses {
		if !strings.HasPrefix(address, "ip-") {
			t.Errorf("certificate address %q was not pseudonymized", address)
		}
	}
}

func slicesContains(haystack []string, needle string) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}
