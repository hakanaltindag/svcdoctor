package security

import (
	"context"
	"net"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe"
	"github.com/hakanaltindag/svcdoctor/internal/probe/tcp"
	"github.com/hakanaltindag/svcdoctor/internal/security/redaction"
)

// TCP evidence carries identity in two places that behave differently under
// redaction, which is why it needs its own contract test:
//
//   - the subject, a concrete address, which redaction recognizes structurally
//   - the evidence identifier, which embeds the logical endpoint and is replaced
//     wholesale rather than parsed
//
// The second is the interesting one. A hostname that appears *only* inside an
// identifier still has to disappear, and it does — but for a different reason
// than every other value, so it is worth an executable proof.
const (
	tcpCanaryEndpointHost = "broker-canary.prod.internal"
	tcpCanaryIPv4         = "10.21.22.23"
	tcpCanaryIPv6         = "2001:db8::beef"
	tcpCanaryVantage      = "runner-canary.local"
)

// errRefused is the error shape the standard library returns for a refused
// connection, so the recorded failure class is a real one rather than the
// conservative fallback.
var errRefused = &net.OpError{
	Op:  "dial",
	Net: "tcp",
	Err: os.NewSyscallError("connect", syscall.ECONNREFUSED),
}

type stubDialer struct {
	err error
}

func (d stubDialer) DialTCP(_ context.Context, _ netip.AddrPort) (net.Conn, error) {
	return nil, d.err
}

// tcpReport builds a LOCAL_FULL report from two TCP attempts against one logical
// endpoint, one per address family, exactly as the transport chain will later
// record them.
func tcpReport(t *testing.T) domain.Report {
	t.Helper()

	endpoint := tcpCanaryEndpointHost + ":9092"
	builder := domain.NewGraphBuilder()

	for _, address := range []string{tcpCanaryIPv4, tcpCanaryIPv6} {
		addr := netip.AddrPortFrom(netip.MustParseAddr(address), 9092)

		result, err := tcp.Connect(context.Background(), stubDialer{err: errRefused}, endpoint, addr, probe.SweepScope{})
		if err != nil {
			t.Fatalf("tcp.Connect: %v", err)
		}
		defer func() { _ = result.Close() }()

		if err := builder.AddEvidence(result.Evidence()); err != nil {
			t.Fatalf("AddEvidence: %v", err)
		}
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
	target, err := domain.NewTarget(endpoint, endpoint)
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	vantage, err := domain.NewLocalVantage(tcpCanaryVantage)
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

func TestLocalTCPReportContainsTheCanaries(t *testing.T) {
	encoded := canonicalJSON(t, tcpReport(t))

	for _, canary := range []string{tcpCanaryEndpointHost, tcpCanaryIPv4, tcpCanaryIPv6, tcpCanaryVantage} {
		if !strings.Contains(encoded, canary) {
			t.Errorf("local report does not contain %q, so the leak test would prove nothing", canary)
		}
	}
}

func TestTCPEvidenceRedactsWithoutLeaking(t *testing.T) {
	shareable, err := redaction.Redact(tcpReport(t))
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}

	encoded := canonicalJSON(t, shareable)
	for _, canary := range []string{tcpCanaryEndpointHost, tcpCanaryIPv4, tcpCanaryIPv6, tcpCanaryVantage} {
		if strings.Contains(encoded, canary) {
			t.Errorf("shareable report leaks %q:\n%s", canary, encoded)
		}
	}
}

// TestEndpointInsideAnIdentifierIsRemoved covers the case the DNS contract test
// cannot reach. Here the logical hostname appears in no subject, no attribute
// and no prose — only inside the TCP evidence identifiers — and it must still be
// gone, because identifiers are replaced rather than rewritten in place.
//
// The target is deliberately an address rather than the name, so the name has no
// other route into the report.
func TestEndpointInsideAnIdentifierIsRemoved(t *testing.T) {
	endpoint := tcpCanaryEndpointHost + ":9092"
	addr := netip.AddrPortFrom(netip.MustParseAddr(tcpCanaryIPv4), 9092)

	result, err := tcp.Connect(context.Background(), stubDialer{err: errRefused}, endpoint, addr, probe.SweepScope{})
	if err != nil {
		t.Fatalf("tcp.Connect: %v", err)
	}
	defer func() { _ = result.Close() }()

	if !strings.Contains(result.Evidence().ID().String(), tcpCanaryEndpointHost) {
		t.Fatalf("precondition failed: identifier %q does not carry the hostname", result.Evidence().ID())
	}
	if strings.Contains(result.Evidence().Subject().Ref(), tcpCanaryEndpointHost) {
		t.Fatal("precondition failed: the hostname reached the subject, so this test proves nothing")
	}

	builder := domain.NewGraphBuilder()
	if err := builder.AddEvidence(result.Evidence()); err != nil {
		t.Fatalf("AddEvidence: %v", err)
	}
	graph, err := builder.Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}

	service, _ := domain.NewServiceID("example")
	run, _ := domain.NewRunMetadata("0.0.0-dev", time.Unix(1700000000, 0).UTC(), time.Second, service)
	target, _ := domain.NewTarget(tcpCanaryIPv4 + ":9092")
	vantage, _ := domain.NewLocalVantage(tcpCanaryVantage)
	security, _ := domain.NewReportSecurity(domain.OutputModeLocalFull, false, false)

	report, err := domain.NewReport(domain.ReportInput{
		Run: run, Target: target, Vantage: vantage, Graph: graph, Security: security,
	})
	if err != nil {
		t.Fatalf("NewReport: %v", err)
	}

	shareable, err := redaction.Redact(report)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	if encoded := canonicalJSON(t, shareable); strings.Contains(encoded, tcpCanaryEndpointHost) {
		t.Errorf("a hostname reachable only through an evidence identifier survived redaction:\n%s", encoded)
	}
}

// TestRedactedTCPEvidenceStaysDiagnostic checks that removing identity left the
// facts intact: the layer, the step, the state and the failure class are what a
// reader of a shared report needs.
func TestRedactedTCPEvidenceStaysDiagnostic(t *testing.T) {
	shareable, err := redaction.Redact(tcpReport(t))
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}

	nodes := shareable.Graph().Nodes()
	if len(nodes) != 2 {
		t.Fatalf("node count = %d, want 2", len(nodes))
	}

	for _, node := range nodes {
		if node.Layer() != domain.LayerTCP {
			t.Errorf("layer = %s, want L2", node.Layer())
		}
		if node.Step() != tcp.StepConnect {
			t.Errorf("step = %s, want %s", node.Step(), tcp.StepConnect)
		}
		if node.State() != domain.StateFail {
			t.Errorf("state = %s, want FAIL", node.State())
		}
		if node.FailureClass() != domain.FailureTCPConnectionRefused {
			t.Errorf("failure class = %s, want TCP_CONNECTION_REFUSED", node.FailureClass())
		}
		if ref := node.Subject().Ref(); !strings.HasPrefix(ref, "ip-") {
			t.Errorf("subject ref = %q, want an ip pseudonym", ref)
		}
	}
}
