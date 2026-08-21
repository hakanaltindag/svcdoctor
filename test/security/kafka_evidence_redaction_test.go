package security

import (
	"context"
	"encoding/binary"
	"io"
	"math"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kmsg"

	"github.com/hakanaltindag/svcdoctor/internal/adapter/kafka"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe/transport"
	"github.com/hakanaltindag/svcdoctor/internal/security/redaction"
)

// The first end-to-end security check that includes a protocol layer: a graph
// built by real DNS, TCP and Kafka execution, turned into a report and redacted.
// It also covers a relationship redaction has not been exercised against before,
// the L2 -> L4 parent edge.
const (
	kafkaCanaryHost    = "broker-canary.kafka.internal"
	kafkaCanaryAddr    = "10.51.52.53"
	kafkaCanaryVantage = "kafka-runner-canary.local"
)

// kafkaPeer answers ApiVersions over loopback.
func kafkaPeer(t *testing.T) netip.AddrPort {
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
			go serveKafka(conn)
		}
	}()

	addr, err := netip.ParseAddrPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("parsing the peer address: %v", err)
	}
	return addr
}

// serveKafka answers the two requests one svcdoctor run makes on a connection:
// ApiVersions, then SaslHandshake. It answers both on the same socket, because
// that is what the adapter does and a fixture that closed in between would make
// the redaction fixture diverge from the code it is protecting.
func serveKafka(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	for {
		key, correlationID, ok := readKafkaRequest(conn)
		if !ok {
			return
		}

		var payload []byte
		switch key {
		case 18: // ApiVersions
			response := kmsg.NewPtrApiVersionsResponse()
			response.SetVersion(0)
			apiKey := kmsg.NewApiVersionsResponseApiKey()
			apiKey.ApiKey, apiKey.MinVersion, apiKey.MaxVersion = 18, 0, 3
			response.ApiKeys = []kmsg.ApiVersionsResponseApiKey{apiKey}
			payload = response.AppendTo(correlationBytes(correlationID))
		case 17: // SaslHandshake
			response := kmsg.NewPtrSASLHandshakeResponse()
			response.SetVersion(1)
			response.SupportedMechanisms = []string{"PLAIN", "SCRAM-SHA-512"}
			payload = response.AppendTo(correlationBytes(correlationID))
		default:
			return
		}

		if len(payload) > math.MaxInt32 {
			return
		}
		framed := make([]byte, 4, 4+len(payload))
		//nolint:gosec // G115: the guard above bounds the length; a frame prefix has no other form.
		binary.BigEndian.PutUint32(framed, uint32(len(payload)))
		if _, err := conn.Write(append(framed, payload...)); err != nil {
			return
		}
	}
}

// readKafkaRequest consumes one framed request and reports its key and
// correlation identifier.
func readKafkaRequest(conn net.Conn) (int16, uint32, bool) {
	var sizeBuf [4]byte
	if _, err := io.ReadFull(conn, sizeBuf[:]); err != nil {
		return 0, 0, false
	}
	size := int64(binary.BigEndian.Uint32(sizeBuf[:]))
	if size < 8 || size > 1<<20 {
		return 0, 0, false
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(conn, body); err != nil {
		return 0, 0, false
	}
	//nolint:gosec // G115: a Kafka api key is an int16 on the wire by definition.
	return int16(binary.BigEndian.Uint16(body[0:2])), binary.BigEndian.Uint32(body[4:8]), true
}

func correlationBytes(correlationID uint32) []byte {
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, correlationID)
	return out
}

type kafkaResolver struct{}

func (kafkaResolver) LookupAddresses(_ context.Context, _ string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr(kafkaCanaryAddr)}, nil
}

type kafkaDialer struct{ target netip.AddrPort }

func (d kafkaDialer) DialTCP(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", d.target.String())
}

// kafkaReport runs transport plus the Kafka adapter and assembles a LOCAL_FULL
// report from the result.
func kafkaReport(t *testing.T) domain.Report {
	t.Helper()

	peer := kafkaPeer(t)
	builder := domain.NewGraphBuilder()

	paths, err := transport.Run(context.Background(), builder, transport.Params{
		Host:     kafkaCanaryHost,
		Port:     9092,
		Resolver: kafkaResolver{},
		Dialer:   kafkaDialer{target: peer},
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

	if len(protocol.Sessions()) != 1 {
		t.Fatalf("sessions = %d, want 1: the fixture exchange did not complete", len(protocol.Sessions()))
	}

	handshake, err := kafka.SASLHandshake(
		context.Background(), builder, protocol.Sessions(), kafka.SASLParams{Mechanism: "PLAIN"})
	if err != nil {
		t.Fatalf("kafka.SASLHandshake: %v", err)
	}
	t.Cleanup(func() { _ = handshake.Close() })

	if len(handshake.Sessions()) != 1 {
		t.Fatalf("handshake sessions = %d, want 1: the fixture handshake did not complete",
			len(handshake.Sessions()))
	}

	graph, err := builder.Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}

	service, err := domain.NewServiceID("kafka")
	if err != nil {
		t.Fatalf("NewServiceID: %v", err)
	}
	run, err := domain.NewRunMetadata("0.0.0-dev", time.Unix(1700000000, 0).UTC(), time.Second, service)
	if err != nil {
		t.Fatalf("NewRunMetadata: %v", err)
	}
	target, err := domain.NewTarget(kafkaCanaryHost+":9092", kafkaCanaryHost+":9092")
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	vantage, err := domain.NewLocalVantage(kafkaCanaryVantage)
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

func kafkaCanaries() []string {
	return []string{kafkaCanaryHost, kafkaCanaryAddr, kafkaCanaryVantage}
}

func TestLocalKafkaReportContainsTheCanaries(t *testing.T) {
	encoded := canonicalJSON(t, kafkaReport(t))

	for _, canary := range kafkaCanaries() {
		if !strings.Contains(encoded, canary) {
			t.Errorf("local report does not contain %q, so the leak test would prove nothing", canary)
		}
	}
}

func TestKafkaReportRedactsWithoutLeaking(t *testing.T) {
	shareable, err := redaction.Redact(kafkaReport(t))
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}

	encoded := canonicalJSON(t, shareable)
	for _, canary := range kafkaCanaries() {
		if strings.Contains(encoded, canary) {
			t.Errorf("shareable report leaks %q:\n%s", canary, encoded)
		}
	}
}

// TestKafkaFactsSurviveRedaction is the other half: a shared report must still
// say what the broker advertised, because that carries no identity and is the
// reason to share it.
func TestKafkaFactsSurviveRedaction(t *testing.T) {
	shareable, err := redaction.Redact(kafkaReport(t))
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}

	var protocol domain.Evidence
	for _, evidence := range shareable.Graph().Nodes() {
		if evidence.Layer() == domain.LayerProtocol {
			protocol = evidence
			break
		}
	}
	if protocol.IsZero() {
		t.Fatal("no protocol evidence survived redaction")
	}

	if protocol.Step() != kafka.StepAPIVersions {
		t.Errorf("step = %s, want %s", protocol.Step(), kafka.StepAPIVersions)
	}
	if protocol.State() != domain.StatePass {
		t.Errorf("state = %s, want PASS", protocol.State())
	}

	ranges, ok := protocol.Attribute(kafka.AttrAPIVersions)
	if !ok {
		t.Fatal("the advertised ranges did not survive redaction")
	}
	list, _ := ranges.StringList()
	if len(list) != 1 || list[0] != "18:0-3" {
		t.Errorf("ranges = %v, want [18:0-3] intact", list)
	}
}

// TestSASLFactsSurviveRedaction is the L5 half: what a broker offers is a
// protocol fact, not an identity, and a shared report keeps saying it.
//
// Mechanism names are the reason this test exists. They are strings that carry
// no identity, so declaring them identifying would pseudonymize PLAIN into
// host-001 and destroy the only thing the node is for.
func TestSASLFactsSurviveRedaction(t *testing.T) {
	shareable, err := redaction.Redact(kafkaReport(t))
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}

	var handshake domain.Evidence
	for _, evidence := range shareable.Graph().Nodes() {
		if evidence.Step() == kafka.StepSASLHandshake {
			handshake = evidence
			break
		}
	}
	if handshake.IsZero() {
		t.Fatal("no handshake evidence survived redaction")
	}

	if handshake.Layer() != domain.LayerAuth {
		t.Errorf("layer = %s, want L5", handshake.Layer())
	}
	if handshake.State() != domain.StatePass {
		t.Errorf("state = %s, want PASS", handshake.State())
	}

	requested, ok := handshake.Attribute(kafka.AttrSASLRequestedMechanism)
	if !ok {
		t.Fatal("the requested mechanism did not survive redaction")
	}
	if value, _ := requested.Str(); value != "PLAIN" {
		t.Errorf("requested mechanism = %q, want PLAIN intact", value)
	}

	offered, ok := handshake.Attribute(kafka.AttrSASLOfferedMechanisms)
	if !ok {
		t.Fatal("the offered mechanisms did not survive redaction")
	}
	list, _ := offered.StringList()
	if len(list) != 2 || list[0] != "PLAIN" || list[1] != "SCRAM-SHA-512" {
		t.Errorf("offered = %v, want [PLAIN SCRAM-SHA-512] intact", list)
	}
}

// TestSASLNodeCarriesNoIdentity is the other direction: the L5 node is built
// from a subject and an endpoint scope, and both are identity that must be gone.
func TestSASLNodeCarriesNoIdentity(t *testing.T) {
	shareable, err := redaction.Redact(kafkaReport(t))
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}

	for _, evidence := range shareable.Graph().Nodes() {
		if evidence.Step() != kafka.StepSASLHandshake {
			continue
		}
		for _, canary := range kafkaCanaries() {
			if strings.Contains(evidence.ID().String(), canary) {
				t.Errorf("the handshake identifier still carries %q", canary)
			}
			if strings.Contains(evidence.Subject().Ref(), canary) {
				t.Errorf("the handshake subject still carries %q", canary)
			}
		}
	}
}

// TestProtocolParentSurvivesIdentifierRemapping checks that the L2 -> L4 edge
// still resolves after every identifier is rewritten.
func TestProtocolParentSurvivesIdentifierRemapping(t *testing.T) {
	local := kafkaReport(t)

	shareable, err := redaction.Redact(local)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	graph := shareable.Graph()

	var protocolID domain.EvidenceID
	for _, evidence := range graph.Nodes() {
		if evidence.Layer() == domain.LayerProtocol {
			protocolID = evidence.ID()
		}
	}
	if protocolID == "" {
		t.Fatal("no protocol node in the shareable report")
	}

	parents := graph.Parents(protocolID)
	if len(parents) != 1 {
		t.Fatalf("parents = %v, want exactly one", parents)
	}
	parent, ok := graph.Node(parents[0])
	if !ok {
		t.Fatalf("the protocol node points at %s, which is not in the graph", parents[0])
	}
	if parent.Layer() != domain.LayerTCP {
		t.Errorf("parent layer = %s, want L2", parent.Layer())
	}
	if strings.Contains(protocolID.String(), kafkaCanaryHost) {
		t.Error("the protocol identifier still carries the hostname")
	}
}
