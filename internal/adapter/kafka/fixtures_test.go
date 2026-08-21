package kafka

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"net/netip"
	"sync"
	"testing"

	"github.com/twmb/franz-go/pkg/kmsg"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe/transport"
)

// The peer here answers just enough Kafka to exercise ApiVersions, and it uses
// kmsg to encode rather than hand-written bytes, so the tests do not quietly
// become a second Kafka implementation. Everything runs over a loopback listener
// the test creates and closes: no broker, no container, no network.

// peerBehaviour is what the fake broker does with a request.
type peerBehaviour int

const (
	// peerAnswers replies with a well-formed ApiVersions response.
	peerAnswers peerBehaviour = iota
	// peerAnswersWithError replies with a well-formed response carrying a
	// broker-side error code.
	peerAnswersWithError
	// peerHangsUp closes the connection without answering.
	peerHangsUp
	// peerSpeaksHTTP answers with something that is not Kafka framing.
	peerSpeaksHTTP
	// peerSendsGarbage answers with plausible framing and an undecodable body.
	peerSendsGarbage
	// peerMisscorrelates answers a different request than the one sent.
	peerMisscorrelates
	// peerSaysNothing keeps the connection open and never answers.
	peerSaysNothing
)

// advertised is the API set the fake broker announces, deliberately out of
// order so the canonical ordering can be shown to be svcdoctor's doing.
func advertised() []kmsg.ApiVersionsResponseApiKey {
	keys := make([]kmsg.ApiVersionsResponseApiKey, 0, 3)
	for _, spec := range []struct{ key, min, max int16 }{
		{18, 0, 3}, // ApiVersions
		{3, 0, 12}, // Metadata
		{1, 0, 13}, // Fetch
	} {
		key := kmsg.NewApiVersionsResponseApiKey()
		key.ApiKey = spec.key
		key.MinVersion = spec.min
		key.MaxVersion = spec.max
		keys = append(keys, key)
	}
	return keys
}

// countingConn counts closes so ownership assertions are facts.
type countingConn struct {
	net.Conn
	mu     sync.Mutex
	closes int
}

func (c *countingConn) Close() error {
	c.mu.Lock()
	c.closes++
	c.mu.Unlock()

	err := c.Conn.Close()
	if err != nil && errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func (c *countingConn) closeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closes
}

// defaultErrorCode is what peerAnswersWithError reports unless a test asks for
// another. 35 is UNSUPPORTED_VERSION, the one code the protocol defines for an
// ApiVersions response.
const defaultErrorCode int16 = 35

// broker is a fake Kafka peer on loopback.
type broker struct {
	addr      netip.AddrPort
	behaviour peerBehaviour
	errorCode int16

	mu       sync.Mutex
	requests int
}

func newBroker(t *testing.T, behaviour peerBehaviour) *broker {
	t.Helper()

	return newBrokerWithErrorCode(t, behaviour, defaultErrorCode)
}

// newErrorBroker answers every request with a well-formed response carrying
// code, so a test can pin what one specific broker error code classifies as.
func newErrorBroker(t *testing.T, code int16) *broker {
	t.Helper()

	return newBrokerWithErrorCode(t, peerAnswersWithError, code)
}

// newBrokerWithErrorCode is the one constructor. The error code is fixed before
// the listener starts, so nothing the serving goroutine reads is written later.
func newBrokerWithErrorCode(t *testing.T, behaviour peerBehaviour, code int16) *broker {
	t.Helper()

	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback listener unavailable in this environment: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	addr, err := netip.ParseAddrPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("parsing the broker address: %v", err)
	}
	b := &broker{addr: addr, behaviour: behaviour, errorCode: code}

	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go b.serve(conn)
		}
	}()
	return b
}

func (b *broker) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	correlationID, err := b.readRequest(conn)
	if err != nil {
		return
	}

	b.mu.Lock()
	b.requests++
	b.mu.Unlock()

	switch b.behaviour {
	case peerHangsUp:
		return
	case peerSaysNothing:
		// Hold the connection open until the client gives up or goes away.
		_, _ = io.Copy(io.Discard, conn)
		return
	case peerSpeaksHTTP:
		_, _ = conn.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
		return
	case peerSendsGarbage:
		body := append(correlationBytes(correlationID), 0xff, 0xff, 0xff)
		_, _ = conn.Write(frame(body))
		return
	case peerMisscorrelates:
		_, _ = conn.Write(frame(b.response(correlationID + 1000)))
		return
	case peerAnswers, peerAnswersWithError:
		_, _ = conn.Write(frame(b.response(correlationID)))
	}
}

// readRequest consumes one framed request and returns its correlation id.
func (b *broker) readRequest(conn net.Conn) (uint32, error) {
	var sizeBuf [4]byte
	if _, err := io.ReadFull(conn, sizeBuf[:]); err != nil {
		return 0, err
	}
	size := int64(binary.BigEndian.Uint32(sizeBuf[:]))
	if size < 8 || size > 1<<20 {
		return 0, errors.New("implausible request size")
	}

	body := make([]byte, size)
	if _, err := io.ReadFull(conn, body); err != nil {
		return 0, err
	}
	// apiKey int16, apiVersion int16, correlationID int32
	return binary.BigEndian.Uint32(body[4:8]), nil
}

// response encodes an ApiVersions response with the header the protocol uses.
func (b *broker) response(correlationID uint32) []byte {
	response := kmsg.NewPtrApiVersionsResponse()
	response.SetVersion(0)
	response.ApiKeys = advertised()
	if b.behaviour == peerAnswersWithError {
		response.ErrorCode = b.errorCode
		response.ApiKeys = nil
	}

	out := correlationBytes(correlationID)
	return response.AppendTo(out)
}

func (b *broker) requestCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.requests
}

func correlationBytes(correlationID uint32) []byte {
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, correlationID)
	return out
}

// frame prefixes a Kafka message with its length. The fixture never builds a
// body anywhere near the limit, and the guard says so rather than assuming it.
func frame(body []byte) []byte {
	if len(body) > math.MaxInt32 {
		panic("fixture response is implausibly large")
	}
	out := make([]byte, 4, 4+len(body))
	//nolint:gosec // G115: the guard above bounds the length; a frame prefix has no other form.
	binary.BigEndian.PutUint32(out, uint32(len(body)))
	return append(out, body...)
}

// --- transport paths ------------------------------------------------------

// path builds a transport continuation the way the chain would, over a real
// connection to the fake broker.
//
// It goes through transport.Run with seams pointing at the broker, so the
// continuation this adapter receives is a genuine one rather than a hand-made
// value: the ownership handoff under test is the real one.
func path(t *testing.T, b *broker, addresses ...string) (*transport.Result, *domain.GraphBuilder) {
	t.Helper()

	if len(addresses) == 0 {
		addresses = []string{"10.0.0.1"}
	}
	builder := domain.NewGraphBuilder()
	result, err := transport.Run(context.Background(), builder, transport.Params{
		Host:     "primary.internal",
		Port:     9092,
		Resolver: fixedResolver{addresses: parseAddrs(t, addresses)},
		Dialer:   brokerDialer{target: b.addr, conns: &connRegistry{}},
	})
	if err != nil {
		t.Fatalf("transport.Run: %v", err)
	}
	t.Cleanup(func() { _ = result.Close() })
	return result, builder
}

type connRegistry struct {
	mu    sync.Mutex
	conns []*countingConn
}

func (r *connRegistry) add(c *countingConn) {
	r.mu.Lock()
	r.conns = append(r.conns, c)
	r.mu.Unlock()
}

func (r *connRegistry) all() []*countingConn {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*countingConn(nil), r.conns...)
}

type fixedResolver struct {
	addresses []netip.Addr
}

func (r fixedResolver) LookupAddresses(_ context.Context, _ string) ([]netip.Addr, error) {
	return r.addresses, nil
}

type brokerDialer struct {
	target netip.AddrPort
	conns  *connRegistry
	refuse map[string]bool
}

func (d brokerDialer) DialTCP(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	if d.refuse[addr.Addr().String()] {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: net.ErrClosed}
	}

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", d.target.String())
	if err != nil {
		return nil, err
	}
	counted := &countingConn{Conn: conn}
	if d.conns != nil {
		d.conns.add(counted)
	}
	return counted, nil
}

func parseAddrs(t *testing.T, values []string) []netip.Addr {
	t.Helper()

	addrs := make([]netip.Addr, 0, len(values))
	for _, v := range values {
		addr, err := netip.ParseAddr(v)
		if err != nil {
			t.Fatalf("netip.ParseAddr(%q): %v", v, err)
		}
		addrs = append(addrs, addr)
	}
	return addrs
}

// --- graph helpers --------------------------------------------------------

func freeze(t *testing.T, builder *domain.GraphBuilder) domain.Graph {
	t.Helper()

	graph, err := builder.Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}
	return graph
}

func node(t *testing.T, graph domain.Graph, id string) domain.Evidence {
	t.Helper()

	evidence, ok := graph.Node(domain.EvidenceID(id))
	if !ok {
		ids := make([]string, 0, graph.Len())
		for _, e := range graph.Nodes() {
			ids = append(ids, e.ID().String())
		}
		t.Fatalf("node %q is missing; graph holds %v", id, ids)
	}
	return evidence
}

func attribute(t *testing.T, e domain.Evidence, key domain.AttributeKey) domain.AttrValue {
	t.Helper()

	value, ok := e.Attribute(key)
	if !ok {
		t.Fatalf("attribute %s is missing; present: %v", key, e.Attributes())
	}
	return value
}
