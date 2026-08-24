package redis

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe/transport"
)

// The Redis adapter's fixtures.
//
// Every test in this package drives **the real chain**: a real listener, real
// sockets, the real transport.Run, and the real adapter. Nothing here stubs the
// adapter's own seams, because the invariants being tested — one credential, one
// frame shape, no key named — are properties of what leaves the socket, and a
// stub that never writes to one cannot prove them.

// behaviour describes how a fake endpoint answers each authorized command.
//
// A test states the endpoint's behaviour rather than a byte script, so a change
// to framing does not rewrite thirty tests — and the fixture still parses the
// real bytes svcdoctor sent, which is what makes assertions about them possible.
type behaviour struct {
	// hello is the reply to the first HELLO. Required.
	hello string
	// helloAfterAuth is the reply to a HELLO that arrives once the connection is
	// authenticated. Empty means reuse hello.
	helloAfterAuth string
	// auth is the reply to AUTH. Empty means "+OK".
	auth string
	// ping is the reply to PING. Empty means "+PONG".
	ping string
	// closeOn names a command after which the peer hangs up without replying.
	closeOn string
	// requireAuth makes every command before a successful AUTH answer NOAUTH.
	requireAuth bool
}

// Canned replies, captured from real servers where the shape matters.
const (
	helloRedis = "*14\r\n$6\r\nserver\r\n$5\r\nredis\r\n$7\r\nversion\r\n$5\r\n8.2.1\r\n" +
		"$5\r\nproto\r\n:2\r\n$2\r\nid\r\n:10\r\n$4\r\nmode\r\n$10\r\nstandalone\r\n" +
		"$4\r\nrole\r\n$6\r\nmaster\r\n$7\r\nmodules\r\n*0\r\n"

	helloValkey = "*14\r\n$6\r\nserver\r\n$6\r\nvalkey\r\n$7\r\nversion\r\n$5\r\n8.1.1\r\n" +
		"$5\r\nproto\r\n:2\r\n$2\r\nid\r\n:2\r\n$4\r\nmode\r\n$10\r\nstandalone\r\n" +
		"$4\r\nrole\r\n$6\r\nmaster\r\n$7\r\nmodules\r\n*0\r\n"

	helloReplica = "*14\r\n$6\r\nserver\r\n$5\r\nredis\r\n$7\r\nversion\r\n$5\r\n8.2.1\r\n" +
		"$5\r\nproto\r\n:2\r\n$2\r\nid\r\n:4\r\n$4\r\nmode\r\n$10\r\nstandalone\r\n" +
		"$4\r\nrole\r\n$7\r\nreplica\r\n$7\r\nmodules\r\n*0\r\n"

	helloCluster = "*14\r\n$6\r\nserver\r\n$5\r\nredis\r\n$7\r\nversion\r\n$5\r\n8.2.1\r\n" +
		"$5\r\nproto\r\n:2\r\n$2\r\nid\r\n:7\r\n$4\r\nmode\r\n$7\r\ncluster\r\n" +
		"$4\r\nrole\r\n$6\r\nmaster\r\n$7\r\nmodules\r\n*0\r\n"

	// A Sentinel omits the role field entirely.
	helloSentinel = "*12\r\n$6\r\nserver\r\n$5\r\nredis\r\n$7\r\nversion\r\n$5\r\n8.2.1\r\n" +
		"$5\r\nproto\r\n:2\r\n$2\r\nid\r\n:3\r\n$4\r\nmode\r\n$8\r\nsentinel\r\n" +
		"$7\r\nmodules\r\n*0\r\n"

	errNoAuth = "-NOAUTH HELLO must be called with the client already authenticated, " +
		"otherwise the HELLO <proto> AUTH <user> <pass> option can be used\r\n"

	// The unknown-command reply a pre-6.0 server or a proxy sends, complete with
	// the argument echo at redis/src/server.c:4386.
	errHelloUnknown = "-ERR unknown command 'HELLO', with args beginning with: \r\n"

	errWrongPass  = "-WRONGPASS invalid username-password pair or user is disabled.\r\n"
	errNoPerm     = "-NOPERM User app has no permissions to run the 'ping' command\r\n"
	errLoading    = "-LOADING Redis is loading the dataset in memory\r\n"
	errMasterDown = "-MASTERDOWN Link with MASTER is down and replica-serve-stale-data " +
		"is set to 'no'.\r\n"
	errUnknownPrefix = "-QUANTUMFLUX a condition svcdoctor does not classify\r\n"
)

// peer is a fake Redis endpoint on a real socket.
type peer struct {
	t    *testing.T
	addr netip.AddrPort

	mu       sync.Mutex
	received []string // every command name that arrived, in order
	raw      []string // every full command frame, for byte assertions
}

// newPeer starts a listener that answers according to b.
func newPeer(t *testing.T, b behaviour) *peer {
	t.Helper()

	var lc net.ListenConfig
	listener, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	addr, err := netip.ParseAddrPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("parsing listener address: %v", err)
	}
	p := &peer{t: t, addr: addr}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go p.serve(conn, b)
		}
	}()
	return p
}

func (p *peer) serve(conn net.Conn, b behaviour) {
	defer func() { _ = conn.Close() }()
	reader := bufio.NewReader(conn)
	authenticated := false

	for {
		command, frame, err := readCommand(reader)
		if err != nil {
			return
		}
		p.record(command, frame)

		if b.closeOn == command {
			return
		}

		var reply string
		switch command {
		case "HELLO":
			switch {
			case b.requireAuth && !authenticated:
				reply = errNoAuth
			case authenticated && b.helloAfterAuth != "":
				reply = b.helloAfterAuth
			default:
				reply = b.hello
			}
		case "AUTH":
			reply = b.auth
			if reply == "" {
				reply = "+OK\r\n"
			}
			if strings.HasPrefix(reply, "+OK") {
				authenticated = true
			}
		case "PING":
			if b.requireAuth && !authenticated {
				reply = "-NOAUTH Authentication required.\r\n"
				break
			}
			reply = b.ping
			if reply == "" {
				reply = "+PONG\r\n"
			}
		default:
			reply = "-ERR unknown command\r\n"
		}
		if reply == "" {
			// An endpoint that accepts the connection and answers nothing. It is
			// how a local budget is exercised without a sleep.
			continue
		}
		if _, err := conn.Write([]byte(reply)); err != nil {
			return
		}
	}
}

func (p *peer) record(command, frame string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.received = append(p.received, command)
	p.raw = append(p.raw, frame)
}

// commands returns the command names that arrived, in order.
func (p *peer) commands() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.received...)
}

// frames returns every full command frame that arrived.
//
// It is what lets a test assert on the exact bytes svcdoctor put on the socket
// rather than on what it meant to.
func (p *peer) frames() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.raw...)
}

// count reports how many times one command arrived.
func (p *peer) count(command string) int {
	n := 0
	for _, c := range p.commands() {
		if c == command {
			n++
		}
	}
	return n
}

// readCommand parses one RESP2 array of bulk strings and returns the command
// name plus the exact bytes that formed it.
func readCommand(r *bufio.Reader) (string, string, error) {
	header, err := r.ReadString('\n')
	if err != nil {
		return "", "", err
	}
	if !strings.HasPrefix(header, "*") {
		return "", "", fmt.Errorf("not a command array: %q", header)
	}
	count, err := strconv.Atoi(strings.TrimSpace(header[1:]))
	if err != nil {
		return "", "", err
	}

	frame := header
	var parts []string
	for i := 0; i < count; i++ {
		lengthLine, err := r.ReadString('\n')
		if err != nil {
			return "", "", err
		}
		frame += lengthLine
		n, err := strconv.Atoi(strings.TrimSpace(lengthLine[1:]))
		if err != nil {
			return "", "", err
		}
		body := make([]byte, n+2)
		if _, err := io.ReadFull(r, body); err != nil {
			return "", "", err
		}
		frame += string(body)
		parts = append(parts, string(body[:n]))
	}
	if len(parts) == 0 {
		return "", "", fmt.Errorf("empty command")
	}
	return strings.ToUpper(parts[0]), frame, nil
}

// --- chain helpers --------------------------------------------------------

type fixedResolver struct{ addresses []netip.Addr }

func (r fixedResolver) LookupAddresses(context.Context, string) ([]netip.Addr, error) {
	return r.addresses, nil
}

// peerDialer sends every connection to the fake endpoint, whatever address the
// chain believes it is dialing.
type peerDialer struct{ target netip.AddrPort }

func (d peerDialer) DialTCP(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", d.target.String())
}

func parseAddrs(t *testing.T, values ...string) []netip.Addr {
	t.Helper()
	out := make([]netip.Addr, 0, len(values))
	for _, v := range values {
		addr, err := netip.ParseAddr(v)
		if err != nil {
			t.Fatalf("netip.ParseAddr(%q): %v", v, err)
		}
		out = append(out, addr)
	}
	return out
}

// sessions runs the real transport chain and the real HELLO pass against p.
func sessions(t *testing.T, p *peer, addresses ...string) (*Result, *domain.GraphBuilder) {
	t.Helper()
	if len(addresses) == 0 {
		addresses = []string{"10.0.0.1"}
	}

	builder := domain.NewGraphBuilder()
	paths, err := transport.Run(context.Background(), builder, transport.Params{
		Host:     "endpoint.internal",
		Port:     6379,
		Resolver: fixedResolver{addresses: parseAddrs(t, addresses...)},
		Dialer:   peerDialer{target: p.addr},
	})
	if err != nil {
		t.Fatalf("transport.Run: %v", err)
	}
	t.Cleanup(func() { _ = paths.Close() })

	result, err := Run(context.Background(), builder, paths.Continuations(), Params{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	t.Cleanup(func() { _ = result.Close() })
	return result, builder
}

// one returns the single session, failing if there is not exactly one.
func one(t *testing.T, result *Result) *Session {
	t.Helper()
	if got := len(result.Sessions()); got != 1 {
		t.Fatalf("got %d sessions, want exactly 1", got)
	}
	return result.Sessions()[0]
}

func freeze(t *testing.T, builder *domain.GraphBuilder) domain.Graph {
	t.Helper()
	graph, err := builder.Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}
	return graph
}

// nodeAt returns the single node recorded at one step.
func nodeAt(t *testing.T, graph domain.Graph, step domain.Step) domain.Evidence {
	t.Helper()
	var found []domain.Evidence
	for _, node := range graph.Nodes() {
		if node.Step() == step {
			found = append(found, node)
		}
	}
	if len(found) != 1 {
		t.Fatalf("got %d nodes at %s, want exactly 1", len(found), step)
	}
	return found[0]
}

func attr(t *testing.T, node domain.Evidence, key domain.AttributeKey) (string, bool) {
	t.Helper()
	value, ok := node.Attribute(key)
	if !ok {
		return "", false
	}
	return value.Str()
}
