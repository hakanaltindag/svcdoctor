//go:build integration

package redis

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"

	diagnosisredis "github.com/hakanaltindag/svcdoctor/internal/diagnosis/redis"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	serviceredis "github.com/hakanaltindag/svcdoctor/internal/service/redis"
)

// The HELLO-argument-echo negative control.
//
// # Why this test exists at all
//
// Redis echoes up to 128 bytes of an unknown command's *arguments* back to the
// caller and into its own log (redis/src/server.c:4378-4389), and the redaction
// that would prevent it lives inside helloCommand — so it never runs on the path
// where HELLO is unknown. A client that sent `HELLO 3 AUTH user password` to a
// server predating Redis 6.0, to a proxy, or to a deployment that renamed the
// command would have its password echoed back and written to a log it does not
// own.
//
// ADR 0064 answers that structurally: HELLO carries zero arguments, so there is
// nothing to echo. This test is the proof, and it is deliberately built around a
// **maximally hostile** peer rather than a merely old one.
//
// # The peer echoes everything, on purpose
//
// It refuses HELLO with an unknown-command error that reflects every argument it
// received, uppercased and quoted, exactly as Redis does — and then it keeps
// serving, so the run continues to AUTH and PING. If svcdoctor ever put a
// credential in HELLO, the credential would come straight back and land in the
// evidence this test scans.
type echoingPeer struct {
	addr     net.Addr
	mu       chan struct{}
	received []string
}

func newEchoingPeer(t *testing.T) *echoingPeer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	p := &echoingPeer{addr: listener.Addr(), mu: make(chan struct{}, 1)}
	p.mu <- struct{}{}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go p.serve(conn)
		}
	}()
	return p
}

func (p *echoingPeer) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	reader := bufio.NewReader(conn)

	for {
		command, args, err := readCommandAndArgs(reader)
		if err != nil {
			return
		}
		<-p.mu
		p.received = append(p.received, command+" "+strings.Join(args, " "))
		p.mu <- struct{}{}

		var reply string
		switch command {
		case "HELLO":
			// The hostile part: every argument comes back, exactly as Redis
			// builds it at server.c:4386.
			echoed := ""
			for _, a := range args {
				echoed += "'" + a + "' "
			}
			reply = fmt.Sprintf("-ERR unknown command 'HELLO', with args beginning with: %s\r\n", echoed)
		case "AUTH":
			reply = "+OK\r\n"
		case "PING":
			reply = "+PONG\r\n"
		default:
			reply = "-ERR unknown command\r\n"
		}
		if _, err := conn.Write([]byte(reply)); err != nil {
			return
		}
	}
}

func (p *echoingPeer) commands() []string {
	<-p.mu
	out := append([]string(nil), p.received...)
	p.mu <- struct{}{}
	return out
}

func readCommandAndArgs(r *bufio.Reader) (string, []string, error) {
	header, err := r.ReadString('\n')
	if err != nil {
		return "", nil, err
	}
	if !strings.HasPrefix(header, "*") {
		return "", nil, fmt.Errorf("not a command array: %q", header)
	}
	count, err := strconv.Atoi(strings.TrimSpace(header[1:]))
	if err != nil {
		return "", nil, err
	}
	var parts []string
	for i := 0; i < count; i++ {
		lengthLine, err := r.ReadString('\n')
		if err != nil {
			return "", nil, err
		}
		n, err := strconv.Atoi(strings.TrimSpace(lengthLine[1:]))
		if err != nil {
			return "", nil, err
		}
		body := make([]byte, n+2)
		if _, err := readFull(r, body); err != nil {
			return "", nil, err
		}
		parts = append(parts, string(body[:n]))
	}
	if len(parts) == 0 {
		return "", nil, fmt.Errorf("empty command")
	}
	return strings.ToUpper(parts[0]), parts[1:], nil
}

func readFull(r *bufio.Reader, buf []byte) (int, error) {
	read := 0
	for read < len(buf) {
		n, err := r.Read(buf[read:])
		read += n
		if err != nil {
			return read, err
		}
	}
	return read, nil
}

// TestHelloUnknownCannotEchoACredential is the control.
func TestHelloUnknownCannotEchoACredential(t *testing.T) {
	const canary = "CANARY-PASSWORD-9f3a1c"

	peer := newEchoingPeer(t)
	addr := peer.addr.(*net.TCPAddr)

	result := run(t, runOptions{host: "127.0.0.1", port: uint16(addr.Port), password: canary})

	// 1. The HELLO that left svcdoctor carried no arguments at all.
	var helloCommands int
	for _, command := range peer.commands() {
		if !strings.HasPrefix(command, "HELLO") {
			continue
		}
		helloCommands++
		if strings.TrimSpace(command) != "HELLO" {
			t.Fatalf("HELLO reached the peer with arguments: %q.\n\n"+
				"This is the exact shape ADR 0064 section 1 forbids: a hostile peer "+
				"echoes them, and the credential is one of them.", command)
		}
	}
	if helloCommands == 0 {
		t.Fatal("no HELLO reached the peer; this control would pass vacuously")
	}

	// 2. The peer really is hostile: it echoed what it received.
	node := oneNodeAt(t, result, stepHello)
	if node.FailureClass() != domain.FailureProtocolUnsupportedCapability {
		t.Fatalf("failure class = %s, want PROTOCOL_UNSUPPORTED_CAPABILITY", node.FailureClass())
	}
	if _, ok := attrOf(t, node, serviceredis.AttrMode); ok {
		t.Error("mode was recorded from an endpoint that does not implement HELLO")
	}

	// 3. Nothing the peer echoed reached the report, and neither did the secret.
	text := findingText(result)
	if strings.Contains(text, canary) {
		t.Fatalf("the credential reached the report:\n%s", text)
	}
	if strings.Contains(text, "with args beginning with") {
		t.Fatal("the peer's raw error text reached the report")
	}

	// 4. The run continued past the unknown HELLO, and AUTH happened at most once.
	authCount := 0
	for _, command := range peer.commands() {
		if strings.HasPrefix(command, "AUTH") {
			authCount++
		}
	}
	if authCount > 1 {
		t.Fatalf("AUTH reached the peer %d times, want at most 1", authCount)
	}
	if hasCode(result, diagnosisredis.CodeProtocolNotEstablished) {
		t.Error("an endpoint that merely lacks HELLO produced a protocol failure finding")
	}
}
