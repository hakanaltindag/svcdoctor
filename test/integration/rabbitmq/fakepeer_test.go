//go:build integration

package rabbitmq

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// A minimal AMQP 0-9-1 peer, controllable frame by frame.
//
// The real brokers cannot be made to do the things the credential-authority
// contract forbids: they will not send `Connection.Secure` after a correct
// PLAIN response, and they will not invite a second credential. This peer will,
// which is what makes the "svcdoctor refuses to" assertions measurable rather
// than merely asserted about the source.
//
// It speaks only what these scenarios need, and it counts what they are about:
// how many credential-bearing frames arrived.

const (
	fakeFrameEnd     = 0xCE
	fakeFrameMethod  = 1
	fakeClassConn    = 10
	fakeMethodStart  = 10
	fakeMethodStartK = 11
	fakeMethodSecure = 20
	fakeMethodTune   = 30
	fakeMethodTuneK  = 31
	fakeMethodOpen   = 40
	fakeMethodOpenK  = 41
	fakeMethodClose  = 50
)

// fakeBehaviour decides what the peer does after the first Start-Ok.
type fakeBehaviour int

const (
	// fakeSecureThenNothing answers a correct Start-Ok with Connection.Secure,
	// which is an invitation to send a second credential-bearing frame.
	fakeSecureThenNothing fakeBehaviour = iota
	// fakeCloseAfterCredential drops the connection the moment the credential
	// arrives, which is what a reconnecting client would retry through.
	fakeCloseAfterCredential
	// fakeSilent accepts the socket and never writes a byte, so svcdoctor's own
	// step budget ends the run. It is how RMQ-H4 gets a local timeout with a
	// real credential counter attached: the peer can prove zero frames arrived,
	// which a blackhole address cannot.
	fakeSilent
)

type fakePeer struct {
	listener net.Listener
	behave   fakeBehaviour

	mu sync.Mutex
	// credentialFrames counts Start-Ok frames, each of which carries a
	// credential. More than one in a run is a contract violation.
	credentialFrames int
	// connections counts accepted sockets. More than one is a reconnect.
	connections int

	wg sync.WaitGroup
}

func newFakePeer(t *testing.T, behave fakeBehaviour) *fakePeer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	p := &fakePeer{listener: ln, behave: behave}
	p.wg.Add(1)
	go p.serve()
	t.Cleanup(func() {
		_ = ln.Close()
		p.wg.Wait()
	})
	return p
}

func (p *fakePeer) port() uint16 {
	return uint16(p.listener.Addr().(*net.TCPAddr).Port)
}

func (p *fakePeer) counts() (credentials, connections int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.credentialFrames, p.connections
}

func (p *fakePeer) serve() {
	defer p.wg.Done()
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			return
		}
		p.mu.Lock()
		p.connections++
		p.mu.Unlock()

		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			defer func() { _ = conn.Close() }()
			p.handle(conn)
		}()
	}
}

func (p *fakePeer) handle(conn net.Conn) {
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	// The protocol header.
	header := make([]byte, 8)
	if _, err := io.ReadFull(conn, header); err != nil {
		return
	}
	if p.behave == fakeSilent {
		// Never answer. The socket stays open and svcdoctor's step budget is
		// what ends the run.
		<-time.After(30 * time.Second)
		return
	}
	if _, err := conn.Write(p.startFrame()); err != nil {
		return
	}

	for {
		class, method, err := readFakeMethod(conn)
		if err != nil {
			return
		}
		if class != fakeClassConn {
			return
		}
		switch method {
		case fakeMethodStartK:
			p.mu.Lock()
			p.credentialFrames++
			p.mu.Unlock()

			switch p.behave {
			case fakeSecureThenNothing:
				// Invite a second credential. svcdoctor must refuse.
				if _, err := conn.Write(encodeFake(fakeMethodSecure,
					appendLongstr(nil, []byte("rspauth=")))); err != nil {
					return
				}
			case fakeCloseAfterCredential:
				return
			}
		case fakeMethodTuneK:
			// Not reached by these scenarios; ignore.
		case fakeMethodOpen:
			if _, err := conn.Write(encodeFake(fakeMethodOpenK, []byte{0})); err != nil {
				return
			}
		case fakeMethodClose:
			_, _ = conn.Write(encodeFake(51, nil))
			return
		}
	}
}

// startFrame builds a Connection.Start offering PLAIN.
func (p *fakePeer) startFrame() []byte {
	var payload []byte
	payload = append(payload, 0, 9) // version-major, version-minor

	// server-properties: one entry, product = "FakeMQ".
	var table []byte
	table = append(table, byte(len("product")))
	table = append(table, "product"...)
	table = append(table, 'S')
	table = appendLongstr(table, []byte("FakeMQ"))
	payload = binary.BigEndian.AppendUint32(payload, uint32(len(table)))
	payload = append(payload, table...)

	payload = appendLongstr(payload, []byte("PLAIN"))
	payload = appendLongstr(payload, []byte("en_US"))
	return encodeFake(fakeMethodStart, payload)
}

func encodeFake(method uint16, payload []byte) []byte {
	body := make([]byte, 0, 4+len(payload))
	body = binary.BigEndian.AppendUint16(body, fakeClassConn)
	body = binary.BigEndian.AppendUint16(body, method)
	body = append(body, payload...)

	out := make([]byte, 0, 8+len(body))
	out = append(out, fakeFrameMethod)
	out = binary.BigEndian.AppendUint16(out, 0)
	out = binary.BigEndian.AppendUint32(out, uint32(len(body)))
	out = append(out, body...)
	out = append(out, fakeFrameEnd)
	return out
}

func appendLongstr(dst, s []byte) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(s)))
	return append(dst, s...)
}

func readFakeMethod(conn net.Conn) (class, method uint16, err error) {
	head := make([]byte, 7)
	if _, err = io.ReadFull(conn, head); err != nil {
		return 0, 0, err
	}
	size := binary.BigEndian.Uint32(head[3:7])
	body := make([]byte, size+1) // payload plus frame-end
	if _, err = io.ReadFull(conn, body); err != nil {
		return 0, 0, err
	}
	if size < 4 {
		return 0, 0, io.ErrUnexpectedEOF
	}
	return binary.BigEndian.Uint16(body[0:2]), binary.BigEndian.Uint16(body[2:4]), nil
}
