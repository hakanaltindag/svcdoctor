package wire

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"
)

// TestSSLRequestBytesAreExact decodes the request independently instead of
// round-tripping it, because a round trip through this package's own encoder
// would agree with itself whatever constant it used.
func TestSSLRequestBytesAreExact(t *testing.T) {
	got := EncodeSSLRequest()

	if len(got) != 8 {
		t.Fatalf("SSLRequest is %d bytes, want exactly 8", len(got))
	}
	if length := binary.BigEndian.Uint32(got[0:4]); length != 8 {
		t.Errorf("length field = %d, want 8", length)
	}
	if code := binary.BigEndian.Uint32(got[4:8]); code != 80877103 {
		t.Errorf("request code = %d, want 80877103 (1234 << 16 | 5679)", code)
	}
	// The literal bytes, so a change to either constant is visible in the diff.
	if want := []byte{0, 0, 0, 8, 4, 210, 22, 47}; !bytes.Equal(got, want) {
		t.Errorf("SSLRequest = % x, want % x", got, want)
	}
}

// TestSSLRequestWritesExactlyEightBytes proves nothing else joins the request on
// the wire. A stray byte here would be read by the server as the start of a TLS
// ClientHello.
func TestSSLRequestWritesExactlyEightBytes(t *testing.T) {
	p := scriptedPeer(t, func(conn net.Conn, p *peer) {
		defer conn.Close()
		respondToSSLRequest(conn, p, []byte("N"))
		// Hold the connection so the client's read cannot race the close.
		time.Sleep(200 * time.Millisecond)
	})

	conn := p.dial(t)
	if _, err := SendSSLRequest(testContext(t), conn); err != nil {
		t.Fatalf("SendSSLRequest: %v", err)
	}

	p.waitForBytes(t, 8)
	if got := p.bytesReceived(); !bytes.Equal(got, EncodeSSLRequest()) {
		t.Errorf("peer received % x, want % x", got, EncodeSSLRequest())
	}
}

// TestSSLResponses covers the three answers the protocol defines and the one it
// does not.
func TestSSLResponses(t *testing.T) {
	cases := []struct {
		name  string
		reply []byte
		want  SSLResponse
		err   error
	}{
		{"accepted", []byte("S"), SSLAccepted, nil},
		{"declined", []byte("N"), SSLDeclined, nil},
		{"errored", []byte("E"), SSLErrored, nil},
		{"http server", []byte("H"), 0, ErrUnexpectedResponse},
		{"zero byte", []byte{0}, 0, ErrUnexpectedResponse},
		{"lowercase s", []byte("s"), 0, ErrUnexpectedResponse},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := scriptedPeer(t, func(conn net.Conn, p *peer) {
				defer conn.Close()
				respondToSSLRequest(conn, p, tc.reply)
				time.Sleep(200 * time.Millisecond)
			})

			got, err := SendSSLRequest(testContext(t), p.dial(t))
			if !errors.Is(err, tc.err) {
				t.Fatalf("err = %v, want %v", err, tc.err)
			}
			if got != tc.want {
				t.Errorf("response = %s, want %s", got, tc.want)
			}
		})
	}
}

// TestSurplusBytesAreRefused is the CVE-2021-23222 guard, and the most important
// test in this package.
//
// A man in the middle that can write to the socket before the handshake sends
// the negotiation byte followed by bytes of its choosing. A client that buffered
// them would later process them as though they had arrived inside the encrypted
// stream. svcdoctor refuses the connection instead.
//
// Both the accepted and the declined answer are covered: the protocol permits
// exactly one byte either way, and a surplus after 'N' is the same evidence of a
// peer that is not behaving as the protocol describes.
func TestSurplusBytesAreRefused(t *testing.T) {
	for _, first := range []string{"S", "N"} {
		t.Run(first, func(t *testing.T) {
			p := scriptedPeer(t, func(conn net.Conn, p *peer) {
				defer conn.Close()
				// One legal byte, then attacker-chosen plaintext, in one write
				// so that both land in the receive buffer together.
				respondToSSLRequest(conn, p, []byte(first+"INJECTED-PLAINTEXT-CANARY"))
				time.Sleep(300 * time.Millisecond)
			})

			got, err := SendSSLRequest(testContext(t), p.dial(t))
			if !errors.Is(err, ErrSurplusBytes) {
				t.Fatalf("err = %v, want ErrSurplusBytes: a peer stuffed the socket "+
					"before the handshake and svcdoctor accepted it", err)
			}
			if got != 0 {
				t.Errorf("response = %s, want none on a refused negotiation", got)
			}
		})
	}
}

// TestNothingIsBufferedBeforeTheHandshake is the structural half of the guard
// above.
//
// The surplus check catches bytes that have already arrived. This asserts the
// stronger property that makes the CVE class impossible rather than merely
// detected: after reading the negotiation byte, **every remaining byte is still
// in the socket**. If this package used a bufio.Reader, the bytes below would
// have been swallowed into it and the connection handed to TLS would be missing
// them.
func TestNothingIsBufferedBeforeTheHandshake(t *testing.T) {
	const following = "BYTES-THE-NEXT-LAYER-MUST-STILL-SEE"

	p := scriptedPeer(t, func(conn net.Conn, p *peer) {
		defer conn.Close()
		if !readN(conn, p, 8) {
			return
		}
		// The negotiation byte alone, then — after the client has certainly
		// read it — the bytes a handshake would consume.
		_, _ = conn.Write([]byte("S"))
		time.Sleep(150 * time.Millisecond)
		_, _ = conn.Write([]byte(following))
		time.Sleep(300 * time.Millisecond)
	})

	conn := p.dial(t)
	response, err := SendSSLRequest(testContext(t), conn)
	if err != nil {
		t.Fatalf("SendSSLRequest: %v", err)
	}
	if response != SSLAccepted {
		t.Fatalf("response = %s, want accepted", response)
	}

	// Read what a TLS handshake would have read. Every byte must still be here.
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, len(following))
	total := 0
	for total < len(following) {
		n, readErr := conn.Read(buf[total:])
		total += n
		if readErr != nil {
			break
		}
	}
	if got := string(buf[:total]); got != following {
		t.Errorf("the next layer would have read %q, want %q: bytes were stranded in a "+
			"buffer the TLS handshake never sees", got, following)
	}
}

// TestSSLRequestDoesNotLeaveADeadlineBehind is an ownership guard.
//
// The connection this runs over is handed straight to a TLS handshake. A
// deadline surviving the call would expire inside somebody else's exchange and
// be misattributed to them.
func TestSSLRequestDoesNotLeaveADeadlineBehind(t *testing.T) {
	p := scriptedPeer(t, func(conn net.Conn, p *peer) {
		defer conn.Close()
		if !readN(conn, p, 8) {
			return
		}
		_, _ = conn.Write([]byte("N"))
		// Answer a later read well after any deadline the exchange used.
		time.Sleep(400 * time.Millisecond)
		_, _ = conn.Write([]byte("X"))
		time.Sleep(300 * time.Millisecond)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	conn := p.dial(t)
	if _, err := SendSSLRequest(ctx, conn); err != nil {
		t.Fatalf("SendSSLRequest: %v", err)
	}

	// The exchange's context has expired by now. **No new deadline is set**:
	// setting one would overwrite the stale deadline this test exists to
	// detect, and the check would pass whether or not it was cleared.
	time.Sleep(300 * time.Millisecond)
	var b [1]byte
	if _, err := conn.Read(b[:]); err != nil {
		t.Fatalf("reading after the exchange failed: %v; the deadline was not cleared", err)
	}
	if b[0] != 'X' {
		t.Errorf("read %q, want %q", b[0], byte('X'))
	}
}

// TestSSLRequestPeerClosedBeforeAnswering distinguishes a peer that went away
// from a peer that said something wrong.
func TestSSLRequestPeerClosedBeforeAnswering(t *testing.T) {
	p := scriptedPeer(t, func(conn net.Conn, p *peer) {
		readN(conn, p, 8)
		_ = conn.Close()
	})

	_, err := SendSSLRequest(testContext(t), p.dial(t))
	if !errors.Is(err, ErrPeerClosed) {
		t.Errorf("err = %v, want ErrPeerClosed", err)
	}
}

// TestSSLRequestRespectsCancellation proves the caller's context can interrupt a
// read that is already waiting, which a context alone cannot do.
func TestSSLRequestRespectsCancellation(t *testing.T) {
	p := scriptedPeer(t, func(conn net.Conn, p *peer) {
		defer conn.Close()
		readN(conn, p, 8)
		// Never answer.
		time.Sleep(3 * time.Second)
	})

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	if _, err := SendSSLRequest(ctx, p.dial(t)); err == nil {
		t.Fatal("a cancelled exchange returned no error")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("cancellation took %s; the context did not interrupt the read", elapsed)
	}
}

// TestSSLRequestRejectsNilConnection pins the input guard.
func TestSSLRequestRejectsNilConnection(t *testing.T) {
	if _, err := SendSSLRequest(context.Background(), nil); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("err = %v, want ErrInvalidInput", err)
	}
}
