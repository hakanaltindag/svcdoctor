package wire

import (
	"context"
	"encoding/binary"
	"net"
)

// sslRequestCode is the value PostgreSQL reserves for an SSL negotiation
// request: 1234 in the high 16 bits, 5679 in the low.
//
// It occupies the position a protocol version would, which is how a server tells
// the two apart, and it is why an SSLRequest is not a StartupMessage with a flag.
const sslRequestCode uint32 = 80877103

// sslRequestLength is the whole message: two 32-bit fields, length inclusive.
const sslRequestLength uint32 = 8

// SSLResponse is what a server answered to an SSLRequest.
//
// The set is closed and has exactly the three members the protocol defines. A
// fourth outcome — any other byte — is not a response and comes back as
// ErrUnexpectedResponse, because it means the peer is not speaking this protocol
// and there is nothing to classify.
type SSLResponse uint8

const (
	// SSLAccepted is 'S': the server will perform TLS, and is now waiting for a
	// ClientHello on this connection.
	SSLAccepted SSLResponse = iota + 1

	// SSLDeclined is 'N': the server will not perform TLS. The connection stays
	// usable in the clear.
	SSLDeclined

	// SSLErrored is 'E': the server answered with an ErrorResponse.
	//
	// **The message is not read and not returned.** At this point the peer is
	// unauthenticated — no certificate has been verified, and anyone able to
	// answer the socket can produce these bytes — so its text must not be shown
	// to a user or stored (CVE-2024-10977). The fact that an error-shaped answer
	// arrived is the whole of what svcdoctor may claim, and the connection must
	// be closed.
	SSLErrored
)

// String returns a stable name for logs and tests.
func (r SSLResponse) String() string {
	switch r {
	case SSLAccepted:
		return "accepted"
	case SSLDeclined:
		return "declined"
	case SSLErrored:
		return "errored"
	default:
		return "invalid"
	}
}

// EncodeSSLRequest returns the eight bytes of an SSLRequest.
//
// It is separate from SendSSLRequest so a test can assert the exact bytes
// without a connection, which is the only way to catch a wrong constant: a
// round-trip through this package's own decoder would agree with itself.
func EncodeSSLRequest() []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint32(buf[0:4], sslRequestLength)
	binary.BigEndian.PutUint32(buf[4:8], sslRequestCode)
	return buf
}

// SendSSLRequest writes an SSLRequest and reads the server's single-byte answer.
//
// The connection is borrowed. On every outcome, including an error, it is left
// open and deadline-free for the caller to close or hand onward — because on
// SSLAccepted the caller's next act is a TLS handshake over this exact socket.
//
// # Exactly one byte, and nothing buffered
//
// This is the security-critical part of the exchange, and it is written the way
// it is for two reasons that are easy to get wrong.
//
// **Nothing is buffered.** The read goes straight to the connection into a local
// array. There is no bufio.Reader anywhere on this path, so no byte can be read
// out of the socket and stranded in a buffer the TLS handshake will never see.
// That stranding is CVE-2021-23222: bytes a man in the middle injected before the
// handshake get retained by the client and then processed as though they had
// arrived inside the encrypted stream. A reader that prefetches would reintroduce
// it silently, which is why this function does its own read rather than sharing
// a reader with the framing code below.
//
// **A surplus byte is refused.** The protocol says a server willing to do TLS
// sends the single byte and then waits, so anything else already readable is
// evidence of stuffing. The read therefore asks for two bytes and requires that
// exactly one arrive.
//
// Asking for two costs one syscall and no latency: a clean server returns one
// byte immediately, and the extra capacity is only ever filled by data that had
// already arrived. The obvious alternative — read one byte, then probe with an
// expired read deadline — was tried and **does not work**: Go's poller checks the
// deadline before consulting the socket, so an expired one returns i/o timeout
// even when stuffed bytes are sitting in the kernel buffer. It reported a clean
// connection for both stuffing cases in a direct experiment, which is a false
// negative on a security check.
//
// What this does not catch is a byte that arrives strictly after the read. That
// byte is not stranded anywhere — it goes to the TLS handshake, which is
// precisely the layer equipped to reject it as a malformed record. The property
// being guaranteed is that **this package retains no pre-TLS byte**, which it
// achieves structurally by keeping none.
func SendSSLRequest(ctx context.Context, conn net.Conn) (SSLResponse, error) {
	if conn == nil {
		return 0, ErrInvalidInput
	}

	release := bindDeadline(ctx, conn)
	defer release()

	if err := writeAll(conn, EncodeSSLRequest()); err != nil {
		return 0, err
	}
	return readSSLResponse(conn)
}

// readSSLResponse reads the one byte the negotiation allows, and refuses more.
func readSSLResponse(conn net.Conn) (SSLResponse, error) {
	// Two bytes of capacity, one byte of permitted answer. A single Read
	// returns everything already available up to the buffer size, so n == 2 is
	// exactly the stuffing case.
	var buf [2]byte
	n, err := conn.Read(buf[:])
	if n == 0 {
		if err != nil {
			return 0, translateReadError(err)
		}
		return 0, ErrPeerClosed
	}
	if n > 1 {
		return 0, ErrSurplusBytes
	}

	switch buf[0] {
	case 'S':
		return SSLAccepted, nil
	case 'N':
		return SSLDeclined, nil
	case 'E':
		return SSLErrored, nil
	default:
		// Not a response to this message. An HTTP server answers 'H' here.
		return 0, ErrUnexpectedResponse
	}
}

// translateReadError maps a failed read onto the sentinels, leaving anything
// deadline-shaped alone so the adapter can decide whose deadline it was.
func translateReadError(err error) error {
	if isEOF(err) {
		return ErrPeerClosed
	}
	return err
}
