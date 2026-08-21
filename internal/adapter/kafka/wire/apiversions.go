package wire

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"time"

	"github.com/twmb/franz-go/pkg/kmsg"
)

const (
	// clientID identifies svcdoctor in the broker's logs. It is fixed rather
	// than configurable: a diagnostic tool should be recognizable, and nothing
	// yet needs to pretend to be something else.
	clientID = "svcdoctor"

	// apiVersionsRequestVersion is the version of ApiVersions svcdoctor sends.
	//
	// Version 0 is deliberate. Every broker that speaks ApiVersions at all
	// answers v0, so the request cannot itself become the reason a peer refuses
	// to describe its capabilities. Asking for a newer version would make the
	// probe's own choice part of the result.
	apiVersionsRequestVersion = 0

	// maxResponseSize bounds what a peer can make svcdoctor allocate. A peer
	// that is not Kafka usually announces a nonsensical size here, which is how
	// ErrNotKafka is recognized.
	maxResponseSize = 8 << 20

	// correlationID is fixed because exactly one request is in flight. Echoing
	// it back is what proves the response belongs to the request that was sent.
	// It is unsigned here only so the response comparison needs no conversion;
	// the protocol field is a signed int32 and kmsg writes it as one.
	correlationID uint32 = 1
)

// Sentinel errors describing what was observed on the wire.
//
// They exist so that the layer above can classify structurally. Matching on
// error text would be a claim that quietly stops being true when a library or a
// platform changes its wording.
var (
	// ErrPeerClosed means the peer closed the connection during the exchange.
	ErrPeerClosed = errors.New("peer closed the connection during the exchange")

	// ErrNotKafka means the peer answered with something that is not Kafka
	// framing at all.
	ErrNotKafka = errors.New("peer response is not kafka framing")

	// ErrMalformedResponse means the framing was plausible but the response
	// could not be decoded, or answered a different request.
	ErrMalformedResponse = errors.New("kafka response could not be decoded")
)

// APIKeyRange is one API key the peer advertised, with the version range it
// supports for it.
type APIKeyRange struct {
	Key        int16
	MinVersion int16
	MaxVersion int16
}

// APIVersions is what one ApiVersions exchange observed, in plain Go values.
type APIVersions struct {
	// ErrorCode is the broker's own error code, zero when it reported none.
	ErrorCode int16

	// Keys is what the peer advertised, in the order it sent them. Canonical
	// ordering is the caller's business, because ordering is a report concern.
	Keys []APIKeyRange
}

// RequestAPIVersion reports which version of ApiVersions was asked for, so that
// the recorded evidence can say what the exchange actually was.
func RequestAPIVersion() int16 { return apiVersionsRequestVersion }

// ExchangeAPIVersions sends one ApiVersions request over conn and reads the
// response.
//
// The connection is borrowed, not owned: this function never closes it, because
// whether a connection survives its exchange is an ownership decision for the
// caller. Deadlines set here for the exchange are cleared before returning, so a
// connection handed on afterwards behaves as though nothing happened to it.
func ExchangeAPIVersions(ctx context.Context, conn net.Conn) (APIVersions, error) {
	if conn == nil {
		return APIVersions{}, errors.New("wire: connection must not be nil")
	}

	release := bindDeadline(ctx, conn)
	defer release()

	if err := writeRequest(conn); err != nil {
		return APIVersions{}, err
	}
	return readResponse(conn)
}

// bindDeadline makes the caller's context able to interrupt blocking I/O.
//
// A context alone cannot stop a Read that is already waiting, so the context's
// deadline is applied to the socket and a watcher expires it if the context ends
// first. The returned function clears both, which is what leaves the connection
// clean for whoever uses it next.
func bindDeadline(ctx context.Context, conn net.Conn) func() {
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			// Expiring the deadline unblocks whichever side is waiting.
			_ = conn.SetDeadline(time.Now())
		case <-done:
		}
	}()

	return func() {
		close(done)
		_ = conn.SetDeadline(time.Time{})
	}
}

// writeRequest encodes and sends the request.
//
// kmsg produces the entire message, length prefix and request header included,
// so nothing about the protocol's shape is written by hand here.
func writeRequest(conn net.Conn) error {
	request := kmsg.NewPtrApiVersionsRequest()
	request.SetVersion(apiVersionsRequestVersion)

	formatter := kmsg.NewRequestFormatter(kmsg.FormatterClientID(clientID))
	encoded := formatter.AppendRequest(nil, request, int32(correlationID))

	if _, err := conn.Write(encoded); err != nil {
		return writeError(err)
	}
	return nil
}

// readResponse reads one framed response and decodes it.
func readResponse(conn net.Conn) (APIVersions, error) {
	var sizeBuf [4]byte
	if _, err := io.ReadFull(conn, sizeBuf[:]); err != nil {
		return APIVersions{}, readError(err)
	}

	// Kafka sizes are signed 32-bit and always positive, so anything with the
	// sign bit set is not a Kafka frame at all. Checking that before converting
	// keeps the decode honest about what the wire actually allows.
	announced := binary.BigEndian.Uint32(sizeBuf[:])
	if announced > math.MaxInt32 {
		return APIVersions{}, fmt.Errorf("%w: announced a negative response size", ErrNotKafka)
	}
	size := int64(announced)
	if size < 4 || size > maxResponseSize {
		// A peer speaking anything else — HTTP, TLS on a plaintext port, a
		// greeting banner — announces a length here that Kafka never would.
		return APIVersions{}, fmt.Errorf("%w: announced response size %d", ErrNotKafka, size)
	}

	body := make([]byte, size)
	if _, err := io.ReadFull(conn, body); err != nil {
		return APIVersions{}, readError(err)
	}

	// The ApiVersions response header is v0 whatever the request version is, so
	// the body starts with the correlation identifier and nothing else. The
	// comparison stays in unsigned space: the identifier is an opaque echo here,
	// and reinterpreting its sign would add a conversion without adding meaning.
	if echoed := binary.BigEndian.Uint32(body[:4]); echoed != correlationID {
		return APIVersions{}, fmt.Errorf(
			"%w: response carries correlation id %d", ErrMalformedResponse, echoed)
	}

	response := kmsg.NewPtrApiVersionsResponse()
	response.SetVersion(apiVersionsRequestVersion)
	if err := response.ReadFrom(body[4:]); err != nil {
		return APIVersions{}, fmt.Errorf("%w: %w", ErrMalformedResponse, err)
	}

	return normalize(response), nil
}

// normalize copies the response into plain values, which is what keeps every
// kmsg type inside this package.
func normalize(response *kmsg.ApiVersionsResponse) APIVersions {
	keys := make([]APIKeyRange, 0, len(response.ApiKeys))
	for _, key := range response.ApiKeys {
		keys = append(keys, APIKeyRange{
			Key:        key.ApiKey,
			MinVersion: key.MinVersion,
			MaxVersion: key.MaxVersion,
		})
	}
	return APIVersions{ErrorCode: response.ErrorCode, Keys: keys}
}

// readError and writeError name what happened on the socket.
//
// An end of file mid-exchange is the peer hanging up, which is a different fact
// from a decoding failure: one says the peer stopped talking, the other says it
// said something svcdoctor could not read.
func readError(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("%w: %w", ErrPeerClosed, err)
	}
	return err
}

func writeError(err error) error {
	if errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("%w: %w", ErrPeerClosed, err)
	}
	return err
}
