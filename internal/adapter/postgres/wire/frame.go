package wire

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
)

// Message type bytes this package recognizes structurally.
//
// The list is not a claim about which messages are expected: deciding that is
// the state machine's job, one layer up. These are the ones something in
// svcdoctor decodes today.
const (
	// MsgAuthentication is 'R', the server naming the authentication it demands.
	MsgAuthentication byte = 'R'
	// MsgErrorResponse is 'E'.
	MsgErrorResponse byte = 'E'
	// MsgNoticeResponse is 'N', which may precede almost anything and is not a
	// decisive answer to any request.
	MsgNoticeResponse byte = 'N'
	// MsgNegotiateProtocolVersion is 'v', the server offering an older minor
	// version than the one requested.
	MsgNegotiateProtocolVersion byte = 'v'
)

// Message is one framed server message, decoded no further than its envelope.
//
// Body is a copy owned by the caller and never aliases a shared buffer, so a
// caller may hold one message while reading the next.
//
// An unknown Type is returned rather than rejected. PostgreSQL is explicitly
// extensible here, and framing has no opinion about which messages are legal at
// which point — a NoticeResponse may precede almost anything, and a message a
// future server adds should not turn a diagnostic run into a decode failure. The
// caller decides whether what arrived was expected.
type Message struct {
	Type byte
	Body []byte
}

// ReadMessage reads one framed server message.
//
// The frame is a type byte, then a 32-bit length that **includes itself** and
// excludes the type byte, then the body. So a body of n bytes is announced as
// n+4, and the smallest legal frame announces exactly 4.
//
// The connection is borrowed and never closed. Deadlines derived from ctx are
// cleared before returning.
func ReadMessage(ctx context.Context, conn net.Conn) (Message, error) {
	if conn == nil {
		return Message{}, ErrInvalidInput
	}

	release := bindDeadline(ctx, conn)
	defer release()

	return readMessage(conn)
}

// readMessage is the deadline-free core, so that a caller reading several
// messages under one context does not rebind per message.
func readMessage(conn net.Conn) (Message, error) {
	var header [5]byte
	if err := readFull(conn, header[:]); err != nil {
		return Message{}, err
	}

	length := binary.BigEndian.Uint32(header[1:5])

	// The length counts itself, so anything below four cannot describe a frame.
	// Rejecting it here is what stops the subtraction below from wrapping.
	if length < 4 {
		return Message{}, ErrMalformedMessage
	}
	bodyLen := length - 4

	// Checked against svcdoctor's own bound before any allocation, so a peer
	// announcing four gibibytes costs nothing but the header already read.
	if bodyLen > MaxMessageSize {
		return Message{}, ErrFrameTooLarge
	}

	msg := Message{Type: header[0]}
	if bodyLen == 0 {
		return msg, nil
	}

	msg.Body = make([]byte, bodyLen)
	if err := readFull(conn, msg.Body); err != nil {
		return Message{}, err
	}
	return msg, nil
}

// isEOF reports whether err means the peer stopped sending.
func isEOF(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}
