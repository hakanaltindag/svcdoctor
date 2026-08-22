package wire

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
)

// ProtocolVersion30 is protocol 3.0: major 3 in the high 16 bits, minor 0 in the
// low.
//
// 3.0 is what svcdoctor requests, and the choice is conservative on purpose.
// Every server in the supported window accepts it with no negotiation round trip,
// while requesting 3.2 makes an older server answer NegotiateProtocolVersion
// first — measured on PostgreSQL 14.24 in the Phase 4.0 study — and buys nothing
// svcdoctor reads. See ADR 0036 section 12.1.
const ProtocolVersion30 uint32 = 196608

// maxStartupParameters bounds how many key/value pairs may be encoded.
//
// The implemented slice sends at most two. The bound exists so that a future
// caller cannot turn a startup packet into an unbounded write, and it is set far
// enough above the real number that it is never reached by anything sensible.
const maxStartupParameters = 16

// StartupParams is what svcdoctor puts in a StartupMessage.
//
// Deliberately two fields. `user` is the only parameter the protocol requires,
// and `database` is the only optional one svcdoctor has a reason to send: it
// selects the resource whose existence and reachability the session is about.
//
// Nothing else is sent. `application_name`, `client_encoding`, `options` and
// `replication` are all available and all omitted, because a diagnostic tool
// should minimize both what it asks a server to do and what it puts in that
// server's logs. Adding one needs a reason, not availability.
//
// **There is no password field, and there is no security.Secret field.** Phase
// 4.3 authenticates nothing; a credential has no path into this struct, which is
// what makes "no credential is sent" a property of the type rather than a
// promise about the code.
type StartupParams struct {
	// User is the role to connect as. Required by the protocol: there is no
	// anonymous startup.
	User string

	// Database is the database to connect to. Optional on the wire — a server
	// that receives no database parameter defaults to one named after the user.
	Database string
}

// validate rejects what cannot be encoded into a well-formed startup packet.
func (p StartupParams) validate() error {
	if p.User == "" {
		return ErrInvalidInput
	}
	// A NUL would terminate the value early and silently change which role or
	// database the server sees, which is an injection rather than a formatting
	// problem. It is refused rather than escaped: the protocol has no escape.
	if strings.ContainsRune(p.User, 0) || strings.ContainsRune(p.Database, 0) {
		return ErrInvalidInput
	}
	return nil
}

// EncodeStartup returns the bytes of a StartupMessage.
//
// Layout is a 32-bit length including itself, a 32-bit protocol version, then
// NUL-terminated key and value strings in pairs, then a final NUL where the next
// key would begin.
//
// It is exported separately from SendStartup so a test can decode the bytes
// independently instead of round-tripping them through the encoder that produced
// them, which would only prove the encoder agrees with itself.
func EncodeStartup(p StartupParams) ([]byte, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}

	pairs := make([]string, 0, 4)
	pairs = append(pairs, "user", p.User)
	if p.Database != "" {
		pairs = append(pairs, "database", p.Database)
	}
	if len(pairs)/2 > maxStartupParameters {
		return nil, ErrInvalidInput
	}

	size := 4 + 4 + 1
	for _, s := range pairs {
		size += len(s) + 1
	}

	buf := make([]byte, 0, size)
	buf = binary.BigEndian.AppendUint32(buf, uint32(size))
	buf = binary.BigEndian.AppendUint32(buf, ProtocolVersion30)
	for _, s := range pairs {
		buf = append(buf, s...)
		buf = append(buf, 0)
	}
	buf = append(buf, 0)
	return buf, nil
}

// SendStartup writes a StartupMessage.
//
// The connection is borrowed and left open and deadline-free, because the
// caller's next act is to read the server's first reply over the same socket.
//
// Nothing is read here. Sending and interpreting the answer are separate so that
// the state machine above owns which replies are legal, and so that a caller can
// bound the write and the read differently if it ever needs to.
func SendStartup(ctx context.Context, conn net.Conn, p StartupParams) error {
	if conn == nil {
		return ErrInvalidInput
	}
	buf, err := EncodeStartup(p)
	if err != nil {
		return err
	}

	release := bindDeadline(ctx, conn)
	defer release()

	return writeAll(conn, buf)
}
