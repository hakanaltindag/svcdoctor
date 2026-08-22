package wire

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
)

// The message type bytes the session-establishment window uses.
//
// They join the four already named in frame.go for the same reason those were:
// something in svcdoctor decodes them today.
const (
	// MsgParameterStatus is 'S', the server reporting a run-time parameter.
	MsgParameterStatus byte = 'S'
	// MsgBackendKeyData is 'K', the cancellation key svcdoctor discards.
	MsgBackendKeyData byte = 'K'
	// MsgReadyForQuery is 'Z', the frame that ends session establishment.
	MsgReadyForQuery byte = 'Z'
)

// msgTerminate is 'X', the only message svcdoctor sends after startup.
const msgTerminate byte = 'X'

// Transaction status bytes carried by ReadyForQuery.
const (
	// TransactionIdle is 'I': not inside a transaction block.
	TransactionIdle byte = 'I'
	// TransactionActive is 'T': inside a transaction block.
	TransactionActive byte = 'T'
	// TransactionFailed is 'E': inside a failed transaction block.
	TransactionFailed byte = 'E'
)

// backendKeyDataMinimum is the smallest structurally plausible BackendKeyData.
//
// Under protocol 3.0 — the version svcdoctor requests — the frame is exactly
// eight bytes: a 32-bit process ID and a 32-bit secret key. Protocol 3.2 widens
// the secret to 32 bytes, so the check is a floor rather than an equality: a
// truncated frame is a real signal about the peer, while a longer one would only
// matter to code that parsed it, and nothing here does.
const backendKeyDataMinimum = 8

// Parameter is one allowlisted ParameterStatus value.
//
// Present is separate from Value because an absent parameter and a parameter
// reported as the empty string are different observations, and the evidence model
// distinguishes them: an absent fact is a missing key, not a zero value.
type Parameter struct {
	Value   string
	Present bool
}

// SessionParameters is every ParameterStatus value svcdoctor retains, and there
// is deliberately nowhere to put the rest.
//
// # The allowlist is the type
//
// A real PostgreSQL 18.6 backend sends fifteen parameters before ReadyForQuery
// and a 14.24 backend sends thirteen. Two of them are identity —
// `session_authorization` is the role, and `search_path` carries `"$user"` and
// deployment schema names — and the remainder have no diagnostic consumer.
//
// So this struct has four fields and no map, no slice and no catch-all.
// **Structural absence is the mechanism**: a caller cannot leak a parameter this
// type cannot hold, and a future edit that wanted to retain one would have to add
// a field here first, which is a visible change with a reason attached. That is
// the same arrangement ErrorFields makes for the fields of an ErrorResponse.
//
// The values are the server's own strings, uninterpreted. `in_hot_standby` is
// retained as "on" or "off" rather than as a boolean, because turning it into
// `replica = true` would be a semantic claim, and this layer records facts.
// See ADR 0039 sections 3 and 7.
type SessionParameters struct {
	ServerVersion              Parameter
	InHotStandby               Parameter
	DefaultTransactionReadOnly Parameter
	IsSuperuser                Parameter
}

// ApplyParameterStatus decodes one ParameterStatus body and retains its value
// only if the key is one of the four.
//
// # Duplicates take the last value
//
// A ParameterStatus reports what a run-time parameter *is*, and the protocol
// emits another one whenever it changes. If the same key arrives twice before
// ReadyForQuery, the later frame describes the session's state and the earlier
// one describes a state it has left, so the later one wins.
//
// That is the opposite of DecodeErrorFields, which takes the first occurrence,
// and the two are not in tension: there the duplicates are fields *inside one
// message*, where a last-wins reader could be steered by anything able to append
// to a field list. Here they are separate frames whose whole purpose is to
// supersede. Different situations, different rules, both written down.
//
// A body that is not two NUL-terminated strings is malformed: the sender
// announced a shape it did not honour.
func (p *SessionParameters) ApplyParameterStatus(body []byte) error {
	key, value, err := decodeParameterStatus(body)
	if err != nil {
		return err
	}

	switch key {
	case "server_version":
		p.ServerVersion = Parameter{Value: value, Present: true}
	case "in_hot_standby":
		p.InHotStandby = Parameter{Value: value, Present: true}
	case "default_transaction_read_only":
		p.DefaultTransactionReadOnly = Parameter{Value: value, Present: true}
	case "is_superuser":
		p.IsSuperuser = Parameter{Value: value, Present: true}
	default:
		// Read, and dropped here. Nothing above this line can see it.
	}
	return nil
}

// decodeParameterStatus splits a ParameterStatus body into its name and value.
//
// The body is the parameter name, a NUL, the value, and a NUL. Both terminators
// are required: a value that runs to the end of the frame without one means the
// sender described a length it did not honour, and accepting it would mean
// trusting a boundary the peer did not draw.
func decodeParameterStatus(body []byte) (string, string, error) {
	split := bytes.IndexByte(body, 0)
	if split < 0 {
		return "", "", ErrMalformedMessage
	}
	rest := body[split+1:]

	end := bytes.IndexByte(rest, 0)
	if end < 0 {
		return "", "", ErrMalformedMessage
	}
	// Anything after the value's terminator is surplus the protocol does not
	// define here.
	if end != len(rest)-1 {
		return "", "", ErrMalformedMessage
	}
	return string(body[:split]), string(rest[:end]), nil
}

// ValidateBackendKeyData checks that a BackendKeyData frame is structurally
// plausible, and returns nothing at all.
//
// # Both values are discarded, and neither has a field to live in
//
// The frame carries a process ID and a secret key. The secret exists so a client
// can send CancelRequest on a second connection; svcdoctor issues no statement,
// so there is nothing to cancel, and storing a cancellation secret would create
// a second secret carrier in a repository that has spent four phases confining
// the first one.
//
// The process ID is dropped too. No rule reads it, and behind a pooler it is
// synthetic — pgBouncer answered with 799998125 and 1172961953 on two
// connections to the same server, which is a fabricated number, not a backend.
//
// So this function returns only an error. There is no struct, no field and no
// accessor through which either value could reach a caller. See ADR 0039
// section 6.
func ValidateBackendKeyData(body []byte) error {
	if len(body) < backendKeyDataMinimum {
		return ErrMalformedMessage
	}
	return nil
}

// DecodeReadyForQuery returns the transaction status byte that ends session
// establishment.
//
// The body is exactly one byte, and it is one of three. A frame of any other
// length, or a byte outside the set, is malformed: this is the message whose
// arrival *defines* success, and accepting a shape the protocol does not define
// would mean passing a session on a frame svcdoctor did not understand.
//
// A status other than 'I' is **not** a failure. A fresh session cannot be inside
// a transaction — svcdoctor issues no command that could open one — so 'T' and
// 'E' are unreachable here by construction rather than by luck. If one ever
// arrives it is a fact about the session, recorded as such, and the session still
// reached the boundary. See ADR 0039 section 5.
func DecodeReadyForQuery(body []byte) (byte, error) {
	if len(body) != 1 {
		return 0, ErrMalformedMessage
	}
	switch body[0] {
	case TransactionIdle, TransactionActive, TransactionFailed:
		return body[0], nil
	default:
		return 0, ErrMalformedMessage
	}
}

// TransactionStatusName returns the stable name recorded as evidence.
//
// The strings reach a report as the postgres.transaction_status attribute, so
// they are contract. An unrecognized byte cannot occur — DecodeReadyForQuery
// refuses one — and renders as "unknown" rather than as a raw byte the peer
// chose, because a report is not a place to echo unvalidated input.
func TransactionStatusName(status byte) string {
	switch status {
	case TransactionIdle:
		return "idle"
	case TransactionActive:
		return "in-transaction"
	case TransactionFailed:
		return "failed-transaction"
	default:
		return "unknown"
	}
}

// EncodeTerminate builds the Terminate message.
//
// Five bytes: the type byte 'X' and a length of 4, which counts itself and
// leaves no body. It is exported so a test can assert the exact bytes without
// round-tripping them through the encoder that produced them.
func EncodeTerminate() []byte {
	out := make([]byte, 5)
	out[0] = msgTerminate
	binary.BigEndian.PutUint32(out[1:5], 4)
	return out
}

// SendTerminate writes a Terminate message.
//
// It is the only thing svcdoctor sends after the StartupMessage and the
// authentication exchange, and it is a courtesy: it tells the server the client
// is finished so the backend exits cleanly instead of logging an unexpected
// disconnection.
//
// The connection is borrowed and not closed here; deadlines derived from ctx are
// cleared before returning, as everywhere else in this package.
//
// **A failure to write it says nothing about the session that already
// succeeded.** The caller is expected to ignore the error for that reason; it is
// returned rather than swallowed so that a test can observe it.
func SendTerminate(ctx context.Context, conn net.Conn) error {
	if conn == nil {
		return ErrInvalidInput
	}

	release := bindDeadline(ctx, conn)
	defer release()

	return writeAll(conn, EncodeTerminate())
}
