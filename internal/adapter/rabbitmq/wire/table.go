package wire

import (
	"encoding/binary"
	"fmt"
)

// --- reading ----------------------------------------------------------------

// cursor walks a buffer this package already holds, refusing to read past it.
//
// Every read is bounds-checked against the remaining bytes, so a declared length
// inside a field table can never produce a slice beyond the frame. The frame
// ceiling in frame.go bounds the buffer; this bounds every step within it.
type cursor struct {
	b   []byte
	off int
}

func (c *cursor) remaining() int { return len(c.b) - c.off }

func (c *cursor) take(n int) ([]byte, error) {
	if n < 0 || n > c.remaining() {
		return nil, fmt.Errorf("%w: field of %d bytes with %d remaining",
			ErrMalformedFrame, n, c.remaining())
	}
	out := c.b[c.off : c.off+n]
	c.off += n
	return out, nil
}

func (c *cursor) u8() (byte, error) {
	b, err := c.take(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (c *cursor) u16() (uint16, error) {
	b, err := c.take(2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b), nil
}

func (c *cursor) u32() (uint32, error) {
	b, err := c.take(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b), nil
}

// shortstr reads a 1-byte-length string. The protocol maximum is 255 by
// construction of the length byte, so no separate bound is needed or invented.
func (c *cursor) shortstr() (string, error) {
	n, err := c.u8()
	if err != nil {
		return "", err
	}
	b, err := c.take(int(n))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// longstr reads a 4-byte-length string, bounded by the bytes actually present.
func (c *cursor) longstr() (string, error) {
	n, err := c.u32()
	if err != nil {
		return "", err
	}
	if int64(n) > int64(c.remaining()) {
		return "", fmt.Errorf("%w: long string declares %d bytes with %d remaining",
			ErrMalformedFrame, n, c.remaining())
	}
	b, err := c.take(int(n))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// fixedFieldSize is the encoded width of every fixed-width AMQP 0-9-1 and QPid
// extension field type. It exists so that an unknown value can be *skipped*
// without being interpreted.
var fixedFieldSize = map[byte]int{
	't': 1,         // bool
	'b': 1, 'B': 1, // int8, uint8
	's': 2, 'u': 2, // int16, uint16
	'I': 4, 'i': 4, // int32, uint32
	'l': 8, 'L': 8, // int64
	'f': 4, 'd': 8, // float, double
	'D': 5, // decimal: scale(1) + value(4)
	'T': 8, // timestamp
	'V': 0, // void
}

// varFieldType reports whether a type is length-prefixed with a 4-byte length.
func varFieldType(t byte) bool {
	switch t {
	case 'S', 'x', 'A', 'F': // longstr, byte array, array, table
		return true
	}
	return false
}

// wanted is the closed set of top-level server-properties keys svcdoctor reads.
//
// Everything else is skipped by declared length. ADR 0070 section 5.1.
var wanted = map[string]struct{}{
	"product":      {},
	"version":      {},
	"platform":     {},
	"cluster_name": {},
}

// walkTopLevelTable extracts the four wanted string fields and skips every other
// value by its declared encoded length.
//
// # It never descends
//
// A nested table or array is skipped whole. RabbitMQ's own parse_table has no
// depth counter at all, so there is no implementation-fixed number to borrow and
// any depth bound svcdoctor invented would be the "N times the observed value"
// reasoning ADR 0061 forbids. Recursion depth here is **1 by construction**: this
// function contains no call to itself, which a test asserts by parsing the
// source. The nesting attack surface is deleted rather than defended.
//
// # There is no entry cap
//
// Phase 8.0A proposed one and ADR 0070 section 5.2 deleted it: the walk is
// already bounded by the frame ceiling, and a minimal entry is two bytes, so the
// iteration count cannot exceed half the payload. A separate number would have
// had no source.
func walkTopLevelTable(c *cursor, size int) (map[string]string, error) {
	if size < 0 || size > c.remaining() {
		return nil, fmt.Errorf("%w: table declares %d bytes with %d remaining",
			ErrMalformedFrame, size, c.remaining())
	}
	end := c.off + size
	out := map[string]string{}

	for c.off < end {
		nameLen, err := c.u8()
		if err != nil {
			return nil, err
		}
		nameBytes, err := c.take(int(nameLen))
		if err != nil {
			return nil, err
		}
		name := string(nameBytes)

		typ, err := c.u8()
		if err != nil {
			return nil, err
		}

		switch {
		case typ == 'S':
			v, err := c.longstr()
			if err != nil {
				return nil, err
			}
			if _, ok := wanted[name]; ok {
				out[name] = v
			}
		case varFieldType(typ):
			// Skipped whole, by declared length, without being entered.
			n, err := c.u32()
			if err != nil {
				return nil, err
			}
			if int64(n) > int64(c.remaining()) {
				return nil, fmt.Errorf("%w: %c field declares %d bytes with %d remaining",
					ErrMalformedFrame, typ, n, c.remaining())
			}
			if _, err := c.take(int(n)); err != nil {
				return nil, err
			}
		default:
			width, ok := fixedFieldSize[typ]
			if !ok {
				return nil, fmt.Errorf("%w: unknown field type %q", ErrMalformedFrame, typ)
			}
			if _, err := c.take(width); err != nil {
				return nil, err
			}
		}
	}
	if c.off != end {
		return nil, fmt.Errorf("%w: table fields overran their declared length", ErrMalformedFrame)
	}
	return out, nil
}

// --- writing ----------------------------------------------------------------

// appendShortstr refuses above 255 rather than truncating.
//
// Truncating an operator's vhost would send a *different* vhost than the one the
// report names, which is a correctness defect wearing a robustness costume.
func appendShortstr(dst []byte, s string) ([]byte, error) {
	if len(s) > 255 {
		return nil, fmt.Errorf("%w: short string of %d bytes exceeds 255", ErrInvalidInput, len(s))
	}
	//nolint:gosec // G115: the length is checked against 255 immediately above,
	// which is the whole point of this function.
	dst = append(dst, byte(len(s)))
	return append(dst, s...), nil
}

func appendLongstr(dst []byte, b []byte) []byte {
	//nolint:gosec // G115: every caller passes a buffer this package built, and
	// the largest is the fixed client-properties table below.
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(b)))
	return append(dst, b...)
}

// clientProperties is the fixed client-properties table svcdoctor sends.
//
// # It is a literal, and that is the point
//
// Nothing here is derived from the target, the environment or operator input, so
// the only variable bytes in a Connection.Start-Ok frame are the credential
// itself. That is what makes the byte-exact encoder test in ADR 0068 section 8
// possible, and it keeps the frame far below LavinMQ's measured 4096-byte
// ceiling — Phase 8.0C measured svcdoctor's Start-Ok at 165 to 202 bytes.
//
// # Exactly one capability
//
// `authentication_failure_close` is a precondition rather than a courtesy: Phase
// 8.0C measured that without it RabbitMQ sends **no frame at all** on a failed
// login and simply closes, which would make a rejected credential and a peer
// close the same observation (ADR 0068 section 3).
//
// `connection.blocked` is deliberately absent. It changes broker behaviour on a
// running connection and BASIC has no running connection.
func clientProperties() []byte {
	var fields []byte
	appendEntry := func(key, value string) {
		//nolint:gosec // G115: every key is a literal in this function, the
		// longest being twelve bytes.
		fields = append(fields, byte(len(key)))
		fields = append(fields, key...)
		fields = append(fields, 'S')
		fields = appendLongstr(fields, []byte(value))
	}
	appendEntry("product", "svcdoctor")
	appendEntry("platform", "Go")
	appendEntry("version", "0")

	// capabilities: { authentication_failure_close: true }
	var caps []byte
	caps = append(caps, byte(len("authentication_failure_close")))
	caps = append(caps, "authentication_failure_close"...)
	caps = append(caps, 't', 0x01)

	fields = append(fields, byte(len("capabilities")))
	fields = append(fields, "capabilities"...)
	fields = append(fields, 'F')
	//nolint:gosec // G115: caps is built from literals in this function.
	fields = binary.BigEndian.AppendUint32(fields, uint32(len(caps)))
	fields = append(fields, caps...)

	//nolint:gosec // G115: fields is built entirely from literals in this
	// function, and a byte-exact test pins its length.
	out := binary.BigEndian.AppendUint32(nil, uint32(len(fields)))
	return append(out, fields...)
}
