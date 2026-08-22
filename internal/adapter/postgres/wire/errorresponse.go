package wire

import "bytes"

// ErrorResponse field type bytes.
//
// Only the two svcdoctor keeps are named. The rest are read past without being
// stored, and are deliberately not given constants: a name is an invitation, and
// there is nothing here that should want one.
const (
	fieldSQLState         byte = 'C'
	fieldSeverityNonLocal byte = 'V'
)

// ErrorFields is everything svcdoctor retains from an ErrorResponse or a
// NoticeResponse.
//
// **The absence of the other fields is the mechanism, not a promise.** There is
// no field here for the message, the detail, the hint, the context, the schema,
// table, column, data type or constraint name, or the server's source file, line
// and routine. A caller cannot leak what it is never handed, and no future edit
// to a caller can start leaking it without editing this struct first — which is
// a visible change with a reason attached.
//
// The two that survive are the two that are both stable and identity-free:
//
//   - SQLState is the five-character code from field 'C'. It is not localizable,
//     it is always present in a message a real backend generated, and it is what
//     lets diagnosis reason without reading English.
//   - Severity is field 'V', which carries the same word as 'S' but is never
//     translated. 'S' is discarded precisely because it may arrive in any
//     language, which would make it useless for comparison and unstable in a
//     report.
//
// Native reports whether 'V' was present at all. That is a real structural
// signal rather than bookkeeping: every genuine PostgreSQL backend since 9.6
// sends it, and pgBouncer does not — the Phase 4.0 study measured a pooler
// answering with a SQLSTATE and no 'V' at all. It is recorded as a fact and read
// by nothing yet.
//
// See ADR 0036 section 6 and section 10.
type ErrorFields struct {
	SQLState string
	Severity string
	Native   bool
}

// IsZero reports whether nothing was retained.
func (f ErrorFields) IsZero() bool {
	return f.SQLState == "" && f.Severity == "" && !f.Native
}

// DecodeErrorFields extracts the retained fields from an ErrorResponse or
// NoticeResponse body.
//
// The body is a sequence of (type byte, NUL-terminated value) pairs terminated by
// a zero byte where the next type byte would be. A body that runs out before its
// terminator is malformed: the peer said there was more and there was not, and
// accepting a truncated field list would mean trusting a length the sender did
// not honour.
//
// # Duplicates
//
// The first occurrence of a field wins. PostgreSQL emits each field at most once,
// so a duplicate means the peer is not behaving as the protocol describes; taking
// the first is the choice that cannot be steered by appending. A last-wins
// decoder would let anything able to inject a trailing field overwrite a SQLSTATE
// that a rule is about to read.
//
// # Encoding
//
// Values are copied as-is and never validated as UTF-8. PostgreSQL encodes them
// in the server's encoding, which svcdoctor has not negotiated at this point, so
// a validity check here would be a guess. It costs nothing to skip: SQLSTATE is
// five ASCII characters and Severity is one of a fixed set of ASCII words, and
// anything that is not gets rejected by the shape checks below rather than
// stored.
func DecodeErrorFields(body []byte) (ErrorFields, error) {
	var out ErrorFields

	for i := 0; i < len(body); {
		code := body[i]
		if code == 0 {
			// The terminator. Anything after it is not part of this message's
			// field list and is ignored rather than parsed.
			return out, nil
		}
		i++

		end := bytes.IndexByte(body[i:], 0)
		if end < 0 {
			// A field whose value has no terminator: the message is truncated
			// or was never well formed.
			return ErrorFields{}, ErrMalformedMessage
		}
		value := string(body[i : i+end])
		i += end + 1

		switch code {
		case fieldSQLState:
			if out.SQLState == "" && validSQLState(value) {
				out.SQLState = value
			}
		case fieldSeverityNonLocal:
			if !out.Native {
				// Presence is recorded even when the word is not one svcdoctor
				// recognizes: 'V' arriving at all is the signal, and refusing to
				// record an unfamiliar severity would hide a future one.
				out.Native = true
				if validSeverity(value) {
					out.Severity = value
				}
			}
		default:
			// Read past, and store nothing. This is the branch that keeps the
			// message, detail, hint and source location out of svcdoctor.
		}
	}

	// The field list ended without its terminating zero byte.
	return ErrorFields{}, ErrMalformedMessage
}

// validSQLState reports whether v has the shape the protocol fixes: exactly five
// characters drawn from the alphanumeric set PostgreSQL uses for condition codes.
//
// Checking the shape rather than a table is deliberate. A table would have to be
// maintained against every future PostgreSQL release, and an unrecognized-but-well-
// formed code is a fact worth recording; a value that is not five characters is
// not a SQLSTATE at all and must not reach a report as one.
func validSQLState(v string) bool {
	if len(v) != 5 {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'A' && c <= 'Z':
		case c >= 'a' && c <= 'z':
		default:
			return false
		}
	}
	return true
}

// severities is the closed vocabulary field 'V' may carry.
//
// It is a fixed set rather than an accepted string because this value reaches a
// report: an unbounded field from an unauthenticated peer is exactly the shape
// this package exists to refuse. An unrecognized word is dropped while Native
// still records that 'V' was there.
var severities = map[string]struct{}{
	"ERROR": {}, "FATAL": {}, "PANIC": {},
	"WARNING": {}, "NOTICE": {}, "DEBUG": {}, "INFO": {}, "LOG": {},
}

func validSeverity(v string) bool {
	_, ok := severities[v]
	return ok
}
