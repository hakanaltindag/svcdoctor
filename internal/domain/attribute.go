package domain

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// AttrKind identifies which category of value an AttrValue holds.
//
// The set is closed on purpose. ADR 0010 forbids map[string]any and raw
// protocol or runtime objects in canonical evidence, and a closed set is what
// makes that structural rather than a convention: there is no constructor that
// accepts an arbitrary type, so no such value can be built.
//
// The zero AttrKind is AttrKindInvalid.
type AttrKind uint8

const (
	// AttrKindInvalid is the zero value and holds nothing.
	AttrKindInvalid AttrKind = iota
	// AttrKindString holds a string.
	AttrKindString
	// AttrKindInt holds a signed 64-bit integer.
	AttrKindInt
	// AttrKindBool holds a boolean.
	AttrKindBool
	// AttrKindDuration holds an elapsed time.
	AttrKindDuration
	// AttrKindTime holds an instant.
	AttrKindTime
	// AttrKindStringList holds an ordered list of strings.
	AttrKindStringList
	// AttrKindHost holds one value that identifies a network peer: a DNS name,
	// an IP literal, or a host:port reference.
	AttrKindHost
	// AttrKindHostList holds an ordered list of such values.
	AttrKindHostList
)

// attrKindNames is indexed by AttrKind. Keep it aligned with the const block
// above; TestAttrKindNamesCoverAllKinds fails if the two drift apart.
var attrKindNames = [...]string{
	AttrKindInvalid:    "invalid",
	AttrKindString:     "string",
	AttrKindInt:        "int",
	AttrKindBool:       "bool",
	AttrKindDuration:   "duration",
	AttrKindTime:       "time",
	AttrKindStringList: "stringList",
	AttrKindHost:       "host",
	AttrKindHostList:   "hostList",
}

// Valid reports whether k is a defined kind. AttrKindInvalid is not.
func (k AttrKind) Valid() bool {
	return k != AttrKindInvalid && int(k) < len(attrKindNames)
}

// String returns the kind name, or a Go-convention rendering of an out-of-range
// value. It never fails.
func (k AttrKind) String() string {
	if int(k) >= len(attrKindNames) {
		return "AttrKind(" + strconv.FormatUint(uint64(k), 10) + ")"
	}
	return attrKindNames[k]
}

// AttrValue is one normalized attribute value.
//
// It is a tagged union with unexported fields and one constructor per kind, so
// the only values that can exist are the ones the model defines. There is no
// path for a caller to place a protocol response, a TLS connection state, or an
// arbitrary interface value into evidence.
//
// Complex service-specific data is expressed as normalized scalars, a string
// list, or additional evidence nodes, never as a nested dynamic object. That is
// what keeps the report schema stable, serialization deterministic, and
// structural redaction possible.
//
// The zero AttrValue is invalid.
type AttrValue struct {
	kind AttrKind
	str  string
	num  int64
	flag bool
	ts   time.Time
	list []string
}

// StringAttr holds a string.
func StringAttr(v string) AttrValue {
	return AttrValue{kind: AttrKindString, str: v}
}

// IntAttr holds a signed 64-bit integer.
func IntAttr(v int64) AttrValue {
	return AttrValue{kind: AttrKindInt, num: v}
}

// BoolAttr holds a boolean.
func BoolAttr(v bool) AttrValue {
	return AttrValue{kind: AttrKindBool, flag: v}
}

// DurationAttr holds an elapsed time.
func DurationAttr(v time.Duration) AttrValue {
	return AttrValue{kind: AttrKindDuration, num: int64(v)}
}

// TimeAttr holds an instant.
//
// The instant is normalized to UTC, which also strips the monotonic reading.
// Both matter for the canonical report: a monotonic reading is meaningless once
// serialized and breaks value comparison, and a fixed location makes the
// encoding of a given instant identical no matter which machine produced it.
// The vantage records where the run happened, so the local offset carries no
// diagnostic information that would be lost here.
func TimeAttr(v time.Time) AttrValue {
	return AttrValue{kind: AttrKindTime, ts: v.UTC()}
}

// StringListAttr holds an ordered list of strings.
//
// The list is copied, so a caller cannot mutate a value after it has been
// recorded as evidence.
func StringListAttr(v ...string) AttrValue {
	list := make([]string, len(v))
	copy(list, v)
	return AttrValue{kind: AttrKindStringList, list: list}
}

// HostAttr holds one value that identifies a network peer: a DNS name, an IP
// literal, or a host:port reference.
//
// # Why this is not just a string
//
// A producer knows whether a value identifies somebody. Structural redaction
// does not, and cannot always work it out: "broker.internal" and "TLS1.3" are
// both dotted strings, and a redactor that guessed would either leak the first
// or destroy the second. Recording the producer's knowledge in the value's type
// makes the question decidable rather than heuristic, which is the same reason
// the whole union is closed.
//
// Use it for any value that names a host, an address or an endpoint. The
// redactor replaces every such value with a stable pseudonym, so correlation
// survives and identity does not.
//
// An ordinary StringAttr is still checked opportunistically, but only a value
// recorded through this constructor is guaranteed to be recognized. See
// ADR 0022.
func HostAttr(v string) AttrValue {
	return AttrValue{kind: AttrKindHost, str: v}
}

// HostListAttr holds an ordered list of peer identities, one per entry.
//
// One identity per entry is required rather than merely tidy: redaction
// replaces whole values, so two names joined into one string would survive
// together. The list is copied.
func HostListAttr(v ...string) AttrValue {
	list := make([]string, len(v))
	copy(list, v)
	return AttrValue{kind: AttrKindHostList, list: list}
}

// Kind reports which category of value v holds.
func (v AttrValue) Kind() AttrKind { return v.kind }

// Valid reports whether v holds a defined kind of value.
func (v AttrValue) Valid() bool { return v.kind.Valid() }

// Str returns the string value and whether v holds one.
func (v AttrValue) Str() (string, bool) {
	return v.str, v.kind == AttrKindString
}

// Int returns the integer value and whether v holds one.
func (v AttrValue) Int() (int64, bool) {
	return v.num, v.kind == AttrKindInt
}

// Bool returns the boolean value and whether v holds one.
func (v AttrValue) Bool() (bool, bool) {
	return v.flag, v.kind == AttrKindBool
}

// Duration returns the duration value and whether v holds one.
func (v AttrValue) Duration() (time.Duration, bool) {
	return time.Duration(v.num), v.kind == AttrKindDuration
}

// Time returns the instant and whether v holds one.
func (v AttrValue) Time() (time.Time, bool) {
	return v.ts, v.kind == AttrKindTime
}

// Host returns the peer identity and whether v holds one.
func (v AttrValue) Host() (string, bool) {
	return v.str, v.kind == AttrKindHost
}

// HostList returns a copy of the peer identities and whether v holds them.
func (v AttrValue) HostList() ([]string, bool) {
	if v.kind != AttrKindHostList {
		return nil, false
	}
	out := make([]string, len(v.list))
	copy(out, v.list)
	return out, true
}

// StringList returns a copy of the list and whether v holds one.
//
// The copy prevents a reader from mutating recorded evidence through the
// returned slice.
func (v AttrValue) StringList() ([]string, bool) {
	if v.kind != AttrKindStringList {
		return nil, false
	}
	out := make([]string, len(v.list))
	copy(out, v.list)
	return out, true
}

// String returns a human-readable rendering of the value. It never fails.
//
// This is for logs and debugging. The canonical form is MarshalJSON.
func (v AttrValue) String() string {
	switch v.kind {
	case AttrKindString, AttrKindHost:
		return v.str
	case AttrKindInt:
		return strconv.FormatInt(v.num, 10)
	case AttrKindBool:
		return strconv.FormatBool(v.flag)
	case AttrKindDuration:
		return time.Duration(v.num).String()
	case AttrKindTime:
		return v.ts.Format(time.RFC3339Nano)
	case AttrKindStringList, AttrKindHostList:
		return "[" + strings.Join(v.list, ", ") + "]"
	default:
		return "AttrValue(" + v.kind.String() + ")"
	}
}

// attrJSON is the wire shape of an AttrValue.
//
// The kind travels with the value on purpose. Without it a timestamp and a
// string are indistinguishable once encoded, and a renderer would have to guess
// how to present a value. Renderers explain results; they do not infer types.
// Carrying the tag also keeps the schema explicitly typed for structural
// redaction. The cost is verbosity, which is acceptable in a canonical machine
// representation whose human views are derived.
type attrJSON struct {
	Kind  string `json:"kind"`
	Value any    `json:"value"`
}

// MarshalJSON emits a tagged value.
//
// Durations are encoded in Go duration syntax such as "1.5s" rather than as a
// bare nanosecond count, because a bare number in a report is ambiguous to a
// human reading it and still has to be parsed by a machine either way.
// Instants are encoded as RFC 3339 in UTC.
func (v AttrValue) MarshalJSON() ([]byte, error) {
	out := attrJSON{Kind: v.kind.String()}

	switch v.kind {
	case AttrKindString, AttrKindHost:
		out.Value = v.str
	case AttrKindInt:
		out.Value = v.num
	case AttrKindBool:
		out.Value = v.flag
	case AttrKindDuration:
		out.Value = time.Duration(v.num).String()
	case AttrKindTime:
		out.Value = v.ts.Format(time.RFC3339Nano)
	case AttrKindStringList, AttrKindHostList:
		list := v.list
		if list == nil {
			list = []string{}
		}
		out.Value = list
	default:
		return nil, fmt.Errorf("%w: AttrValue with kind %s", ErrInvalidValue, v.kind)
	}

	return json.Marshal(out)
}
