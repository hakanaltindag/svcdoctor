package domain

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// VantageSource identifies what kind of place probes ran from.
//
// It is a discriminator so that in-cluster and remote execution contexts can be
// added later as new members, without changing the shape of Vantage and without
// any consumer branching on a service.
//
// The zero VantageSource is VantageSourceUnspecified.
type VantageSource uint8

const (
	// VantageSourceUnspecified is the zero value and is not a source.
	VantageSourceUnspecified VantageSource = iota

	// VantageSourceLocalHost means probes ran directly on the host executing
	// svcdoctor. It is the only source supported in v0.1.
	VantageSourceLocalHost
)

// vantageSourceNames is indexed by VantageSource. Keep it aligned with the const
// block above; TestVantageSourceNamesCoverAllSources fails if the two drift.
var vantageSourceNames = [...]string{
	VantageSourceUnspecified: "UNSPECIFIED",
	VantageSourceLocalHost:   "LOCAL_HOST",
}

// Valid reports whether s is a defined source. VantageSourceUnspecified is not.
func (s VantageSource) Valid() bool {
	return s != VantageSourceUnspecified && int(s) < len(vantageSourceNames)
}

// String returns the symbolic name, or a Go-convention rendering of an
// out-of-range value. It never fails.
func (s VantageSource) String() string {
	if int(s) >= len(vantageSourceNames) {
		return "VantageSource(" + strconv.FormatUint(uint64(s), 10) + ")"
	}
	return vantageSourceNames[s]
}

// MarshalJSON emits the symbolic name so that the report contract is a stable
// string rather than an enum ordinal.
func (s VantageSource) MarshalJSON() ([]byte, error) {
	if !s.Valid() {
		return nil, fmt.Errorf("%w: VantageSource(%d)", ErrInvalidValue, uint8(s))
	}
	return []byte(strconv.Quote(vantageSourceNames[s])), nil
}

// Vantage records where probes ran from.
//
// It stores normalized facts only. It performs no discovery: it does not call
// os.Hostname, read the environment, inspect network interfaces, or contact a
// cluster. Collecting those facts is the platform layer's job; this type is
// where the result is kept once collected.
//
// # Why this is first class
//
// A connectivity or topology result is valid from the recorded vantage point
// unless the evidence explicitly proves otherwise. "This broker is unreachable"
// is a claim about a network position, not about a cluster, and the same target
// may be perfectly reachable from somewhere else. Vantage is therefore a
// required part of a report rather than run metadata, so that the claim and the
// position it was made from cannot be separated when a report is shared.
//
// Nothing here implies universal reachability, and no consumer may read it that
// way.
//
// The identifier is a plain host label rather than a security.Endpoint. A
// vantage is a location, not a connection target: it has no port and is never
// dialled, and it must not become something a credential could be bound to.
//
// The zero Vantage is invalid. Use NewLocalVantage.
type Vantage struct {
	source VantageSource
	host   string
}

// NewLocalVantage records that probes ran on the local host, identified by host.
//
// There is deliberately no general constructor taking a VantageSource, so an
// unspecified vantage cannot be built. When in-cluster or remote execution
// arrives it gets its own constructor with its own required fields.
func NewLocalVantage(host string) (Vantage, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return Vantage{}, fmt.Errorf("%w: vantage host must not be empty", ErrInvalidValue)
	}
	return Vantage{source: VantageSourceLocalHost, host: host}, nil
}

// Source reports what kind of place probes ran from.
func (v Vantage) Source() VantageSource { return v.source }

// Host returns the identifier of where probes ran.
func (v Vantage) Host() string { return v.host }

// IsZero reports whether v is the invalid zero Vantage.
func (v Vantage) IsZero() bool { return v == Vantage{} }

// String returns a readable rendering naming both the source and the host, so
// that a vantage can never be shown without saying what kind of place it was.
func (v Vantage) String() string {
	if v.IsZero() {
		return "<invalid vantage>"
	}
	return v.source.String() + ":" + v.host
}

// MarshalJSON emits the vantage as an object.
//
// Vantage has no exported fields, so a custom marshaler is required rather than
// merely convenient: the default encoding would be "{}" and the report would
// silently lose the position every connectivity claim depends on.
//
// The host is a plain string here. Pseudonymizing it for a shareable report is
// the redactor's job, and it can do that by constructing a new Vantage.
func (v Vantage) MarshalJSON() ([]byte, error) {
	if v.IsZero() {
		return nil, fmt.Errorf("%w: zero Vantage", ErrInvalidValue)
	}
	return json.Marshal(struct {
		Source VantageSource `json:"source"`
		Host   string        `json:"host"`
	}{Source: v.source, Host: v.host})
}
