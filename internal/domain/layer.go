package domain

import (
	"fmt"
	"strconv"
)

// Layer identifies which diagnostic layer a step belongs to.
//
// The order is locked by ADR 0007 and docs/ARCHITECTURE.md section 2:
//
//	L0 input/config -> L1 DNS -> L2 TCP -> L3 TLS -> L4 protocol
//	  -> L5 authentication/authorization -> L6 topology
//
// Protocol capability discovery precedes authentication because that is the
// real wire order of the services in scope.
//
// Layers are ordered by their underlying value, so the defined layers satisfy
// LayerInput < LayerDNS < ... < LayerTopology and can be compared with <.
// Short-circuiting and first-broken-layer reporting depend on that order.
//
// The zero Layer is LayerUnspecified, which is invalid. L0 is a real layer, so
// defaulting an unset value to it would let a forgotten layer masquerade as
// config-layer evidence.
//
// v0.1 stops at L6. Later layers are added by extending this enumeration, not
// by branching on a service anywhere.
type Layer uint8

const (
	// LayerUnspecified is the zero value and is not a layer.
	LayerUnspecified Layer = iota

	// LayerInput is L0: input and configuration normalization.
	LayerInput

	// LayerDNS is L1: name resolution.
	LayerDNS

	// LayerTCP is L2: transport connection establishment.
	LayerTCP

	// LayerTLS is L3: TLS handshake and certificate validation.
	LayerTLS

	// LayerProtocol is L4: protocol and capability discovery.
	LayerProtocol

	// LayerAuth is L5: authentication and authorization.
	LayerAuth

	// LayerTopology is L6: topology discovery and reachability.
	LayerTopology
)

// layerInfo holds the two textual forms of a layer. code is the canonical form
// used in the report; label is the human-readable name.
type layerInfo struct {
	code  string
	label string
}

// layers is indexed by Layer. Keep it aligned with the const block above;
// TestLayerTableCoversAllLayers fails if the two drift apart.
var layers = [...]layerInfo{
	LayerUnspecified: {"UNSPECIFIED", "unspecified"},
	LayerInput:       {"L0", "input"},
	LayerDNS:         {"L1", "dns"},
	LayerTCP:         {"L2", "tcp"},
	LayerTLS:         {"L3", "tls"},
	LayerProtocol:    {"L4", "protocol"},
	LayerAuth:        {"L5", "auth"},
	LayerTopology:    {"L6", "topology"},
}

// Valid reports whether l is one of the defined layers. LayerUnspecified is not.
func (l Layer) Valid() bool {
	return l != LayerUnspecified && int(l) < len(layers)
}

// String returns the canonical layer code, "L0" through "L6". It never fails.
func (l Layer) String() string {
	if int(l) >= len(layers) {
		return "Layer(" + strconv.FormatUint(uint64(l), 10) + ")"
	}
	return layers[l].code
}

// Label returns the human-readable layer name, for example "dns".
//
// It lives here rather than in a renderer so that the mapping from layer to
// name is defined once, in the layer that owns the concept. Renderers explain
// results; they do not re-derive domain vocabulary.
func (l Layer) Label() string {
	if int(l) >= len(layers) {
		return l.String()
	}
	return layers[l].label
}

// MarshalJSON emits the layer code so that the report contract is a stable
// string rather than an enum ordinal.
func (l Layer) MarshalJSON() ([]byte, error) {
	if !l.Valid() {
		return nil, fmt.Errorf("%w: Layer(%d)", ErrInvalidValue, uint8(l))
	}
	return []byte(strconv.Quote(layers[l].code)), nil
}
