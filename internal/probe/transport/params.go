package transport

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/probe/dns"
	"github.com/hakanaltindag/svcdoctor/internal/probe/tcp"
	"github.com/hakanaltindag/svcdoctor/internal/probe/tls"
)

// ErrInvalidInput reports that the chain was called with something it cannot
// use, such as a missing resolver or a zero port.
//
// It is the only error class this package defines. A refused connection or a
// rejected certificate is a diagnostic fact and comes back as evidence in the
// graph; unusable input is a defect in the caller and comes back as an error.
var ErrInvalidInput = errors.New("invalid transport chain input")

// TLSOptions asks the chain to attempt TLS, and says how.
//
// Its presence is the request: a nil *TLSOptions means the chain stops after
// TCP. That is the whole mechanism for expressing "this endpoint speaks TLS",
// and it is deliberately not inferred from the port. A port number is a
// convention, not evidence, and ADR 0011 already refuses to infer a service from
// one; inferring a protocol would be the same mistake one layer down.
//
// The zero value verifies against the system trust store.
type TLSOptions struct {
	// ServerName is the identity to verify. When empty the chain uses the host
	// it was asked to reach, which is the name a client would send. It is never
	// derived from a resolved address.
	ServerName string

	// RootCAs is the trust source. Nil means the system trust store. This
	// package loads nothing from disk.
	RootCAs *x509.CertPool

	// MinVersion and MaxVersion bound the protocol versions offered. Zero means
	// the standard library's default.
	MinVersion uint16
	MaxVersion uint16

	// InsecureSkipVerify disables identity verification for every handshake in
	// this run. It is explicit, it is never an automatic fallback after a
	// verification failure, and each affected node records tls.verified = false.
	InsecureSkipVerify bool
}

// Params describes one endpoint to inspect.
type Params struct {
	// Host is the name or address literal to resolve. Required.
	Host string

	// Port is the port every connection attempt uses. Required.
	Port uint16

	// Resolver and Dialer are the probes' seams, supplied by the caller so that
	// a test can run the whole chain without a network. Required.
	Resolver dns.Resolver
	Dialer   tcp.Dialer

	// TLS asks for a handshake on each established connection. Nil stops the
	// chain after TCP.
	TLS *TLSOptions

	// StepTimeout optionally bounds each probe call, derived from the caller's
	// context. Zero means only the caller's context bounds the work.
	//
	// It exists because one black-holed address would otherwise consume the
	// whole budget and leave every later address unmeasured — the sweep would
	// then report less the slower the target is. The caller's deadline still
	// wins whenever it is the earlier of the two.
	StepTimeout time.Duration
}

// validate rejects input the chain cannot turn into a meaningful sweep.
func (p Params) validate() error {
	switch {
	case p.Host == "":
		return fmt.Errorf("%w: host must not be empty", ErrInvalidInput)
	case p.Port == 0:
		return fmt.Errorf("%w: port must not be zero", ErrInvalidInput)
	case p.Resolver == nil:
		return fmt.Errorf("%w: resolver must not be nil", ErrInvalidInput)
	case p.Dialer == nil:
		return fmt.Errorf("%w: dialer must not be nil", ErrInvalidInput)
	case p.StepTimeout < 0:
		return fmt.Errorf("%w: step timeout %s must not be negative", ErrInvalidInput, p.StepTimeout)
	}
	return nil
}

// endpoint is the logical label every node of this run is scoped by.
//
// It is derived rather than supplied because the caller already gave both parts,
// and two ways to name one endpoint would eventually disagree. net.JoinHostPort
// brackets an IPv6 literal, so the label matches what the probes' subjects use.
func (p Params) endpoint() string {
	return net.JoinHostPort(p.Host, strconv.FormatUint(uint64(p.Port), 10))
}

// tlsParams builds the per-attempt TLS parameters for one address.
func (p Params) tlsParams(addr netip.AddrPort) tls.Params {
	serverName := p.TLS.ServerName
	if serverName == "" {
		serverName = p.Host
	}
	return tls.Params{
		Endpoint:           p.endpoint(),
		Address:            addr,
		ServerName:         serverName,
		RootCAs:            p.TLS.RootCAs,
		MinVersion:         p.TLS.MinVersion,
		MaxVersion:         p.TLS.MaxVersion,
		InsecureSkipVerify: p.TLS.InsecureSkipVerify,
	}
}
