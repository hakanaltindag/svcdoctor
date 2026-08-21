package tls

import (
	cryptotls "crypto/tls"
	"crypto/x509"
	"fmt"
	"net/netip"
	"strings"
	"unicode"

	"github.com/hakanaltindag/svcdoctor/internal/probe"
)

// Trust source values recorded on the evidence. The set is deliberately tiny:
// it says where the roots came from, never which roots or where they live. A
// filesystem path would be identity a shareable report has no way to redact.
const (
	trustSourceSystem = "system"
	trustSourceCustom = "custom"
)

// Params carries everything the handshake needs beyond the connection itself.
//
// It is a parameter object rather than a long argument list because several
// fields are strings and small integers that would be trivially easy to
// transpose, and a transposition would produce a silently wrong handshake.
//
// The zero value plus an Endpoint, Address and ServerName is the secure default:
// verification on, system trust store, standard library version bounds.
type Params struct {
	// Endpoint is the logical identity this attempt belongs to, such as
	// "primary.internal:9092". It scopes the evidence identifier and nothing
	// else, exactly as in the TCP probe. Required.
	Endpoint string

	// Scope distinguishes this handshake from another one that measured the same
	// endpoint and address in the same run. Optional; the zero value reproduces
	// the identifier this probe has minted since Phase 2.
	//
	// It names an execution, not a subject and not a provenance. Nothing here
	// reads it: it becomes one component of the evidence identifier and nothing
	// more. See ADR 0032.
	Scope probe.SweepScope

	// Address is the concrete peer the connection was established to. It becomes
	// the evidence subject. Required.
	//
	// It is supplied rather than read back from the connection because a
	// connection's remote address is not always an address a report should
	// correlate on — a pipe, a proxy or a tunnel all lie about it — and because
	// the L2 and L3 nodes must carry the same subject to be correlatable.
	Address netip.AddrPort

	// ServerName is the identity to verify the peer's certificate against, and
	// the name sent in SNI. Required, and never inferred from Address: a caller
	// that wants an IP verified passes the IP deliberately.
	ServerName string

	// RootCAs is the trust source. Nil means the system trust store, which is
	// what a client on this vantage would use, and is recorded as such.
	//
	// A caller supplying a pool is recorded as a custom trust source. This
	// package loads nothing from disk: assembling a pool is the caller's job,
	// which keeps certificate and secret handling out of a transport probe.
	RootCAs *x509.CertPool

	// MinVersion and MaxVersion bound the protocol versions offered. Zero means
	// the standard library's default. They are here because the architecture
	// names version bounds as a generic TLS parameter, and because a diagnostic
	// tool sometimes needs to ask "would TLS 1.2 have worked?" without guessing.
	MinVersion uint16
	MaxVersion uint16

	// InsecureSkipVerify disables identity verification for this attempt.
	//
	// It is a deliberate, per-attempt choice that a caller has to make in the
	// open. It is never an automatic fallback after a verification failure: a
	// failed verified handshake is itself valuable evidence, and silently
	// retrying without verification would turn a safety failure into a
	// successful-looking result.
	//
	// When set, a successful handshake proves that the peer speaks TLS and that
	// the channel is encrypted. It proves nothing about who the peer is, and the
	// evidence records tls.verified as false so that no reader or rule can
	// mistake the two.
	InsecureSkipVerify bool
}

// validate rejects input the probe cannot turn into a meaningful attempt.
//
// It checks only what would make the attempt incoherent. Endpoint and ServerName
// are otherwise opaque: the identifier encoding absorbs any character (ADR 0019),
// and this package has no business imposing a hostname grammar on a caller.
func (p Params) validate() error {
	if err := validateLabel("endpoint", p.Endpoint); err != nil {
		return err
	}
	if err := validateLabel("server name", p.ServerName); err != nil {
		return err
	}
	if !p.Address.Addr().IsValid() {
		return fmt.Errorf("%w: address must be specified", ErrInvalidInput)
	}
	if p.Address.Port() == 0 {
		return fmt.Errorf("%w: port must not be zero", ErrInvalidInput)
	}
	if p.MinVersion != 0 && p.MaxVersion != 0 && p.MinVersion > p.MaxVersion {
		return fmt.Errorf("%w: min version %#04x exceeds max version %#04x",
			ErrInvalidInput, p.MinVersion, p.MaxVersion)
	}
	return nil
}

func validateLabel(name, value string) error {
	switch {
	case value == "":
		return fmt.Errorf("%w: %s must not be empty", ErrInvalidInput, name)
	case strings.TrimSpace(value) != value:
		return fmt.Errorf("%w: %s must not have leading or trailing whitespace", ErrInvalidInput, name)
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return fmt.Errorf("%w: %s must not contain control characters", ErrInvalidInput, name)
		}
	}
	return nil
}

// address returns the canonical peer address.
//
// Unmapping matters for identity rather than for the handshake: ::ffff:10.0.0.1
// and 10.0.0.1 are one address, and the TCP probe already unmaps, so the two
// layers produce the same subject for the same peer.
func (p Params) address() netip.AddrPort {
	return netip.AddrPortFrom(p.Address.Addr().Unmap(), p.Address.Port())
}

// trustSource reports where the roots came from, or "" when verification was
// disabled and no trust source was consulted at all.
func (p Params) trustSource() string {
	switch {
	case p.InsecureSkipVerify:
		return ""
	case p.RootCAs != nil:
		return trustSourceCustom
	default:
		return trustSourceSystem
	}
}

// config builds the standard library configuration for one attempt.
//
// Nothing is set that a caller did not ask for. In particular there is no cipher
// suite list, no curve preference and no session cache: svcdoctor reports what a
// client would experience, and a client using stdlib defaults is the closest
// thing to that. Pinning them here would make the evidence describe svcdoctor
// rather than the target.
func (p Params) config() *cryptotls.Config {
	return &cryptotls.Config{
		ServerName: p.ServerName,
		RootCAs:    p.RootCAs,
		MinVersion: p.MinVersion,
		MaxVersion: p.MaxVersion,
		// The caller asked for this explicitly and the evidence records that it
		// happened; see the field documentation on Params.
		InsecureSkipVerify: p.InsecureSkipVerify, //nolint:gosec // G402: explicit, per-attempt, and recorded as tls.verified=false.
	}
}
