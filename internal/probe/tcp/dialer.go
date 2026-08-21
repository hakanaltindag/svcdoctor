package tcp

import (
	"context"
	"net"
	"net/netip"
)

// Dialer is the seam between this probe and the network.
//
// It exists for one reason, the same one that justified the DNS resolver seam:
// no test may depend on an uncontrolled network service. Hermetic testing is a
// real second implementation, which is the bar this project sets before an
// interface is justified.
//
// It takes a netip.AddrPort rather than the network and address strings
// net.Dialer uses, and that is a deliberate narrowing:
//
//   - A string address can be a hostname, and a hostname would be resolved
//     inside the dial. That would repeat L1 inside L2, hide a second DNS lookup
//     from the evidence, and charge its latency to the connection attempt. The
//     type makes it impossible to pass a name.
//   - A network string invites "tcp4" and "tcp6", which is address-family
//     selection policy. The address already determines the family.
//
// A dialer must honour the context: cancellation and deadlines are how svcdoctor
// bounds its own work, and a dialer that ignores them would make a local budget
// unenforceable.
type Dialer interface {
	// DialTCP establishes a TCP connection to addr.
	//
	// It returns either a usable connection or an error, never both and never
	// neither. The probe treats a nil connection with a nil error as a defect in
	// the dialer and claims nothing about the target.
	DialTCP(ctx context.Context, addr netip.AddrPort) (net.Conn, error)
}

// SystemDialer dials through the operating system's network stack, which is what
// a client on this vantage would use.
//
// The zero value is ready to use and holds no state, so there is nothing to
// construct and no configuration to get wrong.
//
// It sets no dial timeout of its own. The caller's context is the only budget,
// which keeps one deadline in play rather than two that could disagree about
// whose expiry a timeout was.
type SystemDialer struct{}

// DialTCP connects to addr over TCP.
//
// The address is already a literal, so this performs no name resolution: the
// "tcp" network with a literal address never consults a resolver.
func (SystemDialer) DialTCP(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", addr.String())
}
