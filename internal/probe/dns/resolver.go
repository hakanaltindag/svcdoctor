package dns

import (
	"context"
	"net"
	"net/netip"
)

// Resolver is the seam between this probe and name resolution.
//
// It exists for one reason: no test may depend on an uncontrolled public
// service, and a test that resolves a real name would depend on the network, on
// the machine's resolver configuration, and on whoever owns the zone. Hermetic
// testing is a genuine second implementation, which is the bar this project sets
// before an interface is justified.
//
// It is one method taking one name, and it stays that way until real usage
// forces more:
//
//   - No address family argument. The probe collects every family the resolver
//     returns and lets a later layer decide what to connect to.
//   - No lookup options and no custom DNS server. svcdoctor diagnoses what this
//     client sees from this vantage, so it must ask the resolver the client
//     would actually use. Querying a server the application would never consult
//     would produce evidence about a different question.
//   - No factory, no registry, no plugin lookup. Callers pass an implementation.
//
// The method returns netip.Addr rather than net.IP because netip.Addr is
// comparable, so deduplication and deterministic ordering are ordinary value
// operations, and it has no hidden 4-versus-16-byte representation to normalize.
type Resolver interface {
	// LookupAddresses returns every address the resolver has for host.
	//
	// The returned order carries no meaning: the probe sorts. An empty result
	// with a nil error is legitimate and means the resolver answered that the
	// name has no usable address.
	LookupAddresses(ctx context.Context, host string) ([]netip.Addr, error)
}

// SystemResolver resolves through the resolver the operating system is
// configured to use, which is the one a client on this vantage would use.
//
// The zero value is ready to use and holds no state, so there is nothing to
// construct and no configuration to get wrong.
type SystemResolver struct{}

// LookupAddresses resolves host to every address family the system returns.
//
// The "ip" network asks for both IPv4 and IPv6. Neither family is preferred,
// requested exclusively, or treated as unusual: which of them is reachable is a
// question for L2, on the evidence this lookup produces.
func (SystemResolver) LookupAddresses(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}
