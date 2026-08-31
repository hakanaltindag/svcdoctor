// Package services holds what every fleet service runner needs from the process.
//
// It is one type and no behaviour. The four service packages below it bridge a
// validated configuration to an existing composition root, and each needs the
// same three process-level values — so they are supplied once, by the single
// composition point that already builds them for the leaf commands.
//
// # Why this is not in internal/fleet/run
//
// The scheduler must not import internal/probe: it opens no socket and resolves
// no name, and a guard proves it by reading its import list. These seams are
// probe types, so they live beside the packages that legitimately hold them.
// The scheduler passes a config.Target and a credential and knows nothing else.
package services

import (
	"fmt"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/fleet/config"
	"github.com/hakanaltindag/svcdoctor/internal/probe/dns"
	"github.com/hakanaltindag/svcdoctor/internal/probe/tcp"
	"github.com/hakanaltindag/svcdoctor/internal/probe/transport"
	"github.com/hakanaltindag/svcdoctor/internal/security/trustsource"
)

// Environment is the process context one run's service runners share.
//
// Every field is injected rather than read here, for the same reason
// app.*Params take them: a caller may run the whole composition without a
// network, and collecting a vantage belongs to the platform boundary.
type Environment struct {
	// Resolver and Dialer are the probes' seams. Required for execution.
	Resolver dns.Resolver
	Dialer   tcp.Dialer

	// Vantage records where the probes ran from. Collected once per run, so
	// every target's report names the same vantage — which is what makes them
	// comparable within one aggregate.
	Vantage domain.Vantage

	// Version is svcdoctor's own version, recorded in each target's run metadata.
	Version string
}

// TLSOptions builds the out-of-band transport TLS plan a target asked for.
//
// Shared by Kafka, Redis and RabbitMQ, which all negotiate no encryption in
// band: a TLS listener is a separate port, so this is an ordinary handshake and
// the generic transport chain performs it. PostgreSQL is deliberately absent —
// it negotiates in band through SSLRequest, so its plan is a different type and
// its adapter performs the handshake on the same socket.
//
// That split is ADR 0071 section 7.3's, made concrete: the TLS *block* is
// generic, and what `require` means on the wire is service-owned.
//
// A disabled plan is nil, which every composition root reads as "this run speaks
// plaintext". Nothing infers TLS from a port number.
func TLSOptions(t config.TLS) (*transport.TLSOptions, error) {
	if !t.Enabled() {
		return nil, nil
	}
	roots, err := trustsource.Load(t.CAFile)
	if err != nil {
		return nil, fmt.Errorf("loading the trust source: %w", err)
	}
	return &transport.TLSOptions{
		ServerName:         t.ServerName,
		RootCAs:            roots,
		InsecureSkipVerify: t.Insecure,
	}, nil
}
