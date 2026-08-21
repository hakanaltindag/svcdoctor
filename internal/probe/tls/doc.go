// Package tls performs a TLS handshake over a connection somebody else
// established, and reports what it observed.
//
//	Handshake -> observation (producer-local) -> domain.Evidence + a live TLS connection
//
// It follows the probe contract of ADR 0020 and the ownership contract of
// ADR 0021. It is the first probe that both *consumes* a connection and
// *produces* one.
//
// # It never opens a connection
//
// This package does not dial, does not resolve, and cannot. It has no dialer, no
// resolver and no address to connect to — it is handed an established
// net.Conn and hands back the TLS connection wrapping that same socket. The
// architecture requires the protocol layer to speak over the connection whose
// establishment was measured, and a probe that could redial would silently break
// that: every fact measured at L1 and L2 would then describe a socket the
// handshake never used.
//
// The caller obtains the connection from the TCP probe's Result. This package
// does not import that one: sequencing layers is the transport chain's job, and
// a probe that reached into the previous probe's result type would be
// orchestration wearing a probe's clothes.
//
// # Ownership, in one paragraph
//
// Handshake takes ownership of the connection it is given, unconditionally and
// immediately. After the call the connection is never the caller's again: on
// failure this package closes it, and on success the returned Result owns the
// TLS connection wrapping it. There is exactly one owner at every moment —
// caller, then Result, then whoever calls TakeConn — and closing a TLS
// connection closes the socket underneath it, so the wrapper is the whole
// resource.
//
//	conn, _ := tcpResult.TakeConn()          // caller owns conn
//	r, err := tls.Handshake(ctx, conn, params)
//	if err != nil { return err }             // conn is already closed
//	defer r.Close()                          // safe in every path
//
//	if tlsConn, ok := r.TakeConn(); ok {
//	    defer tlsConn.Close()                // the caller owns it now
//	}
//
// # What it measures
//
//	handshake completed                   PASS    -
//	peer's first record was not TLS       FAIL    TLS_PEER_NOT_TLS
//	certificate name did not match        FAIL    TLS_HOSTNAME_MISMATCH
//	certificate outside its window        FAIL    TLS_CERTIFICATE_EXPIRED / _NOT_YET_VALID
//	chain did not verify                  FAIL    TLS_UNKNOWN_AUTHORITY
//	any other handshake failure           FAIL    TLS_HANDSHAKE_FAILURE
//	a timeout svcdoctor cannot attribute  UNKNOWN EXEC_LOCAL_TIMEOUT
//	the caller's deadline expired         UNKNOWN EXEC_LOCAL_TIMEOUT
//	the caller cancelled                  UNKNOWN EXEC_CANCELLED
//
// Classification uses typed errors only. Error text is never matched, and where
// the standard library does not expose a distinction structurally the probe
// records the weaker class rather than inventing precision — see the classifier
// for the two cases where that happens.
//
// # Facts, not judgements
//
// The probe records that a certificate is valid until a given instant, that the
// negotiated version is TLS1.2, that a named cipher suite was chosen. It never
// records that a certificate expires *soon*, that a version is *old*, or that a
// cipher is *weak*. Those are impact judgements, they need policy, and policy is
// diagnosis work that runs later on frozen evidence.
//
// # Identity is verified; the socket is connected to an address
//
// A handshake happens over a concrete address and verifies a logical name. Those
// are two different facts and this package keeps them apart: the evidence
// subject is the address the connection was made to, and the name whose identity
// was checked is recorded as an attribute. Overwriting the subject with the
// server name would claim the socket went somewhere it did not.
//
// The server name is never inferred from the address. A caller that wants an IP
// verified passes the IP as the server name deliberately.
//
// # Verification is on unless a caller turns it off
//
// The zero Params verifies against the system trust store. Disabling
// verification is explicit, it is never an automatic retry after a failure, and
// it is recorded on the node: a handshake that skipped verification proves
// encryption, not identity, and tls.verified says so. Diagnosis reads only the
// evidence graph (ADR 0017), so a fact that lives only in report-level security
// metadata would be invisible to it.
package tls
