// Package tcp attempts one TCP connection to one concrete address and reports
// what happened.
//
//	Connect -> observation (producer-local) -> domain.Evidence + a live connection
//
// It follows the probe contract established by the DNS probe in ADR 0020. The
// difference is that a successful TCP attempt produces something DNS never
// did: a resource. How that resource changes hands is ADR 0021 and the most
// important thing in this package.
//
// # A connection is produced, not consumed and discarded
//
// The architecture requires that generic transport own DNS, TCP and TLS, and
// hand a live connection to whatever needs it next. The failure mode it exists
// to prevent is this one:
//
//	probe:   dial -> measure -> close
//	adapter: dial again
//
// That is forbidden. A second dial is a second connection, and every fact
// measured about the first one then describes something the protocol exchange
// never used. Worse, nothing fails: the report still looks right.
//
// So a successful Connect returns a Result holding both the evidence and the
// established connection, and the probe does not close it. Ownership is explicit:
//
//	r, err := tcp.Connect(ctx, dialer, "primary.internal:9092", addr)
//	if err != nil { return err }
//	defer r.Close()                  // safe in every path, including after a transfer
//
//	if conn, ok := r.TakeConn(); ok {
//	    defer conn.Close()           // the caller owns it now
//	    // hand conn to the next stage
//	}
//
// Close is always safe to defer: it closes the connection only while the Result
// still owns it, and does nothing once a caller has taken it or after a first
// close. That makes the correct usage also the obvious one, which is the only
// kind of resource discipline that survives contact with real code.
//
// # Evidence never owns the connection
//
// domain.Evidence holds no net.Conn and cannot: its attributes are a closed union
// of normalized values (ADR 0010). The graph holds evidence, the report holds the
// graph, and none of them can hold a live resource. Result is the only thing that
// does, it never enters the domain model, and it is not what gets serialized.
//
// Evidence and runtime resources have different lifetimes on purpose. The
// evidence outlives the connection and describes a moment that has already
// passed.
//
// # One address per call
//
// Connect takes one concrete netip.AddrPort. A name that resolves to three
// addresses produces three calls and three evidence nodes, because three
// connection attempts are three facts and collapsing them would hide that two
// addresses work and one does not.
//
// The probe therefore cannot select, prefer, race or fall back between
// addresses — it never sees more than one. Which addresses to attempt, in what
// order, and whether to stop after the first success is scheduling policy that
// belongs to the transport chain, which does not exist yet. Neither IPv4 nor IPv6
// is preferred, degraded or unusual here.
//
// The dialer seam takes a netip.AddrPort rather than a string for the same
// reason: a string address could be a name, and a name would be resolved inside
// the dialer, silently repeating L1 inside L2 and attributing DNS latency to a
// connection attempt. The type makes that impossible.
//
// # What it observes, and what it refuses to claim
//
//	dial returned a connection          PASS    -
//	peer refused the connection         FAIL    TCP_CONNECTION_REFUSED
//	peer reset the connection           FAIL    TCP_CONNECTION_RESET
//	network unreachable                 FAIL    TCP_NETWORK_UNREACHABLE
//	host unreachable                    FAIL    TCP_HOST_UNREACHABLE
//	the network stack timed out         FAIL    TCP_CONNECTION_TIMEOUT
//	any other dial error                FAIL    TCP_CONNECTION_FAILED
//	a timeout svcdoctor cannot attribute UNKNOWN EXEC_LOCAL_TIMEOUT
//	the caller's deadline expired       UNKNOWN EXEC_LOCAL_TIMEOUT
//	the caller cancelled                UNKNOWN EXEC_CANCELLED
//
// Classification uses structured errors — syscall error numbers reached through
// errors.Is — never error text. Text is a moving target across platforms and Go
// releases, and matching on it would produce confident claims that quietly stop
// being true.
//
// The last three rows are the claim discipline. A deadline belonging to svcdoctor
// says nothing about the target, so it can never become TCP_CONNECTION_TIMEOUT.
// The kernel's own ETIMEDOUT is different: it means the peer did not answer a SYN
// within the stack's limit, which is evidence about the network. Those two look
// identical through net.Error.Timeout, which is why the error number is checked
// first and the generic timeout test only catches what is left.
//
// Duration is recorded as a fact. Whether a connection was "slow" is diagnosis
// policy and no threshold exists here.
//
// # No attributes
//
// This probe records none. What it observed is fully expressed by the subject —
// the concrete address it dialed — together with the state, the failure class and
// the duration Evidence already carries. A peer-address attribute would restate
// the subject, and a family attribute would restate the address.
package tcp
