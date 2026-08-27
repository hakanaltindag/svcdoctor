// Package wire speaks AMQP 0-9-1's connection class and nothing else.
//
// It is the narrowest boundary in the RabbitMQ adapter: the only package that
// encodes an AMQP frame, the only one that sees a peer's reply text, and the
// only one that may call security.Reveal. Everything above it receives
// normalized values — never a peer's bytes, never a raw error string.
//
// The contract it implements is frozen in ADRs 0067 to 0070 and measured in
// docs/validation/RABBITMQ_PHASE80_CONTRACT_STUDY.md. It invents nothing.
//
// # Only the connection class is representable
//
// encodeMethod takes a connectionMethod, not a class id and a method id. The
// class is a constant inside it. So Channel.Open, Queue.Declare,
// Exchange.Declare and every Basic method are not "forbidden by review" — there
// is no expression in this package that constructs one, and adding the ability
// would mean changing the encoder's signature. ADR 0067 section 2 lists the five
// outbound methods; connectionMethod has exactly five values.
//
// # One credential-bearing frame
//
// SendStartOk is the only function here that calls security.Reveal, the only one
// that touches a secret at all, and it is called once per run by construction
// above rather than by a counter here. ADR 0068 section 5.
//
// # No peer text escapes
//
// A Connection.Close carries a reply text that RabbitMQ interpolates the vhost
// and username into, and that an authorization backend can append arbitrary
// bytes to. This package reads at most 255 of those bytes, compares them against
// candidates it renders from svcdoctor's *own* inputs, and returns a
// CloseOutcome constant. No slice of the peer's buffer is retained, returned,
// wrapped in an error or logged. ADR 0069 sections 2 and 3.
//
// # It owns no socket
//
// NewConn wraps a live connection somebody else established. This package never
// dials, never performs a TLS handshake and never closes what it was given
// (ADR 0021), exactly as the Kafka, PostgreSQL and Redis wire packages do not.
package wire
