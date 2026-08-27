// Package rabbitmq turns one AMQP 0-9-1 connection into three evidence nodes.
//
// It is the RabbitMQ half of the boundary CLAUDE.md draws: probes collect
// transport facts, this package understands the protocol, and
// internal/diagnosis/rabbitmq correlates what it recorded. It performs no DNS
// resolution, opens no socket and completes no TLS handshake — the generic
// transport chain does all three and hands over a live connection (ADR 0021).
//
// # The journey is frozen and this package implements it literally
//
// ADRs 0067 to 0070 decide every question this package could otherwise answer:
// which methods may be sent, which mechanism is selected, how many
// credential-bearing frames a run may spend, what the terminal boundary proves,
// and how a refusal is classified. `docs/validation/RABBITMQ_PHASE80_CONTRACT_STUDY.md`
// records the measurements behind them.
//
//	Start        protocol header, Connection.Start        → rabbitmq.connection_start
//	Authenticate Connection.Start-Ok (PLAIN), Tune, Tune-Ok → rabbitmq.authentication
//	Open         Connection.Open, Open-Ok, Close/Close-Ok  → rabbitmq.connection_open
//
// Three nodes and no more. `Connection.Tune` is authentication's success signal
// rather than a step of its own, and there is no vhost node because there is no
// vhost measurement separate from opening a connection in it (ADR 0067 §4).
//
// # This package cannot open a secret
//
// `security.Reveal` lives in the wire package below and is confined there by
// lint. What this package holds is the *authority* decision: `SecretFor` is
// called here, exactly once, with the operator's logical endpoint, and a
// credential bound to any other endpoint is refused before a byte is written.
//
// # Nothing here retries
//
// One connection. No redial, no reconnect, no second authentication, no
// mechanism fallback. Those are not forbidden by a check that could be reset;
// they are unwritten, and structural guards assert their absence.
package rabbitmq
