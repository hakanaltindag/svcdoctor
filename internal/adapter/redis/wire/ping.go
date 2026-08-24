package wire

import (
	"context"
	"fmt"
	"time"
)

// Ping is the normalized outcome of the terminal usability probe.
type Ping struct {
	// Prefix is PrefixNone when the endpoint answered +PONG.
	Prefix ErrorPrefix
}

// Pong reports that the endpoint answered +PONG.
//
// # Why this command and not a cheaper one
//
// PING is the only command in the allowlist that carries none of CMD_NO_AUTH,
// CMD_LOADING or CMD_STALE (redis/src/commands/ping.json), so it is the only one
// gated simultaneously on authentication, ACL authorization, dataset-loading
// state and stale-replica state. HELLO and AUTH are exempt from the ACL command
// check entirely (redis/src/acl.c:1726), so neither can prove authorization.
//
// What it authorizes anyone above to say is fixed by ADR 0063 section 4 and is
// endpoint-scoped: this endpoint answered PING with PONG on this connection.
// Never that Redis, the backend, the cluster or replication is healthy.
func (p Ping) Pong() bool { return p.Prefix == PrefixNone }

// SendPing performs the terminal probe.
//
// No message argument. `PING <message>` would have the endpoint echo a value
// back, adding a peer-controlled string to the reply in exchange for no evidence
// the bare form does not already give.
func (c *Conn) SendPing(ctx context.Context, timeout time.Duration) (Ping, error) {
	r, err := c.exchange(ctx, timeout, pingFrame)
	if err != nil {
		return Ping{}, err
	}

	switch r.kind {
	case kindError:
		return Ping{Prefix: classifyErrorText(r.text)}, nil
	case kindSimpleString:
		if r.text == "PONG" {
			return Ping{Prefix: PrefixNone}, nil
		}
		return Ping{}, fmt.Errorf("%w: PING answered with an unexpected status", ErrUnexpectedReply)
	default:
		// A subscribed connection answers PING with an array, but svcdoctor
		// never subscribes, so an array here is not a shape this step allows.
		return Ping{}, fmt.Errorf("%w: PING answered with a non-status reply", ErrUnexpectedReply)
	}
}
