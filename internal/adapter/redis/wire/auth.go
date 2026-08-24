package wire

import (
	"context"
	"fmt"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/security"
)

// Auth is the normalized outcome of the one credential-bearing command a Redis
// run may send.
type Auth struct {
	// Prefix is PrefixNone when the endpoint answered +OK.
	Prefix ErrorPrefix
}

// Accepted reports that the endpoint answered +OK.
//
// # It does not mean the credential is correct
//
// Verified upstream: ACLCheckUserCredentials returns C_OK for a `nopass` user
// **before examining the password** (redis/src/acl.c:1485), so `AUTH <user>
// <anything>` succeeds against a default-configured server. ADR 0064 section 6
// fixes the wording every layer above must use — the endpoint accepted this
// credential — and forbids "the credential is valid".
func (a Auth) Accepted() bool { return a.Prefix == PrefixNone }

// Rejected reports that the endpoint answered WRONGPASS.
//
// # It names no cause, because Redis names none
//
// `-WRONGPASS invalid username-password pair or user is disabled.` is a single
// reply site (redis/src/acl.c:1511) covering an unknown user, a wrong password
// and a disabled user. The distinction exists inside the server as ENOENT versus
// EINVAL and is discarded before the reply is built. Any layer above that said
// "wrong password" would be inventing one of three possibilities.
func (a Auth) Rejected() bool { return a.Prefix == PrefixWRONGPASS }

// SendAuth performs the single credential-bearing exchange.
//
// # The operator's form, verbatim
//
// An empty username sends the one-argument form and a non-empty username sends
// the two-argument form. **`default` is never synthesized.** The two forms are
// not equivalent: against a `nopass` default user the one-argument form errors
// and the two-argument form returns +OK (redis/src/acl.c:3369-3378), so
// normalizing would turn a true configuration finding into a false success.
//
// # It is called at most once per run
//
// Not by a check inside this function — a counter here could be reset — but by
// construction above it. internal/adapter/redis.Authenticate is the only caller,
// it takes one session and holds no loop, and a structural test asserts there is
// exactly one call site. See ADR 0064 section 4.
//
// # The only Reveal in this package
//
// Revealed once, immediately before the framing that puts it on the socket. Not
// stored, not logged, not returned and not placed in any error. No erasure is
// claimed or attempted: encodeCommand copies the bytes and Go strings are
// immutable, so a Zero call would contradict what internal/security/doc.go has
// said since Phase 1.
func (c *Conn) SendAuth(
	ctx context.Context, timeout time.Duration, username string, secret security.Secret,
) (Auth, error) {
	if secret.IsEmpty() {
		// Unreachable behind the adapter, which does not call this without a
		// credential. Refusing rather than sending `AUTH ""` keeps it that way:
		// an empty password is a credential attempt the endpoint would count.
		return Auth{}, fmt.Errorf("%w: AUTH requires a credential", ErrInvalidInput)
	}

	password := security.Reveal(secret)

	var (
		frame []byte
		err   error
	)
	if username == "" {
		frame, err = encodeCommand("AUTH", password)
	} else {
		frame, err = encodeCommand("AUTH", username, password)
	}
	if err != nil {
		return Auth{}, err
	}

	r, exErr := c.exchange(ctx, timeout, frame)
	if exErr != nil {
		return Auth{}, exErr
	}

	switch r.kind {
	case kindError:
		return Auth{Prefix: classifyErrorText(r.text)}, nil
	case kindSimpleString:
		// Redis answers +OK. Anything else with a simple-string shape is not a
		// success this package will report as one.
		if r.text == "OK" {
			return Auth{Prefix: PrefixNone}, nil
		}
		return Auth{}, fmt.Errorf("%w: AUTH answered with an unexpected status", ErrUnexpectedReply)
	default:
		return Auth{}, fmt.Errorf("%w: AUTH answered with a non-status reply", ErrUnexpectedReply)
	}
}
