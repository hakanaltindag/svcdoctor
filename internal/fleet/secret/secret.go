// Package secret resolves a configuration's credential references.
//
// It is the only package in the fleet layer that reads an environment variable
// or opens a credential file, and it is where a security.Secret is built and
// bound to the endpoint that authorizes it.
//
// # What it knows, and what it must not
//
// It knows env and file mechanics. It does not know PostgreSQL, Kafka, Redis or
// RabbitMQ, holds no protocol type, and contains no service name — a fifth
// service needs nothing here. It never calls security.Reveal: revealing is the
// adapter wire packages' single privilege and `forbidigo` fails the build on a
// call site anywhere else (ADR 0027).
//
// # Why the config package cannot do this
//
// internal/fleet/config does not import internal/security, so it cannot build a
// secret even by mistake — the type is not in scope. That is ADR 0072 section 6
// as a compile-time property rather than a convention, and it is what makes
// "the parser must not reveal secrets" checkable.
//
// # There is no cache
//
// Deliberately, and it is load-bearing rather than an omission. ADR 0072
// section 8: a cache would have to be keyed by the reference, a reference is not
// an authority, and handing target B a credential built for target A's endpoint
// would produce a SecretFor mismatch at the wire boundary — an error, caught
// late, in the one code path where being wrong is most expensive. Two targets
// naming one variable resolve it twice. Reading an environment variable twice is
// free; an invariant that holds by construction is not.
package secret

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/hakanaltindag/svcdoctor/internal/fleet/config"
	"github.com/hakanaltindag/svcdoctor/internal/security"
	"github.com/hakanaltindag/svcdoctor/internal/security/secretinput"
)

// ErrResolution marks every failure this package produces.
//
// It is separate from config.ErrConfig because the two happen at different times
// and mean different things. A configuration error is a defect in what the
// operator wrote and is found before anything runs; a resolution failure means
// the reference was well formed and the material behind it could not be
// obtained. ADR 0074 section 4.2 maps the second to EXECUTION_FAILED, and the
// first to exit 2 with no report at all.
var ErrResolution = errors.New("credential resolution failed")

// Resolver obtains credential material named by a reference.
//
// It is a struct with no fields rather than an interface with one
// implementation. ADR 0009 declines a speculative abstraction, and there is
// exactly one way to resolve `env` and one way to resolve `file`. An interface
// here would also be a seam through which a caching implementation could be
// substituted, which section 8 of ADR 0072 spent its length refusing.
type Resolver struct{}

// NewResolver returns the resolver.
func NewResolver() *Resolver { return &Resolver{} }

// Preflight proves a reference can be resolved, and retains nothing.
//
// # The distinction this implements
//
// ADR 0072 section 5.2 weighed three designs and chose two halves of two of
// them: preflight validates resolvability so that nothing starts if a reference
// is unusable, and resolution happens per target so that at most `concurrency`
// secrets are ever alive at once — a 128-fold reduction in residency against
// resolving everything upfront at the maximum target count.
//
// # For env, a value is read and dropped
//
// os.LookupEnv returns the value in order to report presence, and there is no
// API that reports only presence. So one value is held transiently, one at a
// time, and is not returned, stored, logged or copied. That is stated plainly
// rather than glossed, because the alternative — not checking env references at
// all — means a run with one typo'd variable name executes 49 targets before
// failing on the 50th.
//
// # For file, nothing is read
//
// os.Stat proves existence, type and size without reading a byte, which is the
// stronger of the two guarantees and is available because a filesystem exposes
// metadata separately.
func (r *Resolver) Preflight(ref config.Reference) error {
	switch ref.Kind() {
	case config.SourceNone:
		// A target with no credential reference is a supported run: it reaches
		// its endpoint and produces <SERVICE>_CREDENTIAL_NOT_CONFIGURED, a WARN
		// at exit 0. There is nothing to prove.
		return nil

	case config.SourceEnv:
		value, present := os.LookupEnv(ref.Name())
		if !present {
			return refErrorf(ref, "the environment variable is not set")
		}
		if value == "" {
			return refErrorf(ref, "the environment variable is set but empty")
		}
		// The value goes out of scope here, unread and uncopied. Nothing below
		// this line can see it.
		return nil

	case config.SourceFile:
		return preflightFile(ref)

	default:
		return refErrorf(ref, "names an unsupported credential source")
	}
}

// PreflightAll proves every reference in a configuration resolvable.
//
// Declared order, and it stops at the first failure: a configuration with two
// missing variables is fixed one at a time anyway, and reporting them together
// would mean holding a list of failures whose only purpose is to be printed.
func (r *Resolver) PreflightAll(cfg config.Config) error {
	for _, target := range cfg.Targets {
		if err := r.Preflight(target.Credentials.Password); err != nil {
			return fmt.Errorf("target %q: %w", target.ID, err)
		}
	}
	return nil
}

// Resolve obtains the credential material a reference names.
//
// It is called once per target, immediately before that target executes, and the
// value it returns lives for that target's execution only.
//
// # Every call resolves independently
//
// Two targets naming SHARED_PASSWORD produce two calls and two security.Secret
// values. The references being identical is a coincidence of the file, not a
// fact about either endpoint.
func (r *Resolver) Resolve(ctx context.Context, ref config.Reference) (security.Secret, error) {
	if ctx == nil {
		return security.Secret{}, fmt.Errorf("%w: no context", ErrResolution)
	}
	// A resolution is a local read and is quick, but a cancelled run must not
	// start new work — including work that touches a secret.
	if err := ctx.Err(); err != nil {
		return security.Secret{}, fmt.Errorf("%w: %w", ErrResolution, err)
	}

	switch ref.Kind() {
	case config.SourceNone:
		// The honest mapping of "no reference": the zero Secret, which
		// CredentialFor turns into no credential at all.
		return security.Secret{}, nil

	case config.SourceEnv:
		value, present := os.LookupEnv(ref.Name())
		switch {
		case !present:
			return security.Secret{}, refErrorf(ref, "the environment variable is not set")
		case value == "":
			return security.Secret{}, refErrorf(ref,
				"the environment variable is set but empty")
		}
		return security.NewSecret(value), nil

	case config.SourceFile:
		return resolveFile(ref)

	default:
		return security.Secret{}, refErrorf(ref, "names an unsupported credential source")
	}
}

// CredentialFor resolves a target's reference and binds it to that target's
// endpoint.
//
// # Binding is separate from resolving, and both are here
//
// Resolve is service-neutral and authority-free: it turns a name into material.
// This is where authority is established, and it is established from the
// target's **own** host and port — never from another target's, never from a
// reference, and never from a target identifier. ADR 0072 section 7: a target ID
// identifies a logical execution, is not an endpoint, and no code path binds a
// credential to one.
//
// # An empty secret produces no credential at all
//
// security.NewSecret("") is the zero Secret, but security.Credential.IsZero
// reads only its endpoint — so a credential built around an empty secret is
// *not* zero, and an adapter would walk past its "nothing to present" branch and
// attempt authentication with an empty password. internal/cli/secret.go makes
// the same choice for the same reason.
//
// Reaching that state through a written reference is a resolution failure rather
// than a silent unset, because ADR 0072 section 5.1 requires a reference to
// resolve to something non-empty: an operator who wrote `password: {file: X}`
// asked for a credential, and reporting "no credential was configured" when the
// store returned nothing would describe the wrong problem.
func (r *Resolver) CredentialFor(
	ctx context.Context, target config.Target,
) (security.Credential, error) {
	ref := target.Credentials.Password
	if ref.IsZero() {
		return security.Credential{}, nil
	}

	plaintext, err := r.Resolve(ctx, ref)
	if err != nil {
		return security.Credential{}, err
	}
	if plaintext.IsEmpty() {
		return security.Credential{}, refErrorf(ref, "resolved to an empty credential")
	}

	endpoint, err := security.NewEndpoint(target.Host, target.Port)
	if err != nil {
		return security.Credential{}, fmt.Errorf("%w: binding the credential to the target's "+
			"endpoint: %w", ErrResolution, err)
	}
	credential, err := security.NewCredential(endpoint, target.Credentials.Username, plaintext)
	if err != nil {
		return security.Credential{}, fmt.Errorf("%w: %w", ErrResolution, err)
	}
	return credential, nil
}

// refErrorf builds a resolution error that names the reference and never its value.
//
// The **name** appears: an environment variable svcdoctor cannot read has to be
// nameable or the operator cannot fix it, which is ADR 0049 section 3's rule for
// `--password-file`'s path applied to both sources. The **value** never appears,
// and neither does its length — a size is a fact derived from the secret and it
// buys the reader nothing.
//
// ADR 0072 section 10 splits the two surfaces: a reference name may reach stderr
// and must never reach a canonical report. This produces the former; nothing in
// the fleet layer puts it in the latter.
func refErrorf(ref config.Reference, reason string) error {
	return fmt.Errorf("%w: credential %s %s: %s",
		ErrResolution, ref.Kind(), ref.Name(), reason)
}

// preflightFile proves a credential file is usable without reading it.
//
// # The regular-file requirement is the fleet preflight's, not the flag's
//
// ADR 0072 section 5.1 froze this check as "resolves to a regular file,
// non-empty, within the size bound". `--password-file` has no preflight at all
// and so has no equivalent, and internal/security/secretinput deliberately does
// not impose one — tightening released input handling is a decision for
// ADR 0049, for all four leaf commands at once, and this phase does not make it.
//
// Symlinks are followed, because os.Stat follows them and because a secret
// delivered by a container runtime or a Kubernetes projected volume is reached
// through one. What must be true is that the destination is a regular file, so a
// FIFO cannot make a preflight block forever.
func preflightFile(ref config.Reference) error {
	info, err := os.Stat(ref.Name())
	if err != nil {
		return refErrorf(ref, secretinput.OpenReason(err))
	}
	switch {
	case info.IsDir():
		return refErrorf(ref, "the path is a directory")
	case !info.Mode().IsRegular():
		return refErrorf(ref, fmt.Sprintf(
			"the path is not a regular file (mode %s)", info.Mode().Type()))
	case info.Size() == 0:
		return refErrorf(ref, "the file is empty")
	case info.Size() > secretinput.MaxInput+1:
		// Compared against one byte past the bound for the same reason the read
		// itself is: a file exactly at the maximum plus its trailing newline is
		// the boundary case, and the read is what decides it. This refuses only
		// what cannot possibly be within the bound.
		return refErrorf(ref, "the file is larger than the credential input limit")
	}
	return nil
}

// resolveFile reads a credential file through the one shared implementation.
//
// internal/security/secretinput holds the semantics ADR 0049 section 3 fixed and
// ADR 0072 section 12 inherits unchanged: a 4 KiB bound measured on the input, a
// read of one byte past it, exactly one trailing line ending removed, leading and
// trailing spaces kept, an embedded NUL passed through, and a second line kept.
//
// Not a second implementation, and not a second interpretation.
func resolveFile(ref config.Reference) (security.Secret, error) {
	plaintext, err := secretinput.ReadFile(ref.Name())
	switch {
	case err == nil:
		return security.NewSecret(plaintext), nil
	case errors.Is(err, secretinput.ErrIsDirectory):
		return security.Secret{}, refErrorf(ref, "the path is a directory")
	case errors.Is(err, secretinput.ErrTooLarge):
		return security.Secret{}, refErrorf(ref, err.Error())
	case errors.Is(err, secretinput.ErrUnreadable):
		return security.Secret{}, refErrorf(ref, "unreadable")
	default:
		return security.Secret{}, refErrorf(ref, secretinput.OpenReason(err))
	}
}
