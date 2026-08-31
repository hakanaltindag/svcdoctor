package cli

import (
	"errors"
	"io"

	"github.com/hakanaltindag/svcdoctor/internal/security"
	"github.com/hakanaltindag/svcdoctor/internal/security/secretinput"
)

// maxCredentialInput bounds the credential material this command will read.
//
// The value and its whole justification live in internal/security/secretinput,
// which Phase 9.1A extracted so that the fleet credential resolver could reuse
// the rules rather than restate them (ADR 0072 section 12). This alias exists so
// that the flag-facing code still reads in the vocabulary of the flags.
const maxCredentialInput = secretinput.MaxInput

// credentialSources names what the invocation selected.
type credentialSources struct {
	file      string
	fromStdin bool
}

// validate enforces exclusivity.
//
// # No precedence, deliberately
//
// Two sources is an error rather than a resolution. A precedence rule is one
// more thing to remember under pressure, and the failure it hides — *svcdoctor
// used the other credential* — is exactly the one that costs an hour during an
// incident. Refusing ambiguity is stronger than resolving it (ADR 0049 §2).
func (c credentialSources) validate() error {
	if c.file != "" && c.fromStdin {
		return usagef("--password-file and --password-stdin are mutually exclusive")
	}
	return nil
}

// readSecret returns the credential material the invocation selected.
//
// # No source is not an error
//
// It returns the zero Secret, and that is a valid run. An endpoint demanding
// authentication then produces POSTGRES_CREDENTIAL_NOT_CONFIGURED — a truthful
// WARN at exit 0 — which is why this command never has to acquire a credential
// it was not given, and why there is no prompt (ADR 0049 §2).
//
// # There is no fallback between sources
//
// A named source that cannot be read is an error. It is never quietly replaced
// by the other one: an operator who wrote --password-file must not silently
// authenticate with whatever happened to be on stdin.
func (a *App) readSecret(sources credentialSources) (security.Secret, error) {
	switch {
	case sources.file != "":
		return a.readSecretFile(sources.file)
	case sources.fromStdin:
		plaintext, err := readBoundedSecret(a.In)
		if err != nil {
			return security.Secret{}, usagef("reading the credential from stdin: %s", err)
		}
		return security.NewSecret(plaintext), nil
	default:
		return security.Secret{}, nil
	}
}

// readSecretFile reads credential material from a path the operator named.
//
// The **path** appears in errors, because a file svcdoctor cannot use has to be
// nameable or the operator cannot fix it. The **contents** appear nowhere, and
// neither does their length: a size is a fact derived from the secret and it
// buys the reader nothing (ADR 0049 §3).
//
// The reading rules are internal/security/secretinput's; the wording is this
// package's, because an operator has to be told which flag to fix. A directory
// is still named as a directory rather than left to surface as "unreadable",
// which is the distinction that survives the extraction because the shared
// package reports it as its own sentinel.
func (a *App) readSecretFile(path string) (security.Secret, error) {
	plaintext, err := secretinput.ReadFile(path)
	switch {
	case err == nil:
		return security.NewSecret(plaintext), nil
	case errors.Is(err, secretinput.ErrIsDirectory):
		return security.Secret{}, usagef("--password-file %s is a directory", path)
	case errors.Is(err, secretinput.ErrTooLarge), errors.Is(err, secretinput.ErrNoReader):
		return security.Secret{}, usagef("--password-file %s: %s", path, err)
	case errors.Is(err, secretinput.ErrUnreadable):
		return security.Secret{}, usagef("--password-file %s cannot be read: unreadable", path)
	default:
		return security.Secret{}, usagef(
			"--password-file %s cannot be read: %s", path, openReason(err))
	}
}

// readBoundedSecret reads at most one byte past the limit and refuses the rest.
//
// The rule and its justification are in internal/security/secretinput. This stays
// as the name the flag-facing code and its tests already use.
func readBoundedSecret(r io.Reader) (string, error) {
	return secretinput.Read(r)
}

// trimOneLineEnding removes a single trailing "\r\n" or "\n", and nothing else.
func trimOneLineEnding(s string) string {
	return secretinput.TrimOneLineEnding(s)
}

// credentialFor binds a secret to the endpoint that authorizes it.
//
// # An empty secret produces no credential at all, and that is load-bearing
//
// security.NewSecret("") is the zero Secret, but security.Credential.IsZero
// reads only its **endpoint** — so a credential built around an empty secret is
// *not* zero, and internal/adapter/postgres would walk straight past its
// "nothing to present" branch and attempt SCRAM with an empty password.
//
// So an empty source leaves the credential unset, which is the honest mapping:
// the run was given nothing to present, which is exactly what
// EXEC_REQUIRED_INPUT_MISSING means. An empty file, a file holding one newline,
// and no --password-file at all therefore reach the same place, and none of them
// puts a byte on the wire.
func credentialFor(host string, port uint16, role string, secret security.Secret) (
	security.Credential, error,
) {
	if secret.IsEmpty() {
		return security.Credential{}, nil
	}

	endpoint, err := security.NewEndpoint(host, port)
	if err != nil {
		return security.Credential{}, usagef("binding the credential to %s: %v", host, err)
	}
	credential, err := security.NewCredential(endpoint, role, secret)
	if err != nil {
		return security.Credential{}, usagef("building the credential: %v", err)
	}
	return credential, nil
}

// openReason reduces a filesystem error to its cause, naming nothing else.
func openReason(err error) string {
	return secretinput.OpenReason(err)
}
