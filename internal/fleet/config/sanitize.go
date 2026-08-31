package config

import (
	"regexp"
	"strings"
)

// yamlScalarInError matches the offending value the YAML decoder quotes into its
// own error strings.
//
// # Why this exists, and why it is a security control rather than tidiness
//
// go.yaml.in/yaml/v3 formats a type mismatch as
//
//	cannot unmarshal !!str `hunter2` into config.credentialRef
//
// with the **offending scalar interpolated into the message**. That is exactly
// the shape a plaintext password in a configuration file produces, because
// ADR 0072 section 3 refuses `password: hunter2` at the type level — so the
// single most security-relevant refusal this package makes is also the one whose
// library error carries the secret.
//
// Phase 9.1A measured that before writing any of this package. Propagating the
// decoder's text unchanged would put a plaintext password on the operator's
// terminal, into whatever collects their stderr, and into any support bundle
// built from it.
//
// # Why a sanitizer as well as an interceptor
//
// credentialRef.UnmarshalYAML intercepts a non-mapping node and produces its own
// message, so the common case never reaches the decoder's formatter. That guard
// is specific: it protects the position a credential is *supposed* to be in.
//
// This is the general one, and the two are deliberately redundant. An operator
// who writes `credentials: hunter2`, or who puts a password in a field this
// schema has not yet imagined, still gets a message with no value in it. A
// defence that only covers the shapes someone anticipated is the defence that
// fails on the shape they did not.
//
// # Why redacting backticks costs nothing diagnostically
//
// The three error families this package surfaces are:
//
//	field X not found in type Y            — no backticks, untouched
//	mapping key "x" already defined ...    — double quotes, untouched
//	cannot unmarshal !!str `V` into T      — the value is redacted, the tag and
//	                                         the target type are what a reader
//	                                         actually needs, and both survive
//
// So the sanitizer only fires on the family that leaks, and it preserves the
// part of that family which explains the defect.
var yamlScalarInError = regexp.MustCompile("`[^`]*`")

// redactedScalar replaces a quoted value. It is not the value's length, not its
// prefix and not its hash: every one of those is a fact derived from a secret,
// which ADR 0049 section 3 already refuses to report for the same reason.
const redactedScalar = "`<value redacted>`"

// internalTypeInError matches the Go type name the decoder names in an
// unknown-field error.
//
// `field bogus not found in type config.targetBlock` tells an operator about an
// implementation detail they cannot act on, and names an unexported type they
// cannot look up. The field name — which is theirs — is already in the message,
// and it is the part that matters.
var internalTypeInError = regexp.MustCompile(` not found in type \S+`)

// sanitizeYAML makes a decoder error safe to show and safe to store.
//
// It removes every backtick-quoted span, collapses the decoder's multi-line
// "yaml: unmarshal errors:" block onto one line, and drops the "yaml:" prefix
// that would otherwise tell an operator about an implementation detail they
// cannot act on.
//
// It is applied to **every** error that comes out of the YAML library, at the
// one place each of them is converted into a config.Error, so there is no path
// by which raw decoder text reaches a caller.
func sanitizeYAML(err error) string {
	if err == nil {
		return ""
	}
	text := yamlScalarInError.ReplaceAllString(err.Error(), redactedScalar)
	text = internalTypeInError.ReplaceAllString(text, " is not a field this schema defines")

	lines := strings.Split(text, "\n")
	cleaned := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		switch line {
		case "":
			continue
		case "yaml: unmarshal errors:":
			// A header with no content of its own. Its list follows.
			continue
		}
		cleaned = append(cleaned, strings.TrimPrefix(line, "yaml: "))
	}
	if len(cleaned) == 0 {
		return "the document could not be decoded"
	}
	return strings.Join(cleaned, "; ")
}
