package config

import (
	"fmt"
	"strconv"

	yaml "go.yaml.in/yaml/v3"
)

// SourceKind names where a credential is stored.
//
// A closed set of exactly two, from ADR 0072 section 2. It is closed because
// every additional source is a decision with its own security review — a secret
// manager is a network client, an `exec:` provider is arbitrary code execution —
// and none of them is authorized for v1.
type SourceKind uint8

const (
	// SourceNone is the zero value and means no credential reference.
	SourceNone SourceKind = iota

	// SourceEnv reads a named process environment variable.
	SourceEnv

	// SourceFile reads a file at a named path.
	SourceFile
)

// sourceKindNames is indexed by SourceKind. Keep it aligned with the const block
// above; TestSourceKindNamesCoverEveryValue fails if the two drift.
var sourceKindNames = [...]string{
	SourceNone: "none",
	SourceEnv:  "env",
	SourceFile: "file",
}

// String returns the symbolic name. It never fails.
func (k SourceKind) String() string {
	if int(k) >= len(sourceKindNames) {
		return "SourceKind(" + strconv.FormatUint(uint64(k), 10) + ")"
	}
	return sourceKindNames[k]
}

// maxEnvNameBytes bounds an environment variable name.
//
// Not a resource bound — a name is bounded by the environment block anyway — but
// an input-sanity one. The longest variable name in common tooling is well under
// 64 bytes, so this is roughly twice the largest real value and refuses input
// that is much more likely to be a pasted value than a name.
const maxEnvNameBytes = 128

// Reference names where a credential lives. It never holds one.
//
// # This type is the whole of ADR 0072's "config references secrets; it does not contain them"
//
// It has two string fields, both of which are *names*: a variable name and a
// path. There is no field a secret value could be assigned to, so no formatting
// verb can print one, no serialization can emit one, and no accessor can return
// one. That is a property of the type rather than a rule someone follows.
//
// # Exactly one source, and a plaintext scalar cannot be written at all
//
// `password: hunter2` is refused during decoding, by UnmarshalYAML below, before
// any validation runs. ADR 0072 section 3 requires that refusal to be structural
// precisely because a hand-written check is one someone can move, reorder or
// forget — and the thing being forgotten would be a plaintext password in a file
// under version control.
//
// The zero Reference is absent, which is a valid configuration: a target with no
// password reaches its endpoint and produces
// <SERVICE>_CREDENTIAL_NOT_CONFIGURED, a WARN at exit 0.
type Reference struct {
	kind SourceKind
	// name is the environment variable name for SourceEnv, and the path for
	// SourceFile. It is never a secret value.
	name string
	// present records that the operator wrote a `password:` key, as distinct
	// from omitting one. It is what makes `password: {}` refusable, and it is
	// read only during validation.
	present bool
	// line is where the reference was written, for error location only.
	line int
}

// Kind returns which source the reference names, or SourceNone when absent.
func (r Reference) Kind() SourceKind { return r.kind }

// Name returns the environment variable name or the file path.
//
// It is a name and never a value. ADR 0072 section 10 permits it on stderr and
// forbids it in a canonical report; this package produces the former and never
// the latter.
func (r Reference) Name() string { return r.name }

// IsZero reports whether no credential reference was configured.
func (r Reference) IsZero() bool { return r.kind == SourceNone }

// String renders the reference without reading anything it names.
//
// Safe by construction rather than by redaction: there is no value in this type
// to omit. Resolving the reference is internal/fleet/secret's job and happens
// somewhere else entirely.
func (r Reference) String() string {
	if r.IsZero() {
		return "<no credential reference>"
	}
	return fmt.Sprintf("%s:%s", r.kind, r.name)
}

// GoString keeps %#v from printing the struct field by field.
func (r Reference) GoString() string {
	return fmt.Sprintf("config.Reference{kind: %s, name: %q}", r.kind, r.name)
}

// referenceFields is the decoded form of a credential reference mapping.
//
// It is separate from Reference so that Reference has no exported, settable
// field at all — a caller cannot construct one that claims a source it did not
// come from, and the union invariant is established once, here.
type referenceFields struct {
	Env  string `yaml:"env"`
	File string `yaml:"file"`
}

// UnmarshalYAML decodes a credential reference and refuses everything else.
//
// # The kind check happens before the decoder formats anything
//
// This is the security-critical ordering in the package. go.yaml.in/yaml/v3
// interpolates the offending scalar into its own type-mismatch errors, so
// letting `password: hunter2` reach the decoder's formatter would produce an
// error string containing the password. The node's Kind is inspected first, and
// a non-mapping is refused with a message built here that names the YAML kind
// and never the value.
//
// sanitizeYAML is the second line of defence for the shapes this does not cover.
// Both exist because a defence that only covers the anticipated shapes is the one
// that fails on the shape nobody anticipated.
func (r *Reference) UnmarshalYAML(value *yaml.Node) error {
	r.present = true
	r.line = value.Line

	if value.Kind != yaml.MappingNode {
		return newError(CategoryCredentialReference, fmt.Sprintf(
			"must be a mapping naming exactly one source, such as {env: NAME} or "+
				"{file: PATH}, and %s was written instead. A password is never written "+
				"into the configuration itself", describeKind(value))).onLine(value.Line)
	}

	var fields referenceFields
	if err := strictDecodeNode(value, &fields); err != nil {
		return newError(CategoryCredentialReference, sanitizeConfigErr(err)).onLine(value.Line)
	}

	switch {
	case fields.Env != "" && fields.File != "":
		// ADR 0049 section 2, applied to a written reference: two sources is an
		// error rather than a resolution, because the failure a precedence rule
		// hides is "svcdoctor used the other credential".
		return newError(CategoryCredentialReference,
			"names both \"env\" and \"file\"; exactly one source is required, and there is "+
				"deliberately no precedence between them").onLine(value.Line)
	case fields.Env != "":
		if err := checkEnvName(fields.Env); err != nil {
			return err.onLine(value.Line)
		}
		r.kind, r.name = SourceEnv, fields.Env
	case fields.File != "":
		r.kind, r.name = SourceFile, fields.File
	default:
		return newError(CategoryCredentialReference,
			"names no source; it must name exactly one of \"env\" or \"file\"").
			onLine(value.Line)
	}
	return nil
}

// describeKind names a YAML node kind in an operator's words, never its value.
func describeKind(node *yaml.Node) string {
	switch node.Kind {
	case yaml.ScalarNode:
		switch node.Tag {
		case "!!null":
			return "an empty value"
		default:
			return "a plain value"
		}
	case yaml.SequenceNode:
		return "a list"
	case yaml.AliasNode:
		return "an alias"
	case yaml.DocumentNode, yaml.MappingNode:
		return "a mapping"
	default:
		return "an unsupported value"
	}
}

// checkEnvName enforces the environment variable name grammar.
//
// # The grammar
//
//	1*128( ALPHA / DIGIT / "_" ), not starting with a digit
//
// It is POSIX's own "name" production, which is what every shell and every
// container runtime can actually set. Nothing wider is useful: a name containing
// "=" cannot be exported, and one containing a space cannot be set portably.
//
// # It is also what refuses interpolation
//
// `env: ${DB_PASSWORD}` fails here, on the brace, with a message that says
// interpolation does not exist. ADR 0071 section 8.3 refuses `${VAR}` anywhere in
// the configuration, and this is the one place an operator is most likely to
// reach for it — the field is already about the environment, so the habit
// transfers. Saying so explicitly is worth more than a generic character
// complaint.
func checkEnvName(name string) *Error {
	if len(name) > maxEnvNameBytes {
		return newError(CategoryCredentialReference, fmt.Sprintf(
			"names an environment variable of %d bytes, above the %d byte maximum",
			len(name), maxEnvNameBytes))
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '_':
		case c >= '0' && c <= '9' && i > 0:
		case c == '$' || c == '{' || c == '}':
			return newError(CategoryCredentialReference,
				"must be a bare environment variable name such as DB_PASSWORD, not a "+
					"${...} expression. svcdoctor performs no variable expansion anywhere "+
					"in a configuration, so a name is read exactly as written")
		default:
			return newError(CategoryCredentialReference, fmt.Sprintf(
				"names an environment variable containing %q; a name may hold only "+
					"letters, digits and underscore, and may not begin with a digit",
				string(rune(c))))
		}
	}
	return nil
}

// validate completes the checks that need the surrounding target.
//
// Decoding already established that at most one source is named and that the
// name is well formed. What is left is the case decoding cannot see: a
// `password:` key whose value was written and empty.
func (r Reference) validate() *Error {
	if r.present && r.kind == SourceNone {
		return newError(CategoryCredentialReference,
			"names no source; it must name exactly one of \"env\" or \"file\"").onLine(r.line)
	}
	if r.kind == SourceFile && r.name == "" {
		return newError(CategoryCredentialReference,
			"names an empty file path").onLine(r.line)
	}
	return nil
}

// Credentials is a target's identity and its optional credential reference.
type Credentials struct {
	// Username is the identity presented to the endpoint. It is
	// identity-classed and not secret-classed: security.Credential's own String
	// includes it and masks only the secret, and ADR 0037 added AttrKindIdentity
	// so an identity can be pseudonymized under redaction rather than withheld.
	//
	// So it is an ordinary configuration scalar, it may not be sourced from the
	// environment or a file, and there is no `username: {env: ...}` form. A
	// username is not a secret, and giving it a secret's indirection would
	// suggest it is.
	Username string

	// Password names where the credential lives. It may be zero, which means the
	// target carries no credential and is a supported run.
	Password Reference
}

// credentialsFields is the decoded form of a credentials mapping.
type credentialsFields struct {
	Username string    `yaml:"username"`
	Password Reference `yaml:"password"`
}

// UnmarshalYAML decodes the credentials block.
//
// # Why this has an unmarshaler at all
//
// One case, and it is the case a decoder cannot express. Phase 9.1A measured that
// go.yaml.in/yaml/v3 **skips a field's UnmarshalYAML entirely when the value is
// null**, in both pointer and value form — so
//
//	password:
//
// written and left empty is indistinguishable, at the type level, from omitting
// the key. Absent means "this target carries no credential" and is valid; a
// written-and-empty key is an unfinished reference, or a templating step that
// produced nothing, and treating it as "no credential configured" would tell the
// operator they did not configure a credential when they wrote the key.
//
// So the mapping's own pairs are inspected here for that one shape. This is the
// rule ADR 0072 section 2 states for `password: {}` — *"a reference that names
// nothing"* — reaching the syntactically equivalent form the type system cannot
// see. It narrows nothing and widens nothing.
func (c *Credentials) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.MappingNode {
		return newError(CategoryInvalidField, fmt.Sprintf(
			"must be a mapping with \"username\" and an optional \"password\", and %s was "+
				"written instead", describeKind(value))).onLine(value.Line)
	}

	for i := 0; i+1 < len(value.Content); i += 2 {
		key, val := value.Content[i], value.Content[i+1]
		if key.Value == "password" && val.Tag == "!!null" {
			return newError(CategoryCredentialReference,
				"names no source; it must name exactly one of \"env\" or \"file\", or be "+
					"omitted entirely if this target carries no credential").
				at("credentials.password").onLine(val.Line)
		}
	}

	var fields credentialsFields
	if err := strictDecodeNode(value, &fields); err != nil {
		return err
	}
	c.Username = fields.Username
	c.Password = fields.Password
	return nil
}

// validate checks the credentials block.
func (c Credentials) validate() *Error {
	if err := c.Password.validate(); err != nil {
		return err
	}
	return nil
}
