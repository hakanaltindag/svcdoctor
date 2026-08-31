package config

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrConfig marks every failure this package produces.
//
// It exists so that a caller can tell a configuration defect from a programming
// error with errors.Is, without importing this package's concrete type. The CLI
// will map it to exit 2 in Phase 9.1B.
//
// # It is deliberately not a domain.FailureClass and not a domain.FindingCode
//
// ADR 0073 section 12: a finding is a diagnostic conclusion about a target, drawn
// from evidence, carrying a severity and the evidence identifiers that produced
// it. A malformed configuration file has no evidence, no target-side subject and
// no vantage — nothing was measured, because nothing was dialled. Reusing a
// service vocabulary here would turn a defect in what the operator wrote into a
// claim about a service.
//
// So the finding-code count stays at 60 and the failure-class count stays at 42.
var ErrConfig = errors.New("configuration error")

// Category is the closed vocabulary of configuration failures.
//
// It is small on purpose. Each member names something an operator does
// differently in response, and nothing here distinguishes two defects that have
// the same fix.
//
// The zero Category is CategoryUnspecified and is not a category.
type Category uint8

const (
	// CategoryUnspecified is the zero value and is not a category.
	CategoryUnspecified Category = iota

	// CategorySource means the configuration file itself could not be used: it
	// was absent, unreadable, not a regular file, or larger than the bound.
	// Nothing was parsed.
	CategorySource

	// CategorySyntax means the bytes are not one well-formed YAML document.
	// Duplicate mapping keys and a second document are both syntax defects.
	CategorySyntax

	// CategoryStructure means the document is well-formed YAML that uses a
	// construct this configuration refuses: an anchor, an alias, a merge key or
	// a tag outside the allow-list.
	CategoryStructure

	// CategoryVersion means the configuration version is missing or unsupported.
	CategoryVersion

	// CategoryUnknownField means a field name is not part of the schema. It is
	// separate from CategoryInvalidField because the fix is different: one is a
	// typo or a field from another version, the other is a value out of range.
	CategoryUnknownField

	// CategoryInvalidField means a field is present, understood, and carries a
	// value the schema does not allow.
	CategoryInvalidField

	// CategoryDuplicateID means two targets claim the same identifier.
	CategoryDuplicateID

	// CategoryUnsupportedService means no service is registered under a target's
	// type.
	CategoryUnsupportedService

	// CategoryCredentialReference means a credential reference does not name
	// exactly one source, or names one malformed.
	CategoryCredentialReference
)

// categoryNames is indexed by Category. Keep it aligned with the const block
// above; TestCategoryNamesCoverEveryValue fails if the two drift.
//
// trips the heuristic, CREDENTIAL_REFERENCE_INVALID, is the classification for a
// malformed *reference* — this package cannot hold a credential at all, because
// it does not import internal/security (ADR 0072 §6).
//
//nolint:gosec // G101: these are the names of error categories. The one that
var categoryNames = [...]string{
	CategoryUnspecified:         "UNSPECIFIED",
	CategorySource:              "CONFIG_SOURCE",
	CategorySyntax:              "CONFIG_SYNTAX",
	CategoryStructure:           "CONFIG_STRUCTURE",
	CategoryVersion:             "CONFIG_VERSION",
	CategoryUnknownField:        "CONFIG_UNKNOWN_FIELD",
	CategoryInvalidField:        "CONFIG_INVALID_FIELD",
	CategoryDuplicateID:         "CONFIG_DUPLICATE_ID",
	CategoryUnsupportedService:  "CONFIG_UNSUPPORTED_SERVICE",
	CategoryCredentialReference: "CREDENTIAL_REFERENCE_INVALID",
}

// Valid reports whether c is a defined category.
func (c Category) Valid() bool {
	return c != CategoryUnspecified && int(c) < len(categoryNames)
}

// String returns the symbolic name, or a Go-convention rendering of an
// out-of-range value. It never fails.
func (c Category) String() string {
	if int(c) >= len(categoryNames) {
		return "Category(" + strconv.FormatUint(uint64(c), 10) + ")"
	}
	return categoryNames[c]
}

// Error is one configuration defect, located and categorized.
//
// # What it may carry
//
// A category, the source name, a field path, a target identifier and a line
// number. Every one of those is either svcdoctor's own vocabulary or something
// the operator wrote as a *name* — a key, an identifier, a path component.
//
// # What it may never carry
//
// A secret value, the contents of a credential file, the value of an environment
// variable, or any span of the raw configuration. The last is the one that needs
// a mechanism rather than a promise: the YAML decoder formats offending scalars
// into its own error strings, so `password: hunter2` produces a library error
// containing `hunter2`. sanitizeYAML strips that before any text reaches this
// type, and TestNoSecretValueReachesAConfigError proves it.
type Error struct {
	category Category
	// source names where the configuration came from — a file path. It is the
	// operator's own path and appears for the same reason ADR 0049 section 3
	// puts --password-file's path in errors: a file svcdoctor cannot use has to
	// be nameable or nobody can fix it.
	source string
	// path is the field path within the document, such as
	// "targets[3].credentials.password". Empty when the defect is the document
	// itself.
	path string
	// targetID is the identifier of the target the defect is in, when one has
	// been read. Empty otherwise — a defect can precede the identifier.
	targetID string
	// line is the 1-based line the decoder reported, or 0 when unknown. It is a
	// position and never content.
	line int
	// detail is a sanitized explanation.
	detail string
}

// newError builds a configuration error.
func newError(category Category, detail string) *Error {
	return &Error{category: category, detail: detail}
}

// at records the field path.
func (e *Error) at(path string) *Error { e.path = path; return e }

// inTarget records which target the defect belongs to.
func (e *Error) inTarget(id string) *Error { e.targetID = id; return e }

// onLine records the 1-based line, ignoring a non-positive one.
func (e *Error) onLine(line int) *Error {
	if line > 0 {
		e.line = line
	}
	return e
}

// from records the configuration source.
func (e *Error) from(source string) *Error { e.source = source; return e }

// Category returns the closed classification.
func (e *Error) Category() Category { return e.category }

// Path returns the field path, which may be empty.
func (e *Error) Path() string { return e.path }

// TargetID returns the target identifier, which may be empty.
func (e *Error) TargetID() string { return e.targetID }

// Line returns the 1-based line, or 0 when unknown.
func (e *Error) Line() int { return e.line }

// Error composes the operator-facing message.
//
// The order is outside-in — source, then target, then field path, then line,
// then the reason — because that is the order someone reads a file in when
// looking for the thing to change.
func (e *Error) Error() string {
	var b strings.Builder
	if e.source != "" {
		b.WriteString(e.source)
		b.WriteString(": ")
	}
	switch {
	case e.targetID != "" && e.path != "":
		fmt.Fprintf(&b, "%s (target %q): ", e.path, e.targetID)
	case e.targetID != "":
		fmt.Fprintf(&b, "target %q: ", e.targetID)
	case e.path != "":
		b.WriteString(e.path)
		b.WriteString(": ")
	}
	if e.line > 0 {
		fmt.Fprintf(&b, "line %d: ", e.line)
	}
	b.WriteString(e.detail)
	return b.String()
}

// Unwrap reports ErrConfig so that errors.Is identifies any configuration defect
// without naming this type.
func (e *Error) Unwrap() error { return ErrConfig }

// GoString keeps %#v from printing the struct field by field.
//
// The fields are individually safe, but a Go-syntax dump of a config-adjacent
// type is exactly the habit that later prints something that is not. Rendering
// the category and the message is everything a debugger needs.
func (e *Error) GoString() string {
	return fmt.Sprintf("config.Error{category: %s, message: %q}", e.category, e.Error())
}

// InvalidField builds a configuration error for a service's own validation.
//
// # Why service packages get a constructor rather than the error type
//
// A service must be able to refuse its own configuration in the same vocabulary
// as the generic core, or its refusals would arrive as a different kind of error
// and the CLI would have to learn two mappings. But it must **not** be able to
// mint any category it likes: a service inventing CategorySyntax would claim the
// document was malformed when its own field was.
//
// So exactly one category is reachable from outside this package —
// CategoryInvalidField, which is what a service validating a value is always
// producing — and the path and detail are the service's own words.
//
// The caller supplies a path relative to the target, such as "config.vhost" or
// "credentials.username"; the loop that knows the index prefixes it.
func InvalidField(path, detail string) error {
	return newError(CategoryInvalidField, detail).at(path)
}
