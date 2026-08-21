package security

import (
	"fmt"
	"io"
	"strconv"
)

// mask is the fixed representation emitted by every Secret output path.
// It is deliberately constant: it carries no length, no hash, and no prefix of
// the plaintext, so no output path can reveal anything about the value.
const mask = "***"

// Secret holds a credential value that must never reach output.
//
// The zero Secret is valid and empty. Secret is a concrete value type, safe to
// copy and safe to pass to fmt, encoding/json, and error wrapping. Obtaining
// the plaintext requires calling Reveal.
//
// Do not compare Secrets with ==. Equality is pointer identity, not value
// equality, and comparing secrets is not a meaningful operation here.
type Secret struct {
	// v holds the plaintext behind a pointer, which is load-bearing for
	// leak safety rather than an allocation choice.
	//
	// fmt handles %p and %T before it consults Formatter, Stringer, or
	// GoStringer, and returns early, so those verbs never reach Secret.Format.
	// For a non-pointer operand, %p then falls into fmt's badVerb path, which
	// sets an internal erroring flag; while that flag is set fmt skips all
	// method handling and prints the operand by reflection, and its reflection
	// walk can read unexported fields. A string field would be printed
	// verbatim, and a []byte field would be printed as recoverable byte values.
	//
	// fmt's reflection walk prints a pointer encountered below the top level as
	// an address instead of following it, so the indirection keeps the
	// plaintext out of that path. See TestSecretDoesNotLeakThroughReflection.
	v *secretValue
}

// secretValue is the heap-held plaintext. It is a distinct unexported type so
// that the field above is a pointer rather than an inline struct.
type secretValue struct {
	plaintext string
}

// NewSecret wraps plaintext in a Secret.
//
// An empty plaintext produces the zero Secret, so NewSecret("") and a
// declared-but-unset Secret behave identically.
func NewSecret(plaintext string) Secret {
	if plaintext == "" {
		return Secret{}
	}
	return Secret{v: &secretValue{plaintext: plaintext}}
}

// IsEmpty reports whether the Secret holds no value.
//
// This allows configuration validation, for example rejecting a SASL mechanism
// that was selected without a password, without revealing the value.
func (s Secret) IsEmpty() bool {
	return s.v == nil || s.v.plaintext == ""
}

// String implements fmt.Stringer and always returns the mask.
func (s Secret) String() string {
	return mask
}

// GoString implements fmt.GoStringer so that %#v cannot reveal the plaintext.
func (s Secret) GoString() string {
	return "security.Secret{/* redacted */}"
}

// Format implements fmt.Formatter.
//
// fmt gives Formatter precedence over Stringer and GoStringer, so implementing
// it here closes every verb at once, including verbs a Stringer would not
// otherwise intercept such as %x, %d, and %q. Unknown verbs deliberately return
// the mask rather than a fmt error string, because a fmt error string can embed
// the operand.
func (s Secret) Format(f fmt.State, verb rune) {
	switch {
	case verb == 'v' && f.Flag('#'):
		_, _ = io.WriteString(f, s.GoString())
	case verb == 'q':
		_, _ = io.WriteString(f, strconv.Quote(mask))
	default:
		_, _ = io.WriteString(f, mask)
	}
}

// MarshalJSON implements json.Marshaler and always emits the mask.
//
// There is deliberately no UnmarshalJSON: a report must never be able to
// round-trip a masked value back into a usable Secret.
func (s Secret) MarshalJSON() ([]byte, error) {
	return []byte(strconv.Quote(mask)), nil
}

// MarshalText implements encoding.TextMarshaler and always emits the mask.
//
// This covers encoders that prefer TextMarshaler, and map keys in encoding/json.
func (s Secret) MarshalText() ([]byte, error) {
	return []byte(mask), nil
}
