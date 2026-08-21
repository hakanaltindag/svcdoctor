package security

// Reveal returns the plaintext held by s.
//
// This is the only way to obtain a secret's plaintext, and it exists solely so
// that a protocol adapter can place the value on the wire during authentication.
//
// Rules for call sites:
//
//   - Call it as late as possible, immediately before the value is used.
//   - Never store the result in a struct field, a log line, an error, or any
//     value that can reach the evidence or report model.
//   - Obtain the Secret from Credential.SecretFor so that the endpoint binding
//     is checked first.
//
// It is a package level function rather than a method on Secret on purpose. A
// method would appear in editor completion on every Secret value and would read
// like an ordinary accessor. A package level call reads as a deliberate act and
// every use is greppable as "security.Reveal(", which keeps the escape hatch
// auditable in review.
func Reveal(s Secret) string {
	if s.v == nil {
		return ""
	}
	return s.v.plaintext
}
