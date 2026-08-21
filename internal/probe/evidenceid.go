package probe

import (
	"strings"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// Separator joins the components of an evidence identifier.
//
// It is exported so that a reader of a report, and a test, can name the
// character without repeating a literal. Nothing parses an identifier: see
// EvidenceID.
const Separator = "/"

// EvidenceID builds the identifier of one evidence node from the step that
// produced it and the components that distinguish it.
//
//	EvidenceID("dns.lookup", "primary.internal")
//	    -> "dns.lookup/primary.internal"
//	EvidenceID("tcp.connect", "primary.internal:9092", "10.0.0.1")
//	    -> "tcp.connect/primary.internal:9092/10.0.0.1"
//
// The identifier is derived, never generated: the same step and the same
// components produce the same identifier on every run, with no clock, counter or
// random source involved. See ADR 0019.
//
// # Components, and why there can be several
//
// One component was enough for DNS, where a lookup is about a name and nothing
// else. TCP needs two, because one endpoint can have several addresses and each
// attempt is its own fact, and because two names can resolve to the same address
// without those being one attempt. The components are ordered from the widest
// scope to the narrowest, so identifiers for one endpoint sort together.
//
// # Escaping, and why input is never restricted
//
// Each component is escaped before joining: "%" becomes "%25" and the separator
// becomes "%2F". The mapping is injective, so distinct component lists always
// produce distinct identifiers — "a/b" and "a%2Fb" as components cannot collide,
// which is exactly what escaping "%" first buys.
//
// This exists so that a delimiter choice can never decide what svcdoctor is
// willing to diagnose. A probe must not reject input a layer would otherwise
// accept merely because a character is awkward in an identifier; the encoding
// absorbs it instead. An identifier is bookkeeping, and bookkeeping does not get
// to narrow the product.
//
// # Nothing decodes this
//
// There is deliberately no Decode. domain treats an identifier as opaque, and
// structural redaction replaces identifiers wholesale rather than parsing them
// (ADR 0018). Escaping is here to guarantee uniqueness, not to support a reader
// that does not exist. Adding one would create a parser whose correctness nobody
// depends on until the day it is wrong.
//
// The caller validates its own components. This function has no opinion about
// what a hostname or an endpoint looks like.
func EvidenceID(step domain.Step, components ...string) domain.EvidenceID {
	var b strings.Builder
	b.WriteString(escape(step.String()))
	for _, component := range components {
		b.WriteString(Separator)
		b.WriteString(escape(component))
	}
	return domain.EvidenceID(b.String())
}

// escape makes a component safe to join.
//
// "%" must be escaped first, and that ordering is the whole correctness argument:
// escaping only the separator would map the component "a%2Fb" onto the same text
// as "a/b", so two different subjects would silently share one identifier.
//
// The loop is byte-wise, which is safe because both escaped characters are ASCII
// and cannot appear inside a multi-byte UTF-8 sequence.
func escape(s string) string {
	if !strings.ContainsAny(s, "%"+Separator) {
		return s
	}

	var b strings.Builder
	b.Grow(len(s) + 8)
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '%':
			b.WriteString("%25")
		case '/':
			b.WriteString("%2F")
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
