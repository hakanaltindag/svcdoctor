package config

import (
	"bytes"
	"errors"

	yaml "go.yaml.in/yaml/v3"
)

// strictDecodeNode decodes one already-parsed subtree with unknown fields refused.
//
// # Why a re-encode rather than node.Decode
//
// Phase 9.1A measured that yaml.Node.Decode ignores the decoder's KnownFields
// setting: an unknown field inside a captured subtree decoded cleanly. That is
// not acceptable for a schema whose whole posture is fail-closed, so the subtree
// is serialized and fed through a decoder that has strictness switched on.
//
// The cost is that positions inside the fragment restart at line 1, which is why
// every caller attaches the original node's line before returning. The
// alternative — accepting silent unknown fields inside every service's
// configuration and inside every credential reference — is not a trade.
//
// # Why re-encoding is safe here
//
// checkStructure has already run over the whole document, so no anchor, alias,
// merge key or non-core tag survives to be re-encoded. The fragment this
// serializes is plain data.
func strictDecodeNode(node *yaml.Node, into any) error {
	if node == nil {
		return nil
	}

	raw, err := yaml.Marshal(node)
	if err != nil {
		return newError(CategoryInvalidField, sanitizeYAML(err)).onLine(node.Line)
	}

	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)
	if err := decoder.Decode(into); err != nil {
		// A configuration error raised by a nested UnmarshalYAML travels through
		// the decoder and comes back out here. It is already classified and
		// already sanitized, so it is returned as it is rather than being
		// reclassified as a generic decode failure.
		var configErr *Error
		if errors.As(err, &configErr) {
			return configErr
		}
		return withLine(classifyDecodeError(err), node.Line)
	}
	return nil
}

// withLine attaches a line to a configuration error that does not have one.
//
// A fragment's own line numbers are meaningless after a re-encode, so the
// original node's position is the only true one available.
func withLine(err error, line int) error {
	var configErr *Error
	if errors.As(err, &configErr) {
		return configErr.onLine(line)
	}
	return err
}

// sanitizeConfigErr renders a nested error's text without re-wrapping it.
//
// A *Error already holds a sanitized detail; anything else came from the YAML
// library and is sanitized on the way through. Either way no raw decoder text
// escapes.
func sanitizeConfigErr(err error) string {
	var configErr *Error
	if errors.As(err, &configErr) {
		return configErr.detail
	}
	return sanitizeYAML(err)
}

// ServiceNode is a target's service configuration, captured and not yet decoded.
//
// # It is why the YAML dependency stays in one package
//
// ADR 0071 section 3.3 confines go.yaml.in/yaml/v3 to this package, and ADR 0071
// section 6.3 requires that a service owns the decoding of its own
// configuration. Those two would contradict each other if a service decoder took
// a *yaml.Node, because taking one means importing the library.
//
// This type resolves that: the generic core holds the subtree opaquely, and a
// service calls Decode on it with its own concrete struct. A service package
// imports this package and never the YAML library, so adding a fifth service
// adds no importer of the dependency.
//
// # It is not map[string]any, and that is a security property rather than taste
//
// Phase 9.0 measured that decoding YAML into `any` re-enables implicit typing —
// the class of defect where `id: no` becomes the boolean false and a version
// string becomes a float. Decoding into a typed struct does not. The core
// therefore never holds a generic map, and the whole class is absent rather than
// defended against.
type ServiceNode struct {
	node *yaml.Node
}

// UnmarshalYAML captures the subtree without interpreting it.
//
// Capturing is required rather than convenient: a *yaml.Node field cannot be
// used directly under KnownFields(true), because the decoder tries to match the
// subtree's keys against yaml.Node's own struct fields and refuses every one of
// them. Phase 9.1A measured that before this type existed.
func (s *ServiceNode) UnmarshalYAML(value *yaml.Node) error {
	s.node = value
	return nil
}

// Decode decodes the captured subtree into a service's own type, with unknown
// fields refused.
//
// An absent `config:` block decodes to nothing and is not an error here: whether
// a service *requires* configuration is that service's own validation, and it
// gets to say so in its own words.
func (s *ServiceNode) Decode(into any) error {
	if s == nil || s.node == nil {
		return nil
	}
	return strictDecodeNode(s.node, into)
}

// Line returns where the service configuration was written, or 0 when absent.
func (s *ServiceNode) Line() int {
	if s == nil || s.node == nil {
		return 0
	}
	return s.node.Line
}

// IsZero reports whether no service configuration was written.
func (s *ServiceNode) IsZero() bool { return s == nil || s.node == nil }
