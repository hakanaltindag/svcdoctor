package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	yaml "go.yaml.in/yaml/v3"
)

// MaxBytes bounds a configuration file.
//
// ADR 0071 section 8 derives it: MaxTargets multiplied by a generous 2 KiB for a
// fully-specified, commented target block. It equals internal/cli's
// maxCAFileSize, which is a consistency worth having rather than a coincidence
// worth hiding — both answer "how much of a file an operator pointed at will
// svcdoctor read before deciding they pointed at the wrong one".
const MaxBytes = 1 << 20

// MaxTargets bounds how many targets one configuration may declare.
//
// ADR 0073 section 11.3 derives it from measurement rather than from taste: a
// target report was measured at 2.4 KB for one path and about 1.05 KB per
// additional TLS path, the worst realistic shape (a Kafka run sweeping its
// advertised brokers) reaches roughly 55 KB, that rounds to a 64 KiB per-target
// ceiling, and a 32 MiB budget for accumulated reports divides to 512.
//
// It is a resource ceiling and not a product limit: at about 20 lines per target
// it is a 10,000-line configuration, which no hand-maintained file approaches.
const MaxTargets = 512

// Version is the only configuration version this build understands.
//
// It is **not** domain.SchemaVersion and must never be derived from it. ADR 0071
// section 4.2: this number describes what an operator writes, that one describes
// what svcdoctor emits, and coupling them would tell operators their files were
// obsolete when nothing they wrote had changed.
const Version = 1

// allowedTags is the closed set of YAML tags this configuration accepts.
//
// An allow-list rather than a deny-list, because a deny-list has to be extended
// every time the library learns a tag, and the failure mode of forgetting is
// acceptance. Fail closed (ADR 0071 section 8.2).
//
// The empty string is a document node's own tag and is not a tag an operator can
// write. `!!merge` is absent and that absence is load-bearing: Phase 9.0 measured
// that a merge key decodes silently even with unknown-field rejection enabled and
// without any alias, so refusing anchors and aliases does **not** refuse merges.
// It is refused here, by name, as its own tag.
var allowedTags = map[string]bool{
	"":       true,
	"!!str":  true,
	"!!int":  true,
	"!!bool": true,
	"!!null": true,
	"!!map":  true,
	"!!seq":  true,
}

// readSource returns the configuration bytes at path.
//
// # The order of checks is the order of blast radius
//
// Type, then size, then contents. A directory is named as a directory before
// anything tries to read it, and an oversized file is refused from its metadata
// rather than after a megabyte of it is already resident. The bounded read that
// follows is belt and braces: a file can grow between the stat and the read, and
// that race must not become an unbounded allocation.
//
// # Symlinks are followed, and the destination must be regular
//
// ADR 0071 section 8.1. A Kubernetes projected ConfigMap is a symlink farm
// through `..data/`, so a configuration mounted the way ADR 0062 documents is
// always reached through one — refusing symlinks would refuse the documented
// deployment. What must be true is that the thing at the end is a regular file,
// so a FIFO cannot make `--config` block forever and a device cannot make it
// read something that is not a configuration.
func readSource(path string) ([]byte, error) {
	// os.Stat follows symlinks, so this describes the destination.
	info, err := os.Stat(path)
	if err != nil {
		return nil, newError(CategorySource,
			fmt.Sprintf("cannot be read: %s", statReason(err))).from(path)
	}
	if info.IsDir() {
		return nil, newError(CategorySource, "is a directory, not a configuration file").from(path)
	}
	if !info.Mode().IsRegular() {
		return nil, newError(CategorySource, fmt.Sprintf(
			"is not a regular file (mode %s); a configuration must be a regular file",
			info.Mode().Type())).from(path)
	}
	if info.Size() > MaxBytes {
		return nil, newError(CategorySource, fmt.Sprintf(
			"is larger than the %d byte maximum", MaxBytes)).from(path)
	}

	file, err := os.Open(path) //nolint:gosec // G304: the path is the operator's own input, checked above.
	if err != nil {
		return nil, newError(CategorySource,
			fmt.Sprintf("cannot be read: %s", statReason(err))).from(path)
	}
	defer func() { _ = file.Close() }()

	// One byte past the bound, so "exactly at the maximum" and "over it" are
	// distinguishable — the same rule internal/security/secretinput applies to
	// credential material, for the same reason.
	data, err := io.ReadAll(io.LimitReader(file, MaxBytes+1))
	if err != nil {
		// The error describes the read and never the bytes.
		return nil, newError(CategorySource, "cannot be read: unreadable").from(path)
	}
	if len(data) > MaxBytes {
		return nil, newError(CategorySource, fmt.Sprintf(
			"is larger than the %d byte maximum", MaxBytes)).from(path)
	}
	return data, nil
}

// statReason reduces a filesystem error to its cause, naming nothing else.
func statReason(err error) string {
	switch {
	case errors.Is(err, os.ErrNotExist):
		return "no such file"
	case errors.Is(err, os.ErrPermission):
		return "permission denied"
	default:
		return "unreadable"
	}
}

// parseDocument produces the node tree and proves there is exactly one document.
//
// # Why the node pass exists at all, given that a strict decode follows
//
// Three of this package's refusals cannot be expressed as a Go type: an anchor,
// an alias and a tag are properties of the *syntax*, invisible to a decoder that
// only sees the values they produce. Phase 9.0 measured that an aliased target
// decodes into two identical targets with no error at all. So the tree is walked
// before anything is decoded from it.
//
// # Why duplicate keys are not caught here
//
// They are caught by the strict decode, and Phase 9.1A measured that: decoding
// into a yaml.Node builds the tree without duplicate detection, while decoding
// into a typed struct reports `mapping key "x" already defined at line N`. The
// refusal is real either way; this comment exists so that a later reader does
// not add a second, weaker duplicate check here believing the first one is
// missing.
func parseDocument(data []byte) (*yaml.Node, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))

	var doc yaml.Node
	if err := decoder.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, newError(CategorySyntax,
				"the configuration is empty; it must hold one YAML document")
		}
		return nil, newError(CategorySyntax, sanitizeYAML(err))
	}

	// ADR 0071 section 8: exactly one document. A second one is a second run
	// nobody asked for, and silently using the first would mean the file does
	// not describe what svcdoctor did.
	//
	// A trailing `---` counts, measured: it opens a second document even with
	// nothing after it. A trailing comment without a marker does not.
	var extra yaml.Node
	switch err := decoder.Decode(&extra); {
	case errors.Is(err, io.EOF):
		// Exactly one. The ordinary path.
	case err != nil:
		return nil, newError(CategorySyntax, sanitizeYAML(err))
	default:
		return nil, newError(CategorySyntax, fmt.Sprintf(
			"holds more than one YAML document; the second begins at line %d, "+
				"and a configuration must hold exactly one", extra.Line))
	}

	return &doc, nil
}

// checkStructure refuses the YAML constructs ADR 0071 section 8.2 does not allow.
//
// It walks nodes and reads Anchor, Kind and Tag — never the raw text. A scalar
// whose *value* contains "&name" or "<<" is ordinary data and is not matched,
// which is why this is a tree walk and not a search for a byte sequence.
func checkStructure(node *yaml.Node) error {
	if node == nil {
		return nil
	}

	if node.Anchor != "" {
		return newError(CategoryStructure, fmt.Sprintf(
			"defines the YAML anchor %q; anchors and aliases are not accepted, because an "+
				"alias writes one target's bytes in two places and a reader cannot see what a "+
				"target says without expanding it", node.Anchor)).onLine(node.Line)
	}
	if node.Kind == yaml.AliasNode {
		return newError(CategoryStructure, fmt.Sprintf(
			"uses the YAML alias %q; anchors and aliases are not accepted", node.Value)).
			onLine(node.Line)
	}
	// `!!merge` is refused by the allow-list below as well, because it is not in
	// it. This branch exists for the message rather than for the refusal: an
	// operator who wrote `<<:` is told they wrote a merge key, not that they used
	// an unaccepted tag whose name they never typed.
	//
	// Phase 9.1A's mutation A03 established the redundancy by measurement —
	// removing this branch alone changed no outcome — and it is kept deliberately.
	// The refusal that must not be removed is `!!merge`'s absence from
	// allowedTags.
	if node.Tag == "!!merge" {
		return newError(CategoryStructure,
			"uses a YAML merge key (<<); merge keys are not accepted").onLine(node.Line)
	}
	if !allowedTags[node.Tag] {
		return newError(CategoryStructure, fmt.Sprintf(
			"uses the YAML tag %s, which is not one of the accepted tags "+
				"(!!str, !!int, !!bool, !!null, !!map, !!seq)", node.Tag)).onLine(node.Line)
	}

	for _, child := range node.Content {
		if err := checkStructure(child); err != nil {
			return err
		}
	}
	return nil
}

// versionProbe reads only the version, leniently.
//
// # Why a separate lax pass
//
// ADR 0071 section 4.3 requires that `version: 2` produces *"configuration
// version 2 is not supported"* rather than an avalanche of unknown-field errors
// about fields that version 2 legitimately defines. That ordering is only
// possible if the version is read before strictness is applied, which is what
// this is. Phase 9.0 measured that it works.
//
// The pointer distinguishes absent from zero. `version: 0` is a value the
// operator wrote and is refused as unsupported; a missing key is refused as
// missing, and the two get different messages because they have different fixes.
type versionProbe struct {
	Version *int `yaml:"version"`
}

// checkVersion enforces the frozen version contract.
func checkVersion(data []byte) error {
	var probe versionProbe
	// Deliberately not strict: this pass must succeed on a document whose other
	// fields belong to a version this build does not know.
	if err := yaml.Unmarshal(data, &probe); err != nil {
		// A duplicate key is a syntax defect wherever it is found, and this pass
		// finds one before the strict decode does. Reporting it as a version
		// defect would name the wrong problem — the version is fine, it was
		// written twice.
		detail := sanitizeYAML(err)
		if strings.Contains(detail, "already defined at line") {
			return newError(CategorySyntax, detail)
		}
		// A `version` key that is not an integer lands here.
		return newError(CategoryVersion, fmt.Sprintf(
			"the version must be the integer %d: %s", Version, detail))
	}

	switch {
	case probe.Version == nil:
		return newError(CategoryVersion, fmt.Sprintf(
			"no configuration version is declared; add \"version: %d\". It is required rather "+
				"than defaulted, so that a file cannot change meaning the day a second version "+
				"exists", Version))
	case *probe.Version != Version:
		return newError(CategoryVersion, fmt.Sprintf(
			"configuration version %d is not supported; this build supports version %d",
			*probe.Version, Version))
	}
	return nil
}

// strictDecode decodes the document with unknown fields refused.
//
// This is the pass that enforces the schema, and it is also the pass that
// reports duplicate mapping keys. Both refusals come from the decoder rather
// than from code here, which is why ADR 0071 section 3.1 counted them as free
// and why they hold at every nesting depth without this package walking
// anything.
func strictDecode(data []byte, into *document) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(into); err != nil {
		// A configuration error raised by a type's own UnmarshalYAML — a
		// credential reference refusing a plaintext scalar, a target identifier
		// refusing an uppercase letter — travels through the decoder and comes
		// back out here. It arrives already classified and already sanitized, so
		// it is returned as it is.
		//
		// Reclassifying it would collapse every one of those into
		// CategoryInvalidField, which is how the package's most specific
		// refusals would come to be reported as its most generic one.
		var configErr *Error
		if errors.As(err, &configErr) {
			return configErr
		}
		return classifyDecodeError(err)
	}
	return nil
}

// classifyDecodeError sorts a decoder failure into the closed vocabulary.
//
// The categories differ in what an operator does next — a typo'd key, a
// duplicated key and a value of the wrong type have three different fixes — so
// the classification is worth making even though the decoder reports all three
// the same way.
func classifyDecodeError(err error) error {
	// Sanitized first, unconditionally. Nothing below inspects the raw text, so
	// there is no path where an unsanitized string survives classification.
	detail := sanitizeYAML(err)
	line, detail := splitLinePrefix(detail)

	var category Category
	switch {
	case strings.Contains(detail, "not found in type"):
		category = CategoryUnknownField
	case strings.Contains(detail, "already defined at line"):
		category = CategorySyntax
	default:
		category = CategoryInvalidField
	}
	return newError(category, detail).onLine(line)
}

// splitLinePrefix lifts a leading "line N: " out of a decoder message.
//
// The decoder reports the position inside its own prose. Leaving it there would
// mean Error.Line() reads 0 on the very errors that have the best location
// information, so a consumer that wanted to point at a line — an editor
// integration, a future renderer — would have to parse the message back apart.
// It is lifted into the structured field and removed from the text, so it is
// stated once.
func splitLinePrefix(detail string) (int, string) {
	const prefix = "line "
	if !strings.HasPrefix(detail, prefix) {
		return 0, detail
	}
	rest := detail[len(prefix):]
	colon := strings.Index(rest, ": ")
	if colon <= 0 {
		return 0, detail
	}
	line, err := strconv.Atoi(rest[:colon])
	if err != nil || line <= 0 {
		return 0, detail
	}
	return line, rest[colon+2:]
}

// cleanPath normalizes a configuration path for messages.
//
// It is presentation only and never used to open anything: readSource opens the
// path the caller supplied, so a cleaned form cannot redirect a read.
func cleanPath(path string) string {
	if path == "" {
		return path
	}
	return filepath.Clean(path)
}
