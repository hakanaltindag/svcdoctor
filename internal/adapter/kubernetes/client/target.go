package client

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// ErrTarget reports a Kubernetes target svcdoctor refuses to diagnose.
//
// **It is a configuration error, not a finding.** Every refusal this package
// issues is raised before any network operation, and the caller maps it to the
// existing usage-error path — exit 2, the treatment ADR 0060 gave an
// inert-but-refused invocation. A refused construct never becomes evidence,
// because nothing was measured.
var ErrTarget = errors.New("kubernetes target")

// maxNameBytes bounds a namespace or Service name.
//
// It is the Kubernetes limit rather than a number chosen here: a namespace is a
// DNS-1123 label (63) and a Service name is a DNS-1035 label (63). Refusing a
// longer one costs an operator nothing — the API server would refuse it too —
// and it stops an unbounded operator string reaching an evidence subject.
const maxNameBytes = 63

// Target is one Kubernetes Service diagnosis's declared inputs.
//
// One target is exactly **one Kubernetes API authority + one explicit namespace
// + one explicit Service name** (ADR 0094 section 2.4). There is no selector
// target, no Pod or workload target, no namespace or cluster scan, no regexp, no
// wildcard, no list of Services and no all-namespaces mode — and each of those
// absences is a field that does not exist rather than a value that is rejected.
type Target struct {
	// Kubeconfig is an explicit path to exactly one kubeconfig file.
	//
	// **Explicit only.** KUBECONFIG is not consulted, ~/.kube/config is not a
	// fallback, and a merge list is not supported: a merge list makes one
	// configuration file mean different things on different machines, which is
	// the failure a `run --config` file exists to remove.
	//
	// Mutually exclusive with InCluster.
	Kubeconfig string

	// Context is the kubeconfig context to use. Mandatory with Kubeconfig,
	// forbidden with InCluster.
	//
	// **`current-context` is never used implicitly.** A defaulted context makes
	// one configuration mean different things depending on a machine-local
	// setting, and its failure mode — reading the wrong cluster and reporting
	// "not found" — is indistinguishable from a real finding. One extra field
	// removes an entire class of incident, and `kubectl config current-context`
	// tells an operator what to write.
	Context string

	// InCluster selects the projected ServiceAccount identity.
	//
	// **Explicit only, and never a fallback.** It is mutually exclusive with
	// Kubeconfig, and there is no implicit detection: a mounted ServiceAccount
	// token must never cause svcdoctor to acquire an identity nobody asked for.
	InCluster bool

	// Namespace is mandatory and explicit. Never taken from the context, never
	// defaulted to "default".
	Namespace string

	// ServiceName is the one Service this target is about. Mandatory.
	ServiceName string
}

// Validate checks the target's own shape. It performs no I/O.
//
// It answers only what is decidable from the declaration itself: the two
// authority modes are exclusive, one of them is chosen, and the three mandatory
// names are present and well formed. Whether the kubeconfig exists, parses or
// carries a refused construct is Inspect's question, because answering it needs
// the file.
//
// The order of the checks is fixed so that one malformed target always produces
// the same message.
func (t Target) Validate() error {
	switch {
	case t.InCluster && t.Kubeconfig != "":
		return fmt.Errorf("%w: in-cluster mode and a kubeconfig path are mutually exclusive; "+
			"a run authenticates as the pod's ServiceAccount or as a kubeconfig identity, "+
			"never as whichever of the two happens to resolve first", ErrTarget)
	case t.InCluster && t.Context != "":
		return fmt.Errorf("%w: a context names a kubeconfig entry and has no meaning "+
			"in-cluster", ErrTarget)
	case !t.InCluster && t.Kubeconfig == "":
		return fmt.Errorf("%w: a kubeconfig path or in-cluster mode is required; svcdoctor "+
			"consults no KUBECONFIG variable and no default kubeconfig location, so a target "+
			"that names neither has no API server to read", ErrTarget)
	case !t.InCluster && t.Context == "":
		return fmt.Errorf("%w: a kubeconfig context is required; the file's current-context is "+
			"never used, because a defaulted context makes one configuration read a different "+
			"cluster on a different machine", ErrTarget)
	}

	if err := checkName("namespace", t.Namespace); err != nil {
		return err
	}
	return checkName("service name", t.ServiceName)
}

// checkName validates a namespace or Service name as text.
//
// It is deliberately narrower than a full DNS-1123 or DNS-1035 check and says
// so: the API server owns those grammars and will answer for them. What is
// enforced here is what must hold before the value reaches an evidence subject,
// an identifier and a redaction table — non-empty, bounded, valid UTF-8, and
// free of control characters, whitespace and the separator the identifier
// encoding reserves.
//
// Refusing rather than escaping is the right direction for an operator-written
// name: a name svcdoctor mangled would produce a report about a Service the
// operator did not name.
func checkName(field, value string) error {
	switch {
	case value == "":
		return fmt.Errorf("%w: a %s is required and is never defaulted", ErrTarget, field)
	case len(value) > maxNameBytes:
		return fmt.Errorf("%w: the %s is %d bytes, above the %d byte Kubernetes limit",
			ErrTarget, field, len(value), maxNameBytes)
	case !utf8.ValidString(value):
		return fmt.Errorf("%w: the %s is not valid UTF-8", ErrTarget, field)
	}
	for _, r := range value {
		if r <= ' ' || r == 0x7f {
			return fmt.Errorf("%w: the %s contains a space or a control character",
				ErrTarget, field)
		}
	}
	if strings.ContainsAny(value, "/%") {
		return fmt.Errorf(
			"%w: the %s contains %q or %q, which no Kubernetes object name may hold",
			ErrTarget, field, "/", "%")
	}
	return nil
}

// SubjectRef is the evidence subject every node of a Kubernetes run shares.
//
//	service/<namespace>/<name>
//
// It is the Service object's own identity, at SubjectKindTarget — whose
// definition is *"the inspected target as a whole"*, which the Service is. **No
// new SubjectKind is added and none is needed**, and the API server's host and
// port deliberately do not appear: that pair binds the credential and is not
// published as a canonical identifier (ADR 0094 section 2.4).
func (t Target) SubjectRef() string {
	return "service/" + t.Namespace + "/" + t.ServiceName
}
