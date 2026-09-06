// Package kubernetes holds the Kubernetes vocabulary that more than one layer
// needs.
//
// It is a leaf: it imports internal/domain and nothing else, it contains no
// behaviour, and it exists for one reason. Evidence produced by
// internal/adapter/kubernetes is read by internal/diagnosis/kubernetes and by
// internal/render/terminal, and depguard denies both the adapter import —
// correctly, because the Kubernetes adapter holds a control-plane client, a
// kubeconfig and a credential, and a rule that could reach it would stop being
// a pure function of a frozen graph.
//
// It is the exact counterpart of internal/service/kafka, internal/service/
// postgres, internal/service/redis and internal/service/rabbitmq, and was
// created on the same terms.
//
// # It is also the boundary that keeps client-go out of the rest of the tree
//
// ADR 0094 section 2.10 confines every k8s.io import to
// internal/adapter/kubernetes/client. That leaves diagnosis and the renderer
// needing to name Kubernetes steps and attributes without being able to reach
// the package that produces them, which is exactly the gap a vocabulary leaf
// fills. The constants here are plain strings over internal/domain types, so
// naming one costs no dependency at all.
//
// # What is here, and why each constant earned its place
//
// Five step names, because the frozen evidence shape (ADR 0094 section 2.9) has
// five nodes and a rule has to name the node it anchors at.
//
// Sixteen attribute keys, because ADR 0094 section 2.9 froze exactly sixteen
// normalized attributes and every one of them is read outside the adapter —
// eleven by the two rules Phase 12.1C adds, and the rest by the renderer.
// **The list is closed by that record**, not by taste: a seventeenth key needs
// the contract necessity argued, not merely a producer that has a value spare.
//
// # Closed value vocabularies, and why they are svcdoctor's own
//
// AuthMode and ServiceType hold values svcdoctor declares, matched from a closed
// set. Nothing here is a slice of a peer's bytes: a Service type arriving from
// the API server that svcdoctor does not recognize becomes ServiceTypeUnknown
// rather than a string of the peer's choosing, so a hostile or future value
// cannot reach a report and cannot make any claim stronger.
package kubernetes
