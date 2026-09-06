// Package kubernetes turns one Kubernetes acquisition into evidence.
//
// It is the adapter half of the boundary: internal/adapter/kubernetes/client
// speaks to the API server and answers with svcdoctor's own values, and this
// package records those values as evidence nodes on a GraphBuilder. It imports
// **no k8s.io package at all**, which is what keeps the control-plane
// dependency behind exactly one door.
//
// # Five nodes, one subject, and no per-object cardinality
//
//	k8s.target  L0  ->  k8s.api_access  L5
//	                        ->  k8s.service  L6
//	                                ->  k8s.pod_set               L6
//	                                ->  k8s.endpoint_publication  L6
//
// **There is no per-Pod node and no per-endpoint node**, and that is a
// data-minimization decision rather than a simplification: no admitted finding
// consumes a single Pod field, so retaining one would be identity kept for a
// rendering nobody's diagnosis depends on. It is also what makes the report a
// single-path journey the existing terminal renderer already expresses, with no
// renderer change at all (ADR 0094 sections 11.2 and 12.3).
//
// # It produces evidence and never a finding
//
// Interpreting these nodes is Phase 12.1C's work. Nothing here computes a
// severity, names a cause, or writes a sentence about what an operator should
// do: a Service that does not exist becomes a FAIL node with
// RESOURCE_NOT_FOUND, and the claim *"no Service of this name exists"* is a
// finding a rule will make from it.
package kubernetes
