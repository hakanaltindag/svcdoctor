// Package client is svcdoctor's whole Kubernetes API surface.
//
// It is the **sole importer of every k8s.io library in the repository**, which
// is the same boundary the four protocol `wire` packages hold, for the same
// reason: a control-plane client is a large capability surface, and confining it
// to one package makes "no other layer can reach it" a property of the build
// rather than a rule someone follows. ADR 0094 section 2.10 froze that, and
// depguard plus TestOnlyTheKubernetesClientImportsClientGo enforce it from two
// directions.
//
// # What it does
//
//	validate the target                     -> no I/O at all
//	read and parse the kubeconfig           -> clientcmd.Load, which executes nothing
//	refuse every prohibited construct       -> before any client exists
//	resolve the credential                  -> one security.Reveal, at the end
//	issue exactly three bounded reads       -> GET Service, LIST Pods, LIST EndpointSlices
//	normalize into svcdoctor-owned values   -> no Kubernetes type leaves this package
//
// # What it does not do
//
// It creates no evidence, no finding and no report: it answers with a Result and
// internal/adapter/kubernetes turns that into evidence. It opens no watch,
// starts no informer, holds no cache, runs no reconciliation loop and starts no
// background goroutine — svcdoctor runs, reports and exits (ADR 0062 section 9).
// It performs no retry of any kind: a 429 or a 5xx ends the read and the set
// becomes incomplete, because retrying turns one bounded diagnosis into a small
// monitoring loop.
//
// # The refusal happens before the first request, and that ordering is the
// whole security argument
//
// Phase 12.1A measured where client-go invokes an `exec` credential plugin: not
// at clientcmd.Load, not at ClientConfig(), not at NewForConfig(), but on the
// **first API request** — the transport invokes it lazily. So a refusal issued
// before any request cannot be bypassed, and every dangerous field is visible as
// a typed value at parse time.
//
// This package goes one step further than the frozen requirement. It uses
// clientcmd **only to parse**, and builds the rest.Config by hand from the
// fields it validated. rest.Config.ExecProvider and rest.Config.AuthProvider are
// therefore never populated at all, on any path, so even a refusal that somehow
// failed to fire could not produce a configuration capable of executing
// anything. See buildRESTConfig.
//
// # One Reveal, at the last possible moment
//
// Exactly one production security.Reveal call site exists here, in
// applyCredential, reached by one function whichever of the three
// credential-bearing modes was selected. `forbidigo` fails the build on a second
// one, and this package is named in that rule's exclusion list — which is what
// makes the site deliberate rather than incidental.
//
// # Credential authority is the API server and nothing else
//
// A Kubernetes credential authorizes exactly one thing: the API server this
// target selected. It does not authorize a Pod IP, a ClusterIP, an EndpointSlice
// address, a Node IP, a discovered hostname, or any Kafka, PostgreSQL, Redis or
// RabbitMQ endpoint. That is structural rather than a rule to remember: the
// secret is held by a security.Credential bound to the API server's endpoint, so
// ADR 0028's existing binding check refuses it anywhere else, with no new
// mechanism (ADR 0094 section 6.8).
package client
