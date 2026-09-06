package client

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// TestTheTargetShapeIsExactlyWhatWasFrozen.
//
// One API authority, one explicit namespace, one explicit Service. The two modes
// are exclusive, one of them is mandatory, and nothing is ever defaulted: not the
// kubeconfig location, not the context, not the namespace.
func TestTheTargetShapeIsExactlyWhatWasFrozen(t *testing.T) {
	valid := Target{
		Kubeconfig: "/etc/svcdoctor/kubeconfig", Context: "prod",
		Namespace: "payments", ServiceName: "payments-api",
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("a complete kubeconfig target was refused: %v", err)
	}
	inCluster := Target{InCluster: true, Namespace: "payments", ServiceName: "payments-api"}
	if err := inCluster.Validate(); err != nil {
		t.Fatalf("a complete in-cluster target was refused: %v", err)
	}

	tests := []struct {
		name   string
		target Target
		names  string
	}{
		{
			name:   "both authorities",
			target: Target{InCluster: true, Kubeconfig: "/k", Namespace: "n", ServiceName: "s"},
			names:  "mutually exclusive",
		},
		{
			name: "a context in-cluster",
			target: Target{
				InCluster: true, Context: "prod", Namespace: "n", ServiceName: "s",
			},
			names: "no meaning in-cluster",
		},
		{
			name:   "neither authority",
			target: Target{Namespace: "n", ServiceName: "s"},
			names:  "kubeconfig path or in-cluster mode is required",
		},
		{
			name:   "no context",
			target: Target{Kubeconfig: "/k", Namespace: "n", ServiceName: "s"},
			names:  "context is required",
		},
		{
			name:   "no namespace",
			target: Target{Kubeconfig: "/k", Context: "c", ServiceName: "s"},
			names:  "a namespace is required",
		},
		{
			name:   "no service name",
			target: Target{Kubeconfig: "/k", Context: "c", Namespace: "n"},
			names:  "a service name is required",
		},
		{
			name: "a namespace above the Kubernetes limit",
			target: Target{
				Kubeconfig: "/k", Context: "c",
				Namespace: strings.Repeat("n", maxNameBytes+1), ServiceName: "s",
			},
			names: "above the 63 byte Kubernetes limit",
		},
		{
			name: "a name carrying a control character",
			target: Target{
				Kubeconfig: "/k", Context: "c", Namespace: "pay\x00ments", ServiceName: "s",
			},
			names: "space or a control character",
		},
		{
			name: "a name carrying ANSI",
			target: Target{
				Kubeconfig: "/k", Context: "c", Namespace: "\x1b[31mred", ServiceName: "s",
			},
			names: "space or a control character",
		},
		{
			name: "a name carrying CRLF",
			target: Target{
				Kubeconfig: "/k", Context: "c", Namespace: "a\r\nb", ServiceName: "s",
			},
			names: "space or a control character",
		},
		{
			name: "a name carrying the identifier separator",
			target: Target{
				Kubeconfig: "/k", Context: "c", Namespace: "a/b", ServiceName: "s",
			},
			names: "which no Kubernetes object name may hold",
		},
		{
			name: "a name that is not valid UTF-8",
			target: Target{
				Kubeconfig: "/k", Context: "c", Namespace: "\xff\xfe", ServiceName: "s",
			},
			names: "not valid UTF-8",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.target.Validate()
			if err == nil {
				t.Fatal("the target was accepted")
			}
			if !errors.Is(err, ErrTarget) {
				t.Errorf("error is %v, want an ErrTarget refusal", err)
			}
			if !strings.Contains(err.Error(), test.names) {
				t.Errorf("the refusal reads %q, want it to mention %q", err, test.names)
			}
		})
	}
}

// TestTheSubjectIsTheServiceObjectAndNotTheAPIServer.
//
// The evidence subject is the Service's own identity. The API server's host and
// port bind the credential and are deliberately not published as the run's
// identity, so a report cannot be used to enumerate control planes.
func TestTheSubjectIsTheServiceObjectAndNotTheAPIServer(t *testing.T) {
	target := Target{
		Kubeconfig: "/etc/kubeconfig", Context: "prod",
		Namespace: "payments", ServiceName: "payments-api",
	}
	if got, want := target.SubjectRef(), "service/payments/payments-api"; got != want {
		t.Errorf("subject is %q, want %q", got, want)
	}
	for _, leaked := range []string{"/etc/kubeconfig", "prod", "443", "https"} {
		if strings.Contains(target.SubjectRef(), leaked) {
			t.Errorf("the subject carries %q", leaked)
		}
	}
}

// TestAKubeconfigThatIsNotAKubeconfigIsRefusedWithoutQuotingIt.
//
// A parse error's useful content is *that it did not parse*. The rest is
// operator-supplied text on its way to a terminal and possibly a shared report,
// and the library's own message can quote the document.
func TestAKubeconfigThatIsNotAKubeconfigIsRefusedWithoutQuotingIt(t *testing.T) {
	// A credential-shaped string inside an unparseable document, so the assertion
	// below can show that the refusal does not quote what it refused.
	const secretish = "AKIAIOSFODNN7EXAMPLE" //nolint:gosec // a fixture literal, not a key
	path := writeFile(t, "not-a-kubeconfig", "this: [is not: valid ] yaml "+secretish+" :::\n")

	_, err := Inspect(Target{
		Kubeconfig: path, Context: "prod", Namespace: "n", ServiceName: "s",
	}, false)
	if err == nil {
		t.Fatal("an unparseable kubeconfig was accepted")
	}
	if strings.Contains(err.Error(), secretish) {
		t.Errorf("the refusal quotes the document:\n%v", err)
	}
	if !strings.Contains(err.Error(), "not a valid kubeconfig document") {
		t.Errorf("the refusal does not say what happened: %v", err)
	}
}

// TestAnUnknownContextIsRefusedAndNeverDefaulted.
//
// The file's own `current-context` is never consulted. A defaulted context makes
// one configuration read a different cluster on a different machine, and its
// failure mode — reading the wrong cluster and reporting "not found" — is
// indistinguishable from a real finding.
func TestAnUnknownContextIsRefusedAndNeverDefaulted(t *testing.T) {
	server := newAPIServer(t)
	path := kubeconfig{
		server: server.URL(), caPath: server.caPath,
		contextName: "staging", currentContext: "staging",
	}.write(t)

	target := targetFor(path) // asks for "prod"
	_, err := Inspect(target, false)
	if err == nil {
		t.Fatal("a target naming an absent context was accepted; current-context was used")
	}
	if !strings.Contains(err.Error(), "no context named") {
		t.Errorf("the refusal does not name the problem: %v", err)
	}
	if got := server.requestCount(); got != 0 {
		t.Errorf("the API server received %d requests, want 0", got)
	}
}

// TestOnlyTheSelectedContextIsEverReached.
//
// A kubeconfig legitimately holds several contexts, and one cluster's exec-based
// entry is no reason to refuse a run against a different cluster in the same
// file — refusing the whole document would make svcdoctor unusable on the
// machines it is most needed on.
//
// What makes the narrow scope safe is that the connection is assembled by hand
// from the selected context's fields, so no unselected context, user or cluster
// is reachable at all. This proves both halves: the clean context works, and the
// exec-bearing one in the same file is refused when it is the one selected.
func TestOnlyTheSelectedContextIsEverReached(t *testing.T) {
	server := newAPIServer(t)
	server.service = selectorService("uid-1")
	server.podPages = []scriptedPage{{}}
	server.slicePages = []scriptedPage{{}}

	document := "apiVersion: v1\n" +
		"kind: Config\n" +
		"clusters:\n" +
		"- name: good\n" +
		"  cluster:\n" +
		"    server: " + server.URL() + "\n" +
		"    certificate-authority: " + server.caPath + "\n" +
		"- name: exec-cluster\n" +
		"  cluster:\n" +
		"    server: https://exec.invalid\n" +
		"users:\n" +
		"- name: good-user\n" +
		"  user:\n" +
		"    token: fixture-token\n" +
		"- name: exec-user\n" +
		"  user:\n" +
		"    exec:\n" +
		"      apiVersion: client.authentication.k8s.io/v1\n" +
		"      command: /bin/false\n" +
		"contexts:\n" +
		"- name: prod\n" +
		"  context:\n" +
		"    cluster: good\n" +
		"    user: good-user\n" +
		"- name: exec-context\n" +
		"  context:\n" +
		"    cluster: exec-cluster\n" +
		"    user: exec-user\n" +
		"current-context: exec-context\n"
	path := writeFile(t, "multi-kubeconfig", document)

	// The clean context runs, even though the file's current-context is the
	// exec-based one.
	result, err := Acquire(context.Background(), Params{Target: Target{
		Kubeconfig: path, Context: "prod",
		Namespace: "payments", ServiceName: "payments-api",
	}})
	if err != nil {
		t.Fatalf("the clean context was refused because another context was dangerous: %v", err)
	}
	if !result.Service.OK() {
		t.Errorf("the Service read failed: %+v", result.Service)
	}

	// Selecting the exec context refuses it.
	if _, err := Inspect(Target{
		Kubeconfig: path, Context: "exec-context",
		Namespace: "payments", ServiceName: "payments-api",
	}, false); err == nil || !strings.Contains(err.Error(), "exec credential plugin") {
		t.Fatalf("the exec context was accepted: %v", err)
	}
}
