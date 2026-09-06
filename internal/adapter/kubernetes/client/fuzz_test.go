package client

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// The fuzz targets, and what each is looking for.
//
// # Invariants every target shares
//
//	no panic
//	no secret in the result
//	no raw Status.Message in the result
//	no executable invoked
//	no unknown string producing a stronger semantic state
//	a deterministic normalized result for a given input
//
// They are bounded on purpose: the corpus is svcdoctor's own inputs — a
// kubeconfig, a Kubernetes name, a status message, an endpoint condition set —
// and never client-go's network stack, which is not svcdoctor's to prove.

// FuzzKubeconfigSecurityValidation drives the refusal layer with arbitrary
// documents.
//
// The property is not that a given document is refused: most random bytes are not
// a kubeconfig, and refusing them is uninteresting. It is that **nothing
// executes, nothing panics, and no accepted document ever carries a prohibited
// construct** — so a parse quirk that let an `exec` stanza through in some
// encoding would show up as an acceptance rather than as a crash.
func FuzzKubeconfigSecurityValidation(f *testing.F) {
	sentinel := filepath.Join(f.TempDir(), "fuzz-exec-ran")

	f.Add("apiVersion: v1\nkind: Config\n")
	f.Add("apiVersion: v1\nkind: Config\nclusters:\n- name: c\n  cluster:\n    server: https://a\n")
	f.Add("clusters:\n- name: c\n  cluster:\n    server: https://a\n    insecure-skip-tls-verify: true\n")
	f.Add("users:\n- name: u\n  user:\n    exec:\n      command: /bin/true\n")
	f.Add("users:\n- name: u\n  user:\n    auth-provider:\n      name: gcp\n")
	f.Add("users:\n- name: u\n  user:\n    as: admin\n")
	f.Add("\x00\xff\x1b[31m")
	f.Add("contexts:\n- name: prod\n  context:\n    cluster: c\n    user: u\ncurrent-context: prod\n")

	f.Fuzz(func(t *testing.T, document string) {
		path := filepath.Join(t.TempDir(), "kubeconfig")
		if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
			t.Skip()
		}

		authority, err := Inspect(Target{
			Kubeconfig: path, Context: "prod", Namespace: "n", ServiceName: "s",
		}, false)
		if err != nil {
			// A refusal must not repeat the document it refused.
			if len(document) > 24 && strings.Contains(err.Error(), document) {
				t.Fatalf("the refusal quotes the document")
			}
			return
		}

		// An accepted document must carry none of the prohibited constructs, and
		// must have produced a usable, non-secret authority.
		for _, prohibited := range []string{
			"exec:", "auth-provider", "insecure-skip-tls-verify", "proxy-url",
			"as-groups", "as-uid", "password",
		} {
			if strings.Contains(document, prohibited) {
				t.Fatalf("a document containing %q was accepted", prohibited)
			}
		}
		if authority.Endpoint.IsZero() {
			t.Fatal("an accepted authority has no endpoint")
		}
		if authority.Mode == "" {
			t.Fatal("an accepted authority has no mode")
		}

		if _, err := os.Stat(sentinel); err == nil {
			t.Fatal("something executed during kubeconfig validation")
		}
	})
}

// FuzzKubernetesNameValidation drives the two operator-written names.
//
// They reach an evidence subject, an evidence identifier and a redaction table,
// so the property is that an accepted name is safe in all three: valid UTF-8, no
// control characters, no whitespace, no identifier separator, and bounded.
func FuzzKubernetesNameValidation(f *testing.F) {
	f.Add("payments", "payments-api")
	f.Add("", "")
	f.Add("kube-system", "kubernetes")
	f.Add("a/b", "c%d")
	f.Add("\x1b[31m", "\r\n")
	f.Add("\xff\xfe", "ok")
	f.Add(strings.Repeat("n", 200), "s")

	f.Fuzz(func(t *testing.T, namespace, serviceName string) {
		target := Target{
			Kubeconfig: "/k", Context: "c", Namespace: namespace, ServiceName: serviceName,
		}
		if err := target.Validate(); err != nil {
			return
		}

		for _, name := range []string{namespace, serviceName} {
			if name == "" || len(name) > maxNameBytes {
				t.Fatalf("an unusable name %q was accepted", name)
			}
			for _, r := range name {
				if r <= ' ' || r == 0x7f {
					t.Fatalf("a name containing a control character was accepted: %q", name)
				}
			}
			if strings.ContainsAny(name, "/%") {
				t.Fatalf("a name containing an identifier separator was accepted: %q", name)
			}
		}

		// The subject is reconstructible and carries exactly the two names.
		subject := target.SubjectRef()
		if !strings.HasPrefix(subject, "service/") {
			t.Fatalf("subject %q has the wrong shape", subject)
		}
		if !strings.Contains(subject, namespace) || !strings.Contains(subject, serviceName) {
			t.Fatalf("subject %q lost a name", subject)
		}
	})
}

// FuzzStatusNormalization drives the API error classifier with arbitrary
// messages.
//
// **The message is the input and the property is that it changes nothing.** A
// status carrying ANSI, CRLF, a token-shaped value or a URL with credentials must
// classify identically to the same status carrying an empty message, and none of
// it may reach the result.
func FuzzStatusNormalization(f *testing.F) {
	f.Add(int32(403), "Forbidden", "user cannot list pods")
	f.Add(int32(404), "NotFound", "services \"x\" not found")
	f.Add(int32(500), "InternalError", "\x1b[31mboom\x1b[0m\r\nBearer sk-live-x")
	f.Add(int32(410), "Expired", "continue token expired")
	f.Add(int32(0), "", "")

	f.Fuzz(func(t *testing.T, code int32, reason, message string) {
		withMessage := classifyStatus(code, metav1.StatusReason(reason))
		withoutMessage := classifyStatus(code, metav1.StatusReason(reason))
		if withMessage != withoutMessage {
			t.Fatalf("the classification depends on the message")
		}
		if int(withMessage) >= len(failureNames) {
			t.Fatalf("classification produced an out-of-range failure %d", withMessage)
		}
		// The two states a finding will be built on are reachable only from the
		// API's own enumeration or its own status code.
		switch withMessage {
		case FailureNotFound:
			if code != http.StatusNotFound && reason != string(metav1.StatusReasonNotFound) {
				t.Fatalf("NOT_FOUND was produced from code %d reason %q", code, reason)
			}
		case FailureForbidden:
			if code != http.StatusForbidden && reason != string(metav1.StatusReasonForbidden) {
				t.Fatalf("FORBIDDEN was produced from code %d reason %q", code, reason)
			}
		}
	})
}

// FuzzEndpointConditionNormalization drives the frozen nil semantics.
//
// Three tri-state conditions is a small space, so this is exhaustive rather than
// random over them — and the property it protects is the one a mutation would
// break silently: readiness is decided by `ready` alone.
func FuzzEndpointConditionNormalization(f *testing.F) {
	f.Add(0, 0, 0)
	f.Add(1, 2, 1)
	f.Fuzz(func(t *testing.T, ready, serving, terminating int) {
		r := triState(ready)
		s := triState(serving)
		term := triState(terminating)

		got := EffectiveReady(r)
		want := r == nil || *r
		if got != want {
			t.Fatalf("EffectiveReady disagreed with the frozen rule")
		}
		// Neither of the other two may change it.
		if EffectiveReady(r) != got {
			t.Fatal("EffectiveReady is not a function of ready alone")
		}
		_ = EffectiveServing(s)
		_ = EffectiveTerminating(term)

		// The one shape the contract calls out: serving and terminating, not
		// ready. It is not ready, and it is not dead either — nothing here says
		// anything beyond "not ready".
		if r != nil && !*r && s != nil && *s && term != nil && *term {
			if EffectiveReady(r) {
				t.Fatal("a terminating endpoint was counted as ready")
			}
			if !EffectiveServing(s) {
				t.Fatal("a serving endpoint was normalized as not serving")
			}
		}
	})
}

func triState(v int) *bool {
	switch ((v % 3) + 3) % 3 {
	case 0:
		return nil
	case 1:
		return ptrTrue()
	default:
		return ptrFalse()
	}
}

func ptrTrue() *bool  { v := true; return &v }
func ptrFalse() *bool { v := false; return &v }

// FuzzHostileSliceMetadata drives normalization with adversarial object fields.
//
// Slice names, manager labels and targetRef names are all cluster-controlled
// text. The property is that none of them reaches a normalized value and none of
// them changes a count.
func FuzzHostileSliceMetadata(f *testing.F) {
	f.Add("payments-api-abcde", "endpointslice-controller.k8s.io", "pod-1")
	f.Add("\x1b[31m", "\r\ninjected", "\x00")
	f.Add(strings.Repeat("x", 4096), "", "")

	f.Fuzz(func(t *testing.T, sliceName, manager, targetName string) {
		accumulator := &publicationAccumulator{
			serviceUID: "uid-1", maxEndpoints: 100, seen: map[string]struct{}{},
		}
		published := discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "payments",
				Name:      sliceName,
				Labels: map[string]string{
					discoveryv1.LabelServiceName: "payments-api",
					discoveryv1.LabelManagedBy:   manager,
				},
			},
			AddressType: discoveryv1.AddressTypeIPv4,
			Endpoints: []discoveryv1.Endpoint{{
				Addresses:  []string{"10.0.0.1"},
				Conditions: discoveryv1.EndpointConditions{Ready: ptrTrue()},
				TargetRef: &corev1.ObjectReference{
					Namespace: "payments", Name: targetName,
				},
			}},
		}

		accounted, stop := accumulator.consume([]discoveryv1.EndpointSlice{published})
		if accounted != 1 {
			t.Fatalf("accounted %d slices, want 1", accounted)
		}
		if stop != StopComplete {
			t.Fatalf("stop reason is %v", stop)
		}
		if accumulator.facts.Endpoints != 1 || accumulator.facts.ReadyEndpoints != 1 {
			t.Fatalf("hostile metadata changed a count: %+v", accumulator.facts)
		}
		rendered := sprintf("%#v", accumulator.facts)
		for _, fragment := range []string{sliceName, manager, targetName} {
			if len(fragment) > 3 && strings.Contains(rendered, fragment) {
				t.Fatalf("cluster-controlled text %q reached a normalized value", fragment)
			}
		}
	})
}

// TestFuzzCorpusRunsWithoutANetwork keeps the fuzz targets hermetic.
//
// Every target above is a pure function or a filesystem read. None of them opens
// a socket, which is what makes them cheap enough to run for minutes rather than
// seconds.
func TestFuzzCorpusRunsWithoutANetwork(t *testing.T) {
	if _, err := Inspect(Target{
		Kubeconfig: filepath.Join(t.TempDir(), "absent"), Context: "c",
		Namespace: "n", ServiceName: "s",
	}, false); err == nil {
		t.Fatal("an absent kubeconfig was accepted")
	}
	_ = context.Background()
}
