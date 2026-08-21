package domain

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestNewSubject(t *testing.T) {
	tests := []struct {
		name     string
		make     func(string) (Subject, error)
		ref      string
		wantKind SubjectKind
		wantStr  string
	}{
		{"target", NewTargetSubject, "kafka.internal:9092", SubjectKindTarget, "TARGET:kafka.internal:9092"},
		{"endpoint", NewEndpointSubject, "broker-2.internal:9092", SubjectKindEndpoint, "ENDPOINT:broker-2.internal:9092"},
		{"ipv6 endpoint", NewEndpointSubject, "[2001:db8::1]:9092", SubjectKindEndpoint, "ENDPOINT:[2001:db8::1]:9092"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := tt.make(tt.ref)
			if err != nil {
				t.Fatalf("constructor: %v", err)
			}
			if s.Kind() != tt.wantKind {
				t.Errorf("Kind() = %s, want %s", s.Kind(), tt.wantKind)
			}
			if s.Ref() != tt.ref {
				t.Errorf("Ref() = %q, want %q", s.Ref(), tt.ref)
			}
			if s.IsZero() {
				t.Error("a constructed Subject must not be zero")
			}
			if s.String() != tt.wantStr {
				t.Errorf("String() = %q, want %q", s.String(), tt.wantStr)
			}
		})
	}
}

func TestNewSubjectRejectsBadRef(t *testing.T) {
	invalid := []string{"", " ", "host ", " host", "host\nname", "host\x00"}

	for _, ref := range invalid {
		s, err := NewEndpointSubject(ref)
		if !errors.Is(err, ErrInvalidValue) {
			t.Errorf("NewEndpointSubject(%q) err = %v, want ErrInvalidValue", ref, err)
		}
		if !s.IsZero() {
			t.Errorf("NewEndpointSubject(%q) must return the zero Subject", ref)
		}
	}
}

func TestSubjectJSON(t *testing.T) {
	s, err := NewEndpointSubject("kafka.internal:9092")
	if err != nil {
		t.Fatalf("NewEndpointSubject: %v", err)
	}

	got, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	const want = `{"kind":"ENDPOINT","ref":"kafka.internal:9092"}`
	if string(got) != want {
		t.Errorf("json.Marshal = %s, want %s", got, want)
	}
}

func TestZeroSubjectIsInvalid(t *testing.T) {
	var s Subject

	if !s.IsZero() {
		t.Error("the zero Subject should report IsZero")
	}
	if s.Kind().Valid() {
		t.Error("the zero Subject must not have a valid kind")
	}
	if s.String() != "<invalid subject>" {
		t.Errorf("String() = %q, want %q", s.String(), "<invalid subject>")
	}

	if _, err := json.Marshal(s); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("json.Marshal error = %v, want ErrInvalidValue", err)
	}
}

// TestSubjectKindCannotBeUnspecified proves there is no constructor that could
// produce a subject with no kind.
func TestSubjectKindCannotBeUnspecified(t *testing.T) {
	for _, s := range []Subject{
		mustTargetSubject(t, "target"),
		mustEndpointSubject(t, "host:1"),
	} {
		if !s.Kind().Valid() {
			t.Errorf("%s produced an unspecified kind", s)
		}
	}
}

func TestSubjectIsComparable(t *testing.T) {
	a := mustEndpointSubject(t, "host:9092")
	b := mustEndpointSubject(t, "host:9092")
	c := mustEndpointSubject(t, "other:9092")
	d := mustTargetSubject(t, "host:9092")

	if a != b {
		t.Error("identical subjects should compare equal")
	}
	if a == c {
		t.Error("subjects with different refs should not compare equal")
	}
	if a == d {
		t.Error("subjects with different kinds should not compare equal")
	}
}

func TestSubjectKindString(t *testing.T) {
	tests := []struct {
		kind SubjectKind
		want string
	}{
		{SubjectKindUnspecified, "UNSPECIFIED"},
		{SubjectKindTarget, "TARGET"},
		{SubjectKindEndpoint, "ENDPOINT"},
		{SubjectKind(99), "SubjectKind(99)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.kind.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}

	if _, err := json.Marshal(SubjectKindUnspecified); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("marshalling an unspecified kind: err = %v, want ErrInvalidValue", err)
	}
}

// TestNoServiceSpecificSubjectKinds guards against the model growing a member
// per service. A Kafka broker and a PostgreSQL host are both endpoints.
func TestSubjectKindNamesCoverAllKinds(t *testing.T) {
	const wantCount = 3 // unspecified, target, endpoint

	if len(subjectKindNames) != wantCount {
		t.Fatalf("subjectKindNames has %d entries, want %d", len(subjectKindNames), wantCount)
	}
	for i, name := range subjectKindNames {
		if name == "" {
			t.Errorf("SubjectKind(%d) has no name", i)
		}
	}
	if SubjectKind(SubjectKindEndpoint + 1).Valid() {
		t.Error("no subject kind beyond ENDPOINT should be defined")
	}
}

func mustTargetSubject(t *testing.T, ref string) Subject {
	t.Helper()
	s, err := NewTargetSubject(ref)
	if err != nil {
		t.Fatalf("NewTargetSubject(%q): %v", ref, err)
	}
	return s
}

func mustEndpointSubject(t *testing.T, ref string) Subject {
	t.Helper()
	s, err := NewEndpointSubject(ref)
	if err != nil {
		t.Fatalf("NewEndpointSubject(%q): %v", ref, err)
	}
	return s
}
