package domain

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestNewFindingCodeAccepts(t *testing.T) {
	// Service and layer namespaces, per docs/FINDINGS.md section 1. These appear
	// only as examples; this package holds no catalog of codes.
	valid := []string{
		"KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE",
		"KAFKA_SECURITY_PROTOCOL_MISMATCH",
		"POSTGRES_TLS_POLICY_MISMATCH",
		"DNS_RESOLUTION_FAILED",
		"TCP_CONNECTION_REFUSED",
		"TLS_CERTIFICATE_EXPIRED",
		"A_B",
		"TLS13_NOT_OFFERED",
		"REDIS_ANNOUNCED_NODE_UNREACHABLE",
	}

	for _, s := range valid {
		t.Run(s, func(t *testing.T) {
			code, err := NewFindingCode(s)
			if err != nil {
				t.Fatalf("NewFindingCode(%q): %v", s, err)
			}
			if code.String() != s {
				t.Errorf("String() = %q, want %q", code.String(), s)
			}
			if !code.Valid() {
				t.Error("code should be valid")
			}
		})
	}
}

func TestNewFindingCodeRejects(t *testing.T) {
	tests := []struct {
		name string
		code string
	}{
		{"empty", ""},
		{"single segment", "KAFKA"},
		{"lowercase", "kafka_unreachable"},
		{"mixed case", "Kafka_Unreachable"},
		{"trailing underscore", "KAFKA_"},
		{"leading underscore", "_KAFKA"},
		{"double underscore", "KAFKA__UNREACHABLE"},
		{"hyphen", "KAFKA-UNREACHABLE"},
		{"dot", "KAFKA.UNREACHABLE"},
		{"space", "KAFKA UNREACHABLE"},
		{"leading digit", "1KAFKA_UNREACHABLE"},
		{"newline", "KAFKA_UNREACHABLE\n"},
		{"tab", "KAFKA\tUNREACHABLE"},
		{"non-ascii", "KAFKA_ÜNREACHABLE"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, err := NewFindingCode(tt.code)
			if !errors.Is(err, ErrInvalidValue) {
				t.Fatalf("err = %v, want ErrInvalidValue", err)
			}
			if code != "" {
				t.Errorf("a rejected code must be empty, got %q", code)
			}
			if FindingCode(tt.code).Valid() {
				t.Error("Valid() should reject the same input")
			}
		})
	}
}

// TestFindingCodeNamespaceSetIsOpen is the important property: validation checks
// the shape, never a list of known namespaces. A future service must be able to
// introduce codes without editing core validation.
func TestFindingCodeNamespaceSetIsOpen(t *testing.T) {
	// Namespaces that do not exist anywhere in this project.
	invented := []string{
		"CASSANDRA_NODE_UNREACHABLE",
		"NATS_CLUSTER_SPLIT",
		"SOMETHINGNOBODYPLANNED_WENT_WRONG",
	}

	for _, s := range invented {
		code, err := NewFindingCode(s)
		if err != nil {
			t.Errorf("an unknown namespace must still be accepted: %q: %v", s, err)
		}
		if code.Namespace() == "" {
			t.Errorf("Namespace() should resolve for %q", s)
		}
	}
}

func TestFindingCodeNamespace(t *testing.T) {
	tests := []struct {
		code string
		want string
	}{
		{"KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE", "KAFKA"},
		{"DNS_RESOLUTION_FAILED", "DNS"},
		{"POSTGRES_TLS_POLICY_MISMATCH", "POSTGRES"},
	}

	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			code, err := NewFindingCode(tt.code)
			if err != nil {
				t.Fatalf("NewFindingCode: %v", err)
			}
			if got := code.Namespace(); got != tt.want {
				t.Errorf("Namespace() = %q, want %q", got, tt.want)
			}
		})
	}

	if got := FindingCode("not valid").Namespace(); got != "" {
		t.Errorf("Namespace() of an invalid code = %q, want empty", got)
	}
}

func TestFindingCodeIsComparable(t *testing.T) {
	a, err := NewFindingCode("DNS_RESOLUTION_FAILED")
	if err != nil {
		t.Fatalf("NewFindingCode: %v", err)
	}
	b, err := NewFindingCode("DNS_RESOLUTION_FAILED")
	if err != nil {
		t.Fatalf("NewFindingCode: %v", err)
	}
	c, err := NewFindingCode("TCP_CONNECTION_REFUSED")
	if err != nil {
		t.Fatalf("NewFindingCode: %v", err)
	}

	if a != b {
		t.Error("equal codes should compare equal")
	}
	if a == c {
		t.Error("different codes should not compare equal")
	}

	// Usable as a map key, which grouping and counting will rely on.
	counts := map[FindingCode]int{a: 1}
	counts[b]++
	if counts[a] != 2 {
		t.Error("FindingCode should work as a map key")
	}
}

func TestFindingCodeJSON(t *testing.T) {
	code, err := NewFindingCode("KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE")
	if err != nil {
		t.Fatalf("NewFindingCode: %v", err)
	}

	got, err := json.Marshal(code)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	const want = `"KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE"`
	if string(got) != want {
		t.Errorf("json.Marshal = %s, want %s", got, want)
	}
}

// TestNoFindingCodeCatalogExists guards the ownership rule: code constants live
// with the rules that produce them, and the core holds no enumeration of them.
func TestNoFindingCodeCatalogExists(t *testing.T) {
	var c any = FindingCode("DNS_RESOLUTION_FAILED")

	if _, ok := c.(interface{ Registered() bool }); ok {
		t.Error("FindingCode must not consult a registry")
	}
	if _, ok := c.(interface{ Service() string }); ok {
		t.Error("FindingCode must not know which service owns it beyond its namespace text")
	}
	if _, ok := c.(interface{ Severity() Severity }); ok {
		t.Error("FindingCode must not imply a severity")
	}
	if _, ok := c.(interface{ Layer() Layer }); ok {
		t.Error("FindingCode must not imply a layer; the caller supplies it")
	}
}
