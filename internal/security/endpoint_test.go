package security

import (
	"errors"
	"testing"
)

func TestNewEndpointRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name string
		host string
		port uint16
	}{
		{"empty host", "", 9092},
		{"port zero", "kafka.internal", 0},
		{"both invalid", "", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ep, err := NewEndpoint(tt.host, tt.port)
			if !errors.Is(err, ErrInvalidEndpoint) {
				t.Fatalf("err = %v, want ErrInvalidEndpoint", err)
			}
			if !ep.IsZero() {
				t.Error("a rejected endpoint must be the zero value")
			}
		})
	}
}

func TestEndpointNormalization(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		wantHost string
		wantStr  string
	}{
		{"ascii lowercase unchanged", "kafka.internal", "kafka.internal", "kafka.internal:9092"},
		{"uppercase dns lowered", "KAFKA.INTERNAL", "kafka.internal", "kafka.internal:9092"},
		{"mixed case dns lowered", "Broker-1.Example.COM", "broker-1.example.com", "broker-1.example.com:9092"},
		{"trailing dot stripped", "kafka.internal.", "kafka.internal", "kafka.internal:9092"},
		{"trailing dot and case", "KAFKA.Internal.", "kafka.internal", "kafka.internal:9092"},
		{"ipv4 literal", "10.0.1.7", "10.0.1.7", "10.0.1.7:9092"},
		{"ipv6 canonicalized", "0:0:0:0:0:0:0:1", "::1", "[::1]:9092"},
		{"ipv6 compact", "::1", "::1", "[::1]:9092"},
		{"ipv6 uppercase hex", "2001:DB8::1", "2001:db8::1", "[2001:db8::1]:9092"},
		{"ipv6 with zone", "fe80::1%eth0", "fe80::1%eth0", "[fe80::1%eth0]:9092"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ep, err := NewEndpoint(tt.host, 9092)
			if err != nil {
				t.Fatalf("NewEndpoint(%q): %v", tt.host, err)
			}
			if ep.Host() != tt.wantHost {
				t.Errorf("Host() = %q, want %q", ep.Host(), tt.wantHost)
			}
			if ep.Port() != 9092 {
				t.Errorf("Port() = %d, want 9092", ep.Port())
			}
			if ep.String() != tt.wantStr {
				t.Errorf("String() = %q, want %q", ep.String(), tt.wantStr)
			}
		})
	}
}

// TestAsciiLowerLeavesNonASCIIAlone pins the RFC 4343 decision: DNS case
// insensitivity is ASCII only, so Unicode case folding must not be applied.
func TestAsciiLowerLeavesNonASCIIAlone(t *testing.T) {
	// Latin capital I with dot above; Unicode lowering would change its length.
	const host = "KAFKA-İ.internal"

	ep, err := NewEndpoint(host, 9092)
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	const want = "kafka-İ.internal"
	if ep.Host() != want {
		t.Errorf("Host() = %q, want %q", ep.Host(), want)
	}
}

func TestEndpointEqual(t *testing.T) {
	mk := func(t *testing.T, host string, port uint16) Endpoint {
		t.Helper()
		ep, err := NewEndpoint(host, port)
		if err != nil {
			t.Fatalf("NewEndpoint(%q, %d): %v", host, port, err)
		}
		return ep
	}

	tests := []struct {
		name  string
		aHost string
		aPort uint16
		bHost string
		bPort uint16
		want  bool
	}{
		{"identical", "kafka.internal", 9092, "kafka.internal", 9092, true},
		{"case differs", "KAFKA.internal", 9092, "kafka.internal", 9092, true},
		{"trailing dot differs", "kafka.internal.", 9092, "kafka.internal", 9092, true},
		{"ipv6 spelling differs", "0:0:0:0:0:0:0:1", 9092, "::1", 9092, true},
		{"different host", "broker-1.internal", 9092, "broker-2.internal", 9092, false},
		{"different port", "kafka.internal", 9092, "kafka.internal", 9093, false},
		{"host and port differ", "broker-1.internal", 9092, "broker-2.internal", 9093, false},
		{"ipv6 zone differs", "fe80::1%eth0", 9092, "fe80::1%eth1", 9092, false},
		{"name vs its literal", "localhost", 9092, "127.0.0.1", 9092, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := mk(t, tt.aHost, tt.aPort)
			b := mk(t, tt.bHost, tt.bPort)

			if got := a.Equal(b); got != tt.want {
				t.Errorf("a.Equal(b) = %v, want %v", got, tt.want)
			}
			if got := b.Equal(a); got != tt.want {
				t.Errorf("Equal is not symmetric: b.Equal(a) = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestEqualDoesNotFollowResolution is the security-relevant case. Two distinct
// names may resolve to the same address, but that must never make them equal:
// resolution is a runtime fact that differs per vantage point and can be
// attacker influenced, so it must not widen a credential's scope.
func TestEqualDoesNotFollowResolution(t *testing.T) {
	name, err := NewEndpoint("localhost", 9092)
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	v4, err := NewEndpoint("127.0.0.1", 9092)
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	v6, err := NewEndpoint("::1", 9092)
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}

	if name.Equal(v4) {
		t.Error("a hostname must not equal an address it resolves to")
	}
	if name.Equal(v6) {
		t.Error("a hostname must not equal an address it resolves to")
	}
	if v4.Equal(v6) {
		t.Error("addresses for the same host in different families must not be equal")
	}
}

func TestEndpointZeroValue(t *testing.T) {
	var ep Endpoint

	if !ep.IsZero() {
		t.Error("zero Endpoint should report IsZero")
	}
	if ep.String() != "<invalid endpoint>" {
		t.Errorf("String() = %q, want %q", ep.String(), "<invalid endpoint>")
	}
	if ep.Host() != "" || ep.Port() != 0 {
		t.Error("zero Endpoint should have empty host and zero port")
	}
}
