package domain

import (
	"encoding/json"
	"errors"
	"testing"
)

// TestLayerOrder pins the locked order from ADR 0007. Short-circuiting and
// first-broken-layer reporting depend on it.
func TestLayerOrder(t *testing.T) {
	ordered := []Layer{
		LayerInput,
		LayerDNS,
		LayerTCP,
		LayerTLS,
		LayerProtocol,
		LayerAuth,
		LayerTopology,
	}

	for i := 1; i < len(ordered); i++ {
		prev, cur := ordered[i-1], ordered[i]
		if prev >= cur {
			t.Errorf("expected %s < %s", prev, cur)
		}
	}
}

// TestProtocolPrecedesAuth calls out the correction made by ADR 0007
// explicitly, because the earlier documentation had these reversed.
func TestProtocolPrecedesAuth(t *testing.T) {
	if LayerProtocol >= LayerAuth {
		t.Error("protocol/capability discovery must precede authentication")
	}
	if LayerTLS >= LayerProtocol {
		t.Error("TLS must precede protocol discovery")
	}
	if LayerAuth >= LayerTopology {
		t.Error("authentication must precede topology discovery")
	}
}

func TestLayerString(t *testing.T) {
	tests := []struct {
		layer     Layer
		wantCode  string
		wantLabel string
	}{
		{LayerInput, "L0", "input"},
		{LayerDNS, "L1", "dns"},
		{LayerTCP, "L2", "tcp"},
		{LayerTLS, "L3", "tls"},
		{LayerProtocol, "L4", "protocol"},
		{LayerAuth, "L5", "auth"},
		{LayerTopology, "L6", "topology"},
	}

	for _, tt := range tests {
		t.Run(tt.wantCode, func(t *testing.T) {
			if got := tt.layer.String(); got != tt.wantCode {
				t.Errorf("String() = %q, want %q", got, tt.wantCode)
			}
			if got := tt.layer.Label(); got != tt.wantLabel {
				t.Errorf("Label() = %q, want %q", got, tt.wantLabel)
			}
			if !tt.layer.Valid() {
				t.Error("layer must be valid")
			}
		})
	}
}

func TestLayerJSON(t *testing.T) {
	got, err := json.Marshal(LayerDNS)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if string(got) != `"L1"` {
		t.Errorf("json.Marshal(LayerDNS) = %s, want \"L1\"", got)
	}
}

// TestLayerV01StopsAtL6 pins the v0.1 scope boundary. Adding a layer requires a
// deliberate scope decision, so this failing is the intended signal.
func TestLayerV01StopsAtL6(t *testing.T) {
	if LayerTopology.String() != "L6" {
		t.Errorf("highest layer = %q, want L6", LayerTopology)
	}
	if Layer(LayerTopology + 1).Valid() {
		t.Error("v0.1 must not define a layer above L6")
	}
}

// TestZeroLayerIsInvalid pins the decision that L0 is not the zero value. If it
// were, a forgotten layer would silently claim to be config-layer evidence.
func TestZeroLayerIsInvalid(t *testing.T) {
	var l Layer

	if l != LayerUnspecified {
		t.Errorf("zero Layer = %d, want LayerUnspecified", l)
	}
	if l.Valid() {
		t.Error("the zero Layer must not be valid")
	}
	if l == LayerInput {
		t.Error("the zero Layer must not be L0")
	}
	if got := l.String(); got != "UNSPECIFIED" {
		t.Errorf("String() = %q, want %q", got, "UNSPECIFIED")
	}

	_, err := json.Marshal(l)
	if !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("json.Marshal error = %v, want ErrInvalidValue", err)
	}
}

func TestInvalidLayer(t *testing.T) {
	invalid := Layer(99)

	if invalid.Valid() {
		t.Error("Layer(99) must not be valid")
	}
	if got := invalid.String(); got != "Layer(99)" {
		t.Errorf("String() = %q, want %q", got, "Layer(99)")
	}
	if got := invalid.Label(); got != "Layer(99)" {
		t.Errorf("Label() = %q, want %q", got, "Layer(99)")
	}

	_, err := json.Marshal(invalid)
	if !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("json.Marshal error = %v, want ErrInvalidValue", err)
	}
}

// TestLayerTableCoversAllLayers fails if a layer is added without text forms.
func TestLayerTableCoversAllLayers(t *testing.T) {
	const wantCount = 8 // LayerUnspecified plus L0-L6

	if len(layers) != wantCount {
		t.Fatalf("layers has %d entries, want %d", len(layers), wantCount)
	}
	for i, info := range layers {
		if info.code == "" || info.label == "" {
			t.Errorf("Layer(%d) is missing a code or label", i)
		}
	}
}
