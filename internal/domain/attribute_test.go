package domain

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestAttrValueKinds(t *testing.T) {
	ts := time.Date(2026, 8, 21, 10, 30, 0, 0, time.UTC)

	tests := []struct {
		name     string
		value    AttrValue
		wantKind AttrKind
		wantJSON string
		wantStr  string
	}{
		{
			name:     "string",
			value:    StringAttr("NOERROR"),
			wantKind: AttrKindString,
			wantJSON: `{"kind":"string","value":"NOERROR"}`,
			wantStr:  "NOERROR",
		},
		{
			name:     "empty string",
			value:    StringAttr(""),
			wantKind: AttrKindString,
			wantJSON: `{"kind":"string","value":""}`,
			wantStr:  "",
		},
		{
			name:     "int",
			value:    IntAttr(9092),
			wantKind: AttrKindInt,
			wantJSON: `{"kind":"int","value":9092}`,
			wantStr:  "9092",
		},
		{
			name:     "negative int",
			value:    IntAttr(-1),
			wantKind: AttrKindInt,
			wantJSON: `{"kind":"int","value":-1}`,
			wantStr:  "-1",
		},
		{
			name:     "bool true",
			value:    BoolAttr(true),
			wantKind: AttrKindBool,
			wantJSON: `{"kind":"bool","value":true}`,
			wantStr:  "true",
		},
		{
			name:     "bool false",
			value:    BoolAttr(false),
			wantKind: AttrKindBool,
			wantJSON: `{"kind":"bool","value":false}`,
			wantStr:  "false",
		},
		{
			name:     "duration",
			value:    DurationAttr(1500 * time.Millisecond),
			wantKind: AttrKindDuration,
			wantJSON: `{"kind":"duration","value":"1.5s"}`,
			wantStr:  "1.5s",
		},
		{
			name:     "zero duration",
			value:    DurationAttr(0),
			wantKind: AttrKindDuration,
			wantJSON: `{"kind":"duration","value":"0s"}`,
			wantStr:  "0s",
		},
		{
			name:     "time",
			value:    TimeAttr(ts),
			wantKind: AttrKindTime,
			wantJSON: `{"kind":"time","value":"2026-08-21T10:30:00Z"}`,
			wantStr:  "2026-08-21T10:30:00Z",
		},
		{
			name:     "string list",
			value:    StringListAttr("10.0.1.7", "10.0.1.8"),
			wantKind: AttrKindStringList,
			wantJSON: `{"kind":"stringList","value":["10.0.1.7","10.0.1.8"]}`,
			wantStr:  "[10.0.1.7, 10.0.1.8]",
		},
		{
			name:     "empty string list",
			value:    StringListAttr(),
			wantKind: AttrKindStringList,
			wantJSON: `{"kind":"stringList","value":[]}`,
			wantStr:  "[]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.value.Kind(); got != tt.wantKind {
				t.Errorf("Kind() = %s, want %s", got, tt.wantKind)
			}
			if !tt.value.Valid() {
				t.Error("value must be valid")
			}
			if got := tt.value.String(); got != tt.wantStr {
				t.Errorf("String() = %q, want %q", got, tt.wantStr)
			}

			got, err := json.Marshal(tt.value)
			if err != nil {
				t.Fatalf("json.Marshal: %v", err)
			}
			if string(got) != tt.wantJSON {
				t.Errorf("json.Marshal = %s, want %s", got, tt.wantJSON)
			}
		})
	}
}

func TestAttrValueAccessors(t *testing.T) {
	ts := time.Date(2026, 8, 21, 10, 30, 0, 0, time.UTC)

	if v, ok := StringAttr("x").Str(); !ok || v != "x" {
		t.Errorf("Str() = %q, %v", v, ok)
	}
	if v, ok := IntAttr(7).Int(); !ok || v != 7 {
		t.Errorf("Int() = %d, %v", v, ok)
	}
	if v, ok := BoolAttr(true).Bool(); !ok || !v {
		t.Errorf("Bool() = %v, %v", v, ok)
	}
	if v, ok := DurationAttr(time.Second).Duration(); !ok || v != time.Second {
		t.Errorf("Duration() = %v, %v", v, ok)
	}
	if v, ok := TimeAttr(ts).Time(); !ok || !v.Equal(ts) {
		t.Errorf("Time() = %v, %v", v, ok)
	}
	if v, ok := StringListAttr("a", "b").StringList(); !ok || len(v) != 2 {
		t.Errorf("StringList() = %v, %v", v, ok)
	}
}

// TestAccessorsRejectWrongKind proves a caller cannot read a value as the wrong
// type, which is what keeps the tagged union honest.
func TestAccessorsRejectWrongKind(t *testing.T) {
	v := StringAttr("not a number")

	if _, ok := v.Int(); ok {
		t.Error("Int() must reject a string value")
	}
	if _, ok := v.Bool(); ok {
		t.Error("Bool() must reject a string value")
	}
	if _, ok := v.Duration(); ok {
		t.Error("Duration() must reject a string value")
	}
	if _, ok := v.Time(); ok {
		t.Error("Time() must reject a string value")
	}
	if _, ok := v.StringList(); ok {
		t.Error("StringList() must reject a string value")
	}
}

// TestZeroAttrValueIsInvalid pins that an unset attribute is not silently an
// empty string.
func TestZeroAttrValueIsInvalid(t *testing.T) {
	var v AttrValue

	if v.Valid() {
		t.Error("the zero AttrValue must not be valid")
	}
	if v.Kind() != AttrKindInvalid {
		t.Errorf("Kind() = %s, want invalid", v.Kind())
	}
	if _, ok := v.Str(); ok {
		t.Error("the zero AttrValue must not read as a string")
	}

	_, err := json.Marshal(v)
	if !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("json.Marshal error = %v, want ErrInvalidValue", err)
	}
}

// TestTimeAttrNormalizesToUTC pins the determinism decision: the same instant
// encodes identically no matter which machine or zone produced it.
func TestTimeAttrNormalizesToUTC(t *testing.T) {
	zone := time.FixedZone("UTC+3", 3*60*60)
	local := time.Date(2026, 8, 21, 13, 30, 0, 0, zone)

	v := TimeAttr(local)

	got, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	const want = `{"kind":"time","value":"2026-08-21T10:30:00Z"}`
	if string(got) != want {
		t.Errorf("json.Marshal = %s, want %s", got, want)
	}

	// The same instant expressed in UTC must encode identically.
	utc, err := json.Marshal(TimeAttr(local.UTC()))
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if string(got) != string(utc) {
		t.Errorf("the same instant encoded differently: %s vs %s", got, utc)
	}
}

// TestTimeAttrDropsMonotonicReading guards value comparison and serialization:
// a monotonic reading is meaningless once encoded.
func TestTimeAttrDropsMonotonicReading(t *testing.T) {
	now := time.Now() // carries a monotonic reading

	stored, ok := TimeAttr(now).Time()
	if !ok {
		t.Fatal("Time() should return the value")
	}
	if stored != stored.Round(0) {
		t.Error("the stored instant still carries a monotonic reading")
	}
	if !stored.Equal(now) {
		t.Error("normalization must not change the instant")
	}
}

// TestSerializationIsDeterministic checks that encoding the same value twice
// produces identical bytes, which the canonical report depends on.
func TestSerializationIsDeterministic(t *testing.T) {
	values := []AttrValue{
		StringAttr("NOERROR"),
		IntAttr(9092),
		BoolAttr(true),
		DurationAttr(250 * time.Millisecond),
		TimeAttr(time.Date(2026, 8, 21, 10, 30, 0, 0, time.UTC)),
		StringListAttr("a", "b", "c"),
	}

	for _, v := range values {
		first, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		for i := 0; i < 5; i++ {
			again, err := json.Marshal(v)
			if err != nil {
				t.Fatalf("json.Marshal: %v", err)
			}
			if string(first) != string(again) {
				t.Errorf("%s encoded differently: %s vs %s", v.Kind(), first, again)
			}
		}
	}
}

// TestStringListIsCopiedOnWrite proves recorded evidence cannot be mutated
// through the slice the caller passed in.
func TestStringListIsCopiedOnWrite(t *testing.T) {
	input := []string{"10.0.1.7", "10.0.1.8"}
	v := StringListAttr(input...)

	input[0] = "mutated"

	got, ok := v.StringList()
	if !ok {
		t.Fatal("StringList() should return the value")
	}
	if got[0] != "10.0.1.7" {
		t.Errorf("recorded value changed with the caller's slice: %q", got[0])
	}
}

// TestStringListIsCopiedOnRead proves a reader cannot mutate recorded evidence
// through the returned slice.
func TestStringListIsCopiedOnRead(t *testing.T) {
	v := StringListAttr("10.0.1.7", "10.0.1.8")

	first, ok := v.StringList()
	if !ok {
		t.Fatal("StringList() should return the value")
	}
	first[0] = "mutated"

	second, ok := v.StringList()
	if !ok {
		t.Fatal("StringList() should return the value")
	}
	if second[0] != "10.0.1.7" {
		t.Errorf("recorded value changed through a reader's slice: %q", second[0])
	}
}

// TestNoArbitraryObjectCanBeStored is the ADR 0010 guarantee, expressed as a
// property of the API surface: every constructor takes a concrete primitive, so
// there is no path for a protocol response, a TLS connection state, or any
// interface value to reach evidence.
func TestNoArbitraryObjectCanBeStored(t *testing.T) {
	var v any = AttrValue{}

	if _, ok := v.(interface{ Raw() any }); ok {
		t.Error("AttrValue must not expose a raw accessor")
	}
	if _, ok := v.(interface{ Interface() any }); ok {
		t.Error("AttrValue must not expose an interface accessor")
	}
	if _, ok := v.(interface{ Map() map[string]any }); ok {
		t.Error("AttrValue must not expose a map accessor")
	}
	if _, ok := v.(interface{ Any(any) AttrValue }); ok {
		t.Error("AttrValue must not accept an arbitrary value")
	}

	// Every kind the model can hold is reachable only through a constructor
	// that takes a concrete primitive. Adding a kind means adding one of these,
	// which is the review point where an escape hatch would be noticed.
	for _, constructed := range []AttrValue{
		StringAttr(""),
		IntAttr(0),
		BoolAttr(false),
		DurationAttr(0),
		TimeAttr(time.Time{}),
		StringListAttr(),
		HostAttr(""),
		HostListAttr(),
	} {
		if !constructed.Valid() {
			t.Errorf("constructor produced an invalid value of kind %s", constructed.Kind())
		}
	}
}

func TestAttrKindString(t *testing.T) {
	tests := []struct {
		kind AttrKind
		want string
	}{
		{AttrKindInvalid, "invalid"},
		{AttrKindString, "string"},
		{AttrKindInt, "int"},
		{AttrKindBool, "bool"},
		{AttrKindDuration, "duration"},
		{AttrKindTime, "time"},
		{AttrKindStringList, "stringList"},
		{AttrKindHost, "host"},
		{AttrKindHostList, "hostList"},
		{AttrKind(99), "AttrKind(99)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.kind.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}

	if AttrKindInvalid.Valid() {
		t.Error("AttrKindInvalid must not be valid")
	}
	if AttrKind(99).Valid() {
		t.Error("AttrKind(99) must not be valid")
	}
}

// TestAttrKindNamesCoverAllKinds fails if a kind is added without a name.
func TestAttrKindNamesCoverAllKinds(t *testing.T) {
	// AttrKindInvalid plus eight value kinds. Phase 2.3 added host and hostList
	// so that a producer can declare a value as identity-bearing rather than
	// leaving redaction to guess; see ADR 0022.
	const wantCount = 9

	if len(attrKindNames) != wantCount {
		t.Fatalf("attrKindNames has %d entries, want %d", len(attrKindNames), wantCount)
	}
	for i, name := range attrKindNames {
		if name == "" {
			t.Errorf("AttrKind(%d) has no name", i)
		}
	}
}

// TestHostAttrsCarryIdentityDistinctly pins the reason the host kinds exist: a
// producer declares that a value identifies a peer, so structural redaction
// never has to tell "broker.internal" from "TLS1.3" by shape.
func TestHostAttrsCarryIdentityDistinctly(t *testing.T) {
	host := HostAttr("broker.internal")
	if got, ok := host.Host(); !ok || got != "broker.internal" {
		t.Errorf("Host() = %q, %v, want %q, true", got, ok, "broker.internal")
	}
	if _, ok := host.Str(); ok {
		t.Error("a host value must not read as a plain string, or redaction could not tell them apart")
	}
	if got, want := host.Kind(), AttrKindHost; got != want {
		t.Errorf("Kind() = %s, want %s", got, want)
	}

	list := HostListAttr("a.internal", "b.internal")
	names, ok := list.HostList()
	if !ok || len(names) != 2 {
		t.Fatalf("HostList() = %v, %v, want two entries", names, ok)
	}
	if _, ok := list.StringList(); ok {
		t.Error("a host list must not read as a plain string list")
	}

	// The copy is what stops a caller mutating recorded evidence.
	names[0] = "mutated"
	again, _ := list.HostList()
	if again[0] != "a.internal" {
		t.Error("HostList returned a slice that aliases the recorded value")
	}
}

// TestHostAttrsEncodeLikeTheirStringCounterparts keeps the wire format simple:
// the kind tag carries the meaning, and the value is the same text a reader
// would expect.
func TestHostAttrsEncodeLikeTheirStringCounterparts(t *testing.T) {
	encoded, err := json.Marshal(HostAttr("broker.internal"))
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if got, want := string(encoded), `{"kind":"host","value":"broker.internal"}`; got != want {
		t.Errorf("json.Marshal = %s, want %s", got, want)
	}

	encoded, err = json.Marshal(HostListAttr("a.internal", "b.internal"))
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if got, want := string(encoded), `{"kind":"hostList","value":["a.internal","b.internal"]}`; got != want {
		t.Errorf("json.Marshal = %s, want %s", got, want)
	}
}
