package wire

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/twmb/franz-go/pkg/kmsg"
)

// TestMetadataAsksForNoTopics pins the single most consequential field in this
// request, at the level where the encoding actually happens.
//
// At v1 an empty topics array means "no topics" and a null one means "every
// topic". The difference between describing a cluster and downloading its entire
// partition map is therefore one slice being empty rather than nil — a
// distinction Go makes easy to lose, and one no type checker will catch.
func TestMetadataAsksForNoTopics(t *testing.T) {
	request := kmsg.NewPtrMetadataRequest()
	request.SetVersion(metadataRequestVersion)
	request.Topics = []kmsg.MetadataRequestTopic{}
	empty := request.AppendTo(nil)

	nullRequest := kmsg.NewPtrMetadataRequest()
	nullRequest.SetVersion(metadataRequestVersion)
	nullRequest.Topics = nil
	null := nullRequest.AppendTo(nil)

	if bytes.Equal(empty, null) {
		t.Fatal("an empty topic list encodes identically to a null one; " +
			"this version cannot express a broker-only request")
	}
	if !bytes.HasSuffix(empty, []byte{0, 0, 0, 0}) {
		t.Errorf("empty topics encoded as %x, want a trailing zero-length array", empty)
	}
	if !bytes.HasSuffix(null, []byte{0xff, 0xff, 0xff, 0xff}) {
		t.Errorf("null topics encoded as %x, want a trailing -1", null)
	}
}

// TestMetadataVersionZeroCannotExpressBrokerOnly is why v0 is not used.
//
// At v0 an empty array means *all* topics, so the version choice is not a
// compatibility preference — it is the difference between asking a small
// question and a very large one.
func TestMetadataVersionZeroCannotExpressBrokerOnly(t *testing.T) {
	v0 := kmsg.NewPtrMetadataRequest()
	v0.SetVersion(0)
	v0.Topics = []kmsg.MetadataRequestTopic{}
	empty := v0.AppendTo(nil)

	v0Null := kmsg.NewPtrMetadataRequest()
	v0Null.SetVersion(0)
	v0Null.Topics = nil
	null := v0Null.AppendTo(nil)

	if !bytes.Equal(empty, null) {
		t.Fatal("v0 distinguishes empty from null; the reason for choosing v1 has changed")
	}
}

// TestMetadataVersionIsOne pins the choice from both directions: v1 carries the
// controller identifier v0 lacks, and stays non-flexible where v9 would not.
func TestMetadataVersionIsOne(t *testing.T) {
	if got := MetadataVersion(); got != 1 {
		t.Fatalf("Metadata version = %d, want 1", got)
	}

	request := kmsg.NewPtrMetadataRequest()
	request.SetVersion(metadataRequestVersion)
	response := kmsg.NewPtrMetadataResponse()
	response.SetVersion(metadataRequestVersion)

	if request.IsFlexible() || response.IsFlexible() {
		t.Error("the version this package sends is flexible; the framing does not support it")
	}
	if request.MaxVersion() < 9 {
		t.Errorf("kmsg max version = %d: the version choice is meant to be a choice",
			request.MaxVersion())
	}
}

// TestMetadataAtThisVersionCarriesNoClusterID is the security-relevant half of
// the version decision.
//
// A cluster identifier is deployment identity with no settled redaction
// classification. At v1 it is not on the wire, so it is structurally absent
// rather than received and filtered — a property no future edit to the
// normalizer can weaken.
func TestMetadataAtThisVersionCarriesNoClusterID(t *testing.T) {
	response := kmsg.NewPtrMetadataResponse()
	response.SetVersion(metadataRequestVersion)
	clusterID := "cluster-canary-do-not-leak"
	response.ClusterID = &clusterID
	response.ControllerID = 4

	encoded := response.AppendTo(nil)
	if bytes.Contains(encoded, []byte(clusterID)) {
		t.Fatal("v1 encodes a cluster identifier; the version's safety argument is wrong")
	}

	decoded := kmsg.NewPtrMetadataResponse()
	decoded.SetVersion(metadataRequestVersion)
	if err := decoded.ReadFrom(encoded); err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if decoded.ClusterID != nil {
		t.Errorf("a v1 response decoded a cluster identifier: %q", *decoded.ClusterID)
	}

	// And nothing derived from the response can carry one upward: the
	// normalized value has no field a cluster identifier could occupy.
	normalized := normalizeMetadata(decoded)
	rendered := fmt.Sprintf("%#v", normalized)
	if strings.Contains(rendered, clusterID) {
		t.Errorf("the normalized value carries the cluster identifier: %s", rendered)
	}
	for _, field := range []string{"ClusterID", "ClusterId"} {
		if strings.Contains(rendered, field) {
			t.Errorf("the normalized value has a %s field: %s", field, rendered)
		}
	}
}

// TestNormalizedMetadataCarriesNoRack: rack is on the wire at v1 and stays in
// this package. It is identity-ambiguous free text with no consumer, and a value
// like that is how a shareable report acquires a leak nobody planned.
func TestNormalizedMetadataCarriesNoRack(t *testing.T) {
	// The fixture proves the field really is on the wire at this version, so
	// the exclusion below is a decision rather than an accident of the protocol.
	response := kmsg.NewPtrMetadataResponse()
	response.SetVersion(metadataRequestVersion)
	broker := kmsg.NewMetadataResponseBroker()
	broker.NodeID, broker.Host, broker.Port = 1, "broker.internal", 9093
	rack := "dc-frankfurt-rack-7"
	broker.Rack = &rack
	response.Brokers = []kmsg.MetadataResponseBroker{broker}

	encoded := response.AppendTo(nil)
	if !bytes.Contains(encoded, []byte(rack)) {
		t.Fatal("v1 does not encode a rack; this exclusion guards nothing")
	}

	decoded := kmsg.NewPtrMetadataResponse()
	decoded.SetVersion(metadataRequestVersion)
	if err := decoded.ReadFrom(encoded); err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if decoded.Brokers[0].Rack == nil {
		t.Fatal("the rack did not survive decoding; this exclusion guards nothing")
	}

	rendered := fmt.Sprintf("%#v", normalizeMetadata(decoded))
	if strings.Contains(rendered, rack) {
		t.Errorf("the normalized broker carries the rack: %s", rendered)
	}
	if strings.Contains(rendered, "Rack") {
		t.Errorf("the normalized broker has a Rack field: %s", rendered)
	}
}

// TestMetadataPortStaysSigned: a broker that advertised an impossible port said
// something, and narrowing it at the wire boundary would turn a diagnosable fact
// into a decoding artifact.
func TestMetadataPortStaysSigned(t *testing.T) {
	response := kmsg.NewPtrMetadataResponse()
	response.SetVersion(metadataRequestVersion)
	broker := kmsg.NewMetadataResponseBroker()
	broker.NodeID, broker.Host, broker.Port = 9, "broker.internal", -1
	response.Brokers = []kmsg.MetadataResponseBroker{broker}

	normalized := normalizeMetadata(response)
	if len(normalized.Brokers) != 1 {
		t.Fatalf("brokers = %d, want 1", len(normalized.Brokers))
	}
	if got := normalized.Brokers[0].Port; got != -1 {
		t.Errorf("port = %d, want -1 preserved", got)
	}
}

// TestMetadataCorrelationIsDistinct: one connection now carries four exchanges
// in sequence, and each response must be checkable against its own request.
func TestMetadataCorrelationIsDistinct(t *testing.T) {
	ids := map[uint32]string{
		correlationAPIVersions:      "api versions",
		correlationSASLHandshake:    "sasl handshake",
		correlationSASLAuthenticate: "sasl authenticate",
		correlationMetadata:         "metadata",
	}
	if len(ids) != 4 {
		t.Errorf("two request kinds share a correlation identifier: %v", ids)
	}
}

// TestExchangeMetadataRefusesNoConnection covers the caller error that would
// otherwise surface as a nil dereference inside the framing.
func TestExchangeMetadataRefusesNoConnection(t *testing.T) {
	_, err := ExchangeMetadata(context.Background(), nil)
	if err == nil {
		t.Fatal("a nil connection was accepted")
	}
}
