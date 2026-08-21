package wire

import (
	"context"
	"net"

	"github.com/twmb/franz-go/pkg/kmsg"
)

// metadataRequestVersion is the version of Metadata svcdoctor sends.
//
// Version 1 is the smallest version that can ask the question this step actually
// has, and the choice is bounded on both sides rather than being "the newest".
//
// # Why not v0
//
// The topics field is what selects between "describe the cluster" and "describe
// the cluster and every topic in it", and the two versions read an empty list
// differently:
//
//	v0   an empty topics array means *all* topics
//	v1+  an empty topics array means *no* topics; null means all
//
// So v0 cannot express "brokers only" at all. Asking it would pull every
// partition of every topic across the wire to learn a broker list that occupies
// a few dozen bytes.
//
// # Why not v2 or later
//
// v2 adds ClusterID, v3 adds throttling, v8 adds authorized-operations
// bitfields, and v9 makes the message flexible — which the framing in
// exchange.go refuses, because it reads a v0 response header and would misparse
// the tagged fields a flexible header carries.
//
// ClusterID is the interesting one, and it is deliberately left out of reach.
// A cluster identifier is deployment identity with no settled redaction
// classification, and svcdoctor does not need it to describe a topology. At v1
// the field is not on the wire at all, so it is structurally absent rather than
// received and then dropped — a stronger property than a filter, and one nobody
// can weaken by adding a line. See ADR 0031.
//
// v1 does add the two facts this step wants beyond v0: the controller's node
// identifier, and each broker's rack.
const metadataRequestVersion = 1

// MetadataBroker is one broker the cluster advertised, in plain Go values.
//
// The fields are exactly what the response carried, unvalidated and
// unnormalized. Deciding whether a host and port name a usable endpoint is the
// adapter's job, because "usable" is a judgement about an execution target and
// this package reports what arrived.
//
// Port is the protocol's int32 rather than a uint16 for the same reason: a
// broker that advertised 70000 or -1 said something, and narrowing it here would
// turn a diagnosable fact into a decoding artifact.
type MetadataBroker struct {
	NodeID int32
	Host   string
	Port   int32
}

// Metadata is what one Metadata exchange observed, in plain Go values.
//
// # What it deliberately does not carry
//
// Topics. None were requested, so the response has none, and a field that is
// always empty would invite a caller to conclude something about a cluster
// nobody asked about.
//
// ClusterID. Not present at this version; see metadataRequestVersion.
//
// Rack. It is on the wire at v1 and stays in this package. A rack label is
// deployment-descriptive free text — "us-east-1a" carries little, "dc-frankfurt"
// carries a lot — and nothing in this phase reads it. Recording an
// identity-ambiguous value with no consumer is how a shareable report acquires a
// leak nobody planned. See ADR 0031.
//
// ThrottleMillis, authorized operations and the v13 top-level error code are all
// absent from this version and are not synthesized.
type Metadata struct {
	// ControllerID is the node identifier of the broker the cluster considers
	// its controller. Kafka's own default is -1, which states that the
	// responding broker knows of no controller — an absence worth recording as
	// the statement it is.
	ControllerID int32

	// Brokers is what the peer advertised, in the order it sent them. Canonical
	// ordering is the caller's business, because ordering is a report concern.
	//
	// Duplicates and contradictions are preserved exactly as they arrived. A
	// cluster that advertises one node identifier at two addresses, or two node
	// identifiers at one address, has said something a diagnostic tool must not
	// tidy away before its caller has seen it.
	Brokers []MetadataBroker
}

// MetadataVersion reports which version of Metadata was asked for, so that the
// recorded evidence can say what the exchange actually was.
func MetadataVersion() int16 { return metadataRequestVersion }

// ExchangeMetadata asks conn's broker to describe the cluster's brokers.
//
// The connection is borrowed, not owned; see exchange.
//
// # It asks for no topics, and that is the request rather than a filter
//
// Topics is set to an empty, non-nil slice, which at v1 encodes as a
// zero-length array and means "no topics". A nil slice would encode as null and
// mean "every topic", so the distinction is load-bearing and is pinned by a
// test: the difference between describing a cluster and downloading its entire
// partition map is one field being empty rather than absent.
func ExchangeMetadata(ctx context.Context, conn net.Conn) (Metadata, error) {
	request := kmsg.NewPtrMetadataRequest()
	request.SetVersion(metadataRequestVersion)
	// Empty, not nil. See the doc comment above.
	request.Topics = []kmsg.MetadataRequestTopic{}

	response := kmsg.NewPtrMetadataResponse()
	response.SetVersion(metadataRequestVersion)

	if err := exchange(ctx, conn, correlationMetadata, request, response); err != nil {
		return Metadata{}, err
	}
	return normalizeMetadata(response), nil
}

// normalizeMetadata copies the response into plain values, which is what keeps
// every kmsg type inside this package.
func normalizeMetadata(response *kmsg.MetadataResponse) Metadata {
	brokers := make([]MetadataBroker, 0, len(response.Brokers))
	for _, broker := range response.Brokers {
		brokers = append(brokers, MetadataBroker{
			NodeID: broker.NodeID,
			Host:   broker.Host,
			Port:   broker.Port,
		})
	}
	return Metadata{ControllerID: response.ControllerID, Brokers: brokers}
}
