package wire

import (
	"context"
	"net"

	"github.com/twmb/franz-go/pkg/kmsg"
)

// apiVersionsRequestVersion is the version of ApiVersions svcdoctor sends.
//
// Version 0 is deliberate. Every broker that speaks ApiVersions at all answers
// v0, so the request cannot itself become the reason a peer refuses to describe
// its capabilities. Asking for a newer version would make the probe's own choice
// part of the result.
const apiVersionsRequestVersion = 0

// APIKeyRange is one API key the peer advertised, with the version range it
// supports for it.
type APIKeyRange struct {
	Key        int16
	MinVersion int16
	MaxVersion int16
}

// APIVersions is what one ApiVersions exchange observed, in plain Go values.
type APIVersions struct {
	// ErrorCode is the broker's own error code, zero when it reported none.
	ErrorCode int16

	// Keys is what the peer advertised, in the order it sent them. Canonical
	// ordering is the caller's business, because ordering is a report concern.
	Keys []APIKeyRange
}

// RequestAPIVersion reports which version of ApiVersions was asked for, so that
// the recorded evidence can say what the exchange actually was.
func RequestAPIVersion() int16 { return apiVersionsRequestVersion }

// ExchangeAPIVersions sends one ApiVersions request over conn and reads the
// response.
//
// The connection is borrowed, not owned; see exchange.
func ExchangeAPIVersions(ctx context.Context, conn net.Conn) (APIVersions, error) {
	request := kmsg.NewPtrApiVersionsRequest()
	request.SetVersion(apiVersionsRequestVersion)

	response := kmsg.NewPtrApiVersionsResponse()
	response.SetVersion(apiVersionsRequestVersion)

	if err := exchange(ctx, conn, correlationAPIVersions, request, response); err != nil {
		return APIVersions{}, err
	}
	return normalizeAPIVersions(response), nil
}

// normalizeAPIVersions copies the response into plain values, which is what
// keeps every kmsg type inside this package.
func normalizeAPIVersions(response *kmsg.ApiVersionsResponse) APIVersions {
	keys := make([]APIKeyRange, 0, len(response.ApiKeys))
	for _, key := range response.ApiKeys {
		keys = append(keys, APIKeyRange{
			Key:        key.ApiKey,
			MinVersion: key.MinVersion,
			MaxVersion: key.MaxVersion,
		})
	}
	return APIVersions{ErrorCode: response.ErrorCode, Keys: keys}
}
