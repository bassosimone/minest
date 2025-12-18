//
// SPDX-License-Identifier: BSD-3-Clause
//
// Adapted from: https://github.com/ooni/probe-engine/blob/v0.23.0/netx/resolver/dnsoverhttps.go
// Adapted from: https://github.com/rbmk-project/rbmk/blob/v0.17.0/pkg/dns/dnscore/dohttps.go
//

package dmi

import (
	"bytes"
	"context"
	"io"
	"net/http"

	"github.com/miekg/dns"
)

// HTTPSClient abstracts over [*http.Client].
type HTTPSClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// HTTPSExchanger implements [ClientExchanger] for DNS over HTTPS.
//
// Construct using [NewHTTPSExchanger].
type HTTPSExchanger struct {
	// Client is the HTTPSClient to use to query.
	//
	// Set by [NewHTTPSExchanger] to the user-provided value.
	Client HTTPSClient

	// URL is the server URL to use to query.
	//
	// Set by [NewHTTPSExchanger] to the user-provided value.
	URL string
}

// NewHTTPSExchanger creates a new [*HTTPSExchanger].
func NewHTTPSExchanger(client HTTPSClient, URL string) *HTTPSExchanger {
	return &HTTPSExchanger{
		Client: client,
		URL:    URL,
	}
}

// Ensure that [*HTTPSExchanger] implements [ClientExchanger].
var _ ClientExchanger = &HTTPSExchanger{}

// Exchange implements [ClientExchanger].
func (he *HTTPSExchanger) Exchange(ctx context.Context, query *Query) (*Response, error) {
	// 1. Mutate and serialize the query
	//
	// For DoH, by default we leave the query ID to zero, which
	// is what the RFC suggests to do.
	query = query.Clone()
	query.flags |= queryFlagBlockLengthPadding | queryFlagDNSSec
	query.id = 0
	query.maxSize = queryMaxResponseSizeTCP
	queryMsg, err := query.NewMsg()
	if err != nil {
		return nil, err
	}
	rawQuery, err := queryMsg.Pack()
	if err != nil {
		return nil, err
	}

	// 2. Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, he.URL, bytes.NewReader(rawQuery))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/dns-message")

	// 3. Do the HTTP round trip
	httpResp, err := he.Client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

	// 4. Ensure that the response makes sense
	if httpResp.StatusCode != 200 {
		return nil, ErrServerMisbehaving
	}
	if httpResp.Header.Get("content-type") != "application/dns-message" {
		return nil, ErrServerMisbehaving
	}

	// 5. Limit response body to a reasonable size and read it
	reader := io.LimitReader(httpResp.Body, queryMaxResponseSizeTCP)
	rawResp, err := io.ReadAll(reader)
	if err != nil {
		return nil, ErrServerMisbehaving
	}

	// 6. Attempt to parse the raw response body
	respMsg := &dns.Msg{}
	if err := respMsg.Unpack(rawResp); err != nil {
		return nil, err
	}

	// 7. Parse the response and return the parsing result
	return NewResponse(queryMsg, respMsg)
}
