//
// SPDX-License-Identifier: BSD-3-Clause
//
// Adapted from: https://github.com/rbmk-project/rbmk/blob/v0.17.0/pkg/dns/dnscore/dotcp.go
// Adapted from: https://github.com/ooni/probe-engine/blob/v0.23.0/netx/resolver/dnsovertcp.go
//

package dmi

import (
	"context"
	"errors"
	"net"
	"os"
	"time"

	"github.com/miekg/dns"
)

// UDPDialer abstracts over [*net.Dialer].
type UDPDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// UDPExchanger implements [ClientExchanger] for DNS over UDP.
//
// Construct using [NewUDPExchanger].
type UDPExchanger struct {
	// Dialer is the UDPDialer to use to query.
	//
	// Set by [NewUDPExchanger] to the user-provided value.
	Dialer UDPDialer

	// Endpoint is the server endpoint to use to query.
	//
	// Set by [NewUDPExchanger] to the user-provided value.
	Endpoint string
}

// NewUDPExchanger creates a new [*UDPExchanger].
func NewUDPExchanger(dialer UDPDialer, endpoint string) *UDPExchanger {
	return &UDPExchanger{
		Dialer:   dialer,
		Endpoint: endpoint,
	}
}

// Ensure that [*UDPExchanger] implements [ClientExchanger].
var _ ClientExchanger = &UDPExchanger{}

// Exchange implements [ClientExchanger].
func (ue *UDPExchanger) Exchange(ctx context.Context, query *Query) (*Response, error) {
	// 1. create the connection
	conn, err := ue.Dialer.DialContext(ctx, "udp", ue.Endpoint)
	if err != nil {
		return nil, err
	}

	// 2. Use a single connection for request, which is what the standard library
	// does as well for and is more robust in terms of residual censorship.
	//
	// Make sure we react to context being canceled early.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		defer conn.Close()
		<-ctx.Done()
	}()

	// 3. Use the context deadline to limit the query lifetime
	// as documented in the [*Transport.Query] function.
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	// 4. Mutate and serialize the query.
	query = query.Clone()
	query.id = dns.Id()
	query.maxSize = queryMaxResponseSizeUDP
	queryMsg, err := query.NewMsg()
	if err != nil {
		return nil, err
	}
	rawQuery, err := queryMsg.Pack()
	if err != nil {
		return nil, err
	}

	// 5. Send the query.
	if _, err := conn.Write(rawQuery); err != nil {
		return nil, err
	}

	// 6. Read the response message.
	buff := make([]byte, queryMaxResponseSizeUDP)
	count, err := conn.Read(buff)
	if err != nil {
		return nil, err
	}
	rawResp := buff[:count]

	// 7. Parse the response and possibly log that we received it.
	respMsg := new(dns.Msg)
	if err := respMsg.Unpack(rawResp); err != nil {
		return nil, err
	}
	return NewResponse(queryMsg, respMsg)
}

// ExchangeAndCollectDuplicates is like [*UDPExchanger.Exchange] but
// collects duplicate responses for the provided query. This method is useful
// for internet censorship measurements. State-level infrastructure such as
// China's Great Firewall inject bogus responses but do not block the
// actual response from the legitimate DNS server. This method can also
// be useful to detect misconfigurations and packet duplication.
//
// This method collects responses in a loop until the deadline set
// in the provided context is done. To prevent the code to loop forever
// when no context deadline or cancellation is in place, we configure
// a default deadline of one minute just in case.
//
// An error return value indicates one of the following conditions:
//
//  1. failure to serialize the query
//
//  2. failure to send the query
//
//  3. no responses received an recv error
//
// If we receive garbage or completely invalid DNS responses, we just
// swallow the error. Typically, this does not happen when measuring
// censorship. If you wrap the connection by providing a custom dialer,
// you will have access to this additional information anyway.
func (ue *UDPExchanger) ExchangeAndCollectDuplicates(
	ctx context.Context, query *Query) ([]*Response, error) {
	// 1. create the connection
	conn, err := ue.Dialer.DialContext(ctx, "udp", ue.Endpoint)
	if err != nil {
		return nil, err
	}

	// 2. Use a single connection for request, which is what the standard library
	// does as well for and is more robust in terms of residual censorship.
	//
	// Make sure we react to context being canceled early.
	//
	// Ensure we have a default long deadline just to avoid running ~forever.
	const defaultLongDeadline = time.Minute
	ctx, cancel := context.WithTimeout(ctx, defaultLongDeadline)
	defer cancel()
	go func() {
		defer conn.Close()
		<-ctx.Done()
	}()

	// 3. Use the context deadline to limit the query lifetime
	// as documented in the [*Transport.Query] function.
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	// 4. Mutate and serialize the query.
	query = query.Clone()
	query.id = dns.Id()
	query.maxSize = queryMaxResponseSizeUDP
	queryMsg, err := query.NewMsg()
	if err != nil {
		return nil, err
	}
	rawQuery, err := queryMsg.Pack()
	if err != nil {
		return nil, err
	}

	// 5. Send the query.
	if _, err := conn.Write(rawQuery); err != nil {
		return nil, err
	}

	// 6. loop collecting responses.
	var respv []*Response
	for {
		// 6.1. Read the response message.
		buff := make([]byte, queryMaxResponseSizeUDP)
		count, err := conn.Read(buff)
		if err != nil {
			expectedErr := errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrDeadlineExceeded)
			if len(respv) > 0 && expectedErr {
				err = nil // swallow error when close or i/o timeout interrupt us
			}
			return respv, err
		}
		rawResp := buff[:count]

		// 6.2. Parse the response
		respMsg := new(dns.Msg)
		if err := respMsg.Unpack(rawResp); err != nil {
			continue
		}
		resp, err := NewResponse(queryMsg, respMsg)
		if err != nil {
			continue
		}
		respv = append(respv, resp)
	}
}
