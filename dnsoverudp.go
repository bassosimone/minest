//
// SPDX-License-Identifier: BSD-3-Clause
//
// Adapted from: https://github.com/rbmk-project/rbmk/blob/v0.17.0/pkg/dns/dnscore/doudp.go
// Adapted from: https://github.com/ooni/probe-engine/blob/v0.23.0/netx/resolver/dnsoverudp.go
//

package minest

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/bassosimone/dnscodec"
	"github.com/miekg/dns"
)

// NetDialer abstracts over [*net.Dialer].
type NetDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// DNSOverUDPTransport implements [DNSTransport] for DNS over UDP.
//
// Construct using [NewDNSOverUDPTransport].
type DNSOverUDPTransport struct {
	// Dialer is the [NetDialer] to use to create connections.
	//
	// Set by [NewDNSOverUDPTransport] to the user-provided value.
	Dialer NetDialer

	// Endpoint is the server endpoint to use to query.
	//
	// Set by [NewDNSOverUDPTransport] to the user-provided value.
	Endpoint netip.AddrPort

	// ObserveRawQuery is an optional hook called with a copy of the raw DNS query.
	ObserveRawQuery func([]byte)

	// ObserveRawResponse is an optional hook called with a copy of the raw DNS response.
	ObserveRawResponse func([]byte)
}

// NewDNSOverUDPTransport creates a new [*DNSOverUDPTransport].
func NewDNSOverUDPTransport(dialer NetDialer, endpoint netip.AddrPort) *DNSOverUDPTransport {
	return &DNSOverUDPTransport{
		Dialer:   dialer,
		Endpoint: endpoint,
	}
}

// Ensure that [*DNSOverUDPTransport] implements [DNSTransport].
var _ DNSTransport = &DNSOverUDPTransport{}

// Dial creates a [net.Conn] with the configured endpoint.
//
// This method enables building long-lived connections and reusing them across
// multiple exchanges via [*DNSOverUDPTransport.ExchangeWithConn].
func (dt *DNSOverUDPTransport) Dial(ctx context.Context) (net.Conn, error) {
	return dt.Dialer.DialContext(ctx, "udp", dt.Endpoint.String())
}

// Exchange implements [DNSTransport].
func (dt *DNSOverUDPTransport) Exchange(ctx context.Context, query *dnscodec.Query) (*dnscodec.Response, error) {
	// 1. create the connection
	conn, err := dt.Dial(ctx)
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

	// 3. defer to ExchangeWithConn.
	return dt.ExchangeWithConn(ctx, conn, query)
}

// SendQuery sends a [*dnscodec.Query] using a [net.Conn].
//
// We only honor deadlines from the context; canceling the context without a
// deadline does not interrupt I/O. This behavior may change in the future.
func (dt *DNSOverUDPTransport) SendQuery(ctx context.Context, conn net.Conn, query *dnscodec.Query) (*dns.Msg, error) {
	// 1. Use the context deadline to limit the lifetime.
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
		defer conn.SetDeadline(time.Time{})
	}

	// 2. Mutate and serialize the query.
	query = query.Clone()
	query.MaxSize = dnscodec.QueryMaxResponseSizeUDP
	queryMsg, err := query.NewMsg()
	if err != nil {
		return nil, err
	}
	rawQuery, err := queryMsg.Pack()
	if err != nil {
		return nil, err
	}
	if dt.ObserveRawQuery != nil {
		dt.ObserveRawQuery(bytes.Clone(rawQuery))
	}

	// 3. Send the query.
	if _, err := conn.Write(rawQuery); err != nil {
		return nil, err
	}
	return queryMsg, nil
}

// RecvResponse receives a [*dnscodec.Response] using a [net.Conn].
//
// We only honor deadlines from the context; canceling the context without a
// deadline does not interrupt I/O. This behavior may change in the future.
func (dt *DNSOverUDPTransport) RecvResponse(
	ctx context.Context, conn net.Conn, queryMsg *dns.Msg) (*dnscodec.Response, error) {
	// 1. Use the context deadline to limit the lifetime.
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
		defer conn.SetDeadline(time.Time{})
	}

	// 4. Read the response message.
	buff := make([]byte, dnscodec.QueryMaxResponseSizeUDP)
	count, err := conn.Read(buff)
	if err != nil {
		return nil, err
	}
	rawResp := buff[:count]
	if dt.ObserveRawResponse != nil {
		dt.ObserveRawResponse(bytes.Clone(rawResp))
	}

	// 5. Parse the response and possibly log that we received it.
	respMsg := new(dns.Msg)
	if err := respMsg.Unpack(rawResp); err != nil {
		return nil, err
	}
	return dnscodec.ParseResponse(queryMsg, respMsg)
}

// ExchangeWithConn sends a [*dnscodec.Query] and receives a [*dnscodec.Response].
//
// This method allows reusing a long-lived connection across multiple exchanges.
func (dt *DNSOverUDPTransport) ExchangeWithConn(ctx context.Context,
	conn net.Conn, query *dnscodec.Query) (*dnscodec.Response, error) {
	queryMsg, err := dt.SendQuery(ctx, conn, query)
	if err != nil {
		return nil, err
	}
	return dt.RecvResponse(ctx, conn, queryMsg)
}
