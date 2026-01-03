//
// SPDX-License-Identifier: BSD-3-Clause
//
// Adapted from: https://github.com/rbmk-project/rbmk/blob/v0.17.0/pkg/dns/dnscore/dotcp.go
// Adapted from: https://github.com/ooni/probe-engine/blob/v0.23.0/netx/resolver/dnsovertcp.go
//

package dmi

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"math"
	"net"

	"github.com/bassosimone/dnscodec"
	"github.com/bassosimone/runtimex"
	"github.com/miekg/dns"
)

// StreamDialer abstracts over [*net.Dialer].
type StreamDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// StreamExchanger implements [ClientExchanger] for DNS over TCP and TLS.
//
// Construct using [NewStreamExchanger].
type StreamExchanger struct {
	// Dialer is the StreamDialer to use to query.
	//
	// Set by [NewStreamExchanger] to the user-provided value.
	Dialer StreamDialer

	// Endpoint is the server endpoint to use to query.
	//
	// Set by [NewStreamExchanger] to the user-provided value.
	Endpoint string
}

// NewStreamExchanger creates a new [*StreamExchanger].
func NewStreamExchanger(dialer StreamDialer, endpoint string) *StreamExchanger {
	return &StreamExchanger{
		Dialer:   dialer,
		Endpoint: endpoint,
	}
}

// Ensure that [*StreamExchanger] implements [ClientExchanger].
var _ ClientExchanger = &StreamExchanger{}

// streamConnectionStater abstracts over [*tls.Conn].
type streamConnectionStater interface {
	ConnectionState() tls.ConnectionState
}

// Exchange implements [ClientExchanger].
func (se *StreamExchanger) Exchange(ctx context.Context, query *dnscodec.Query) (*dnscodec.Response, error) {
	// 1. create the connection
	conn, err := se.Dialer.DialContext(ctx, "tcp", se.Endpoint)
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
	if _, ok := conn.(streamConnectionStater); ok {
		query.Flags |= dnscodec.QueryFlagBlockLengthPadding | dnscodec.QueryFlagDNSSec
	}
	query.ID = dns.Id()
	query.MaxSize = dnscodec.QueryMaxResponseSizeTCP
	queryMsg, err := query.NewMsg()
	if err != nil {
		return nil, err
	}
	rawQuery, err := queryMsg.Pack()
	if err != nil {
		return nil, err
	}

	// 5. Wrap the query into a frame
	rawQueryFrame, err := newStreamMsgFrame(rawQuery)
	if err != nil {
		return nil, err
	}

	// 6. Send the query.
	if _, err := conn.Write(rawQueryFrame); err != nil {
		return nil, err
	}

	// 7. Wrap the conn to avoid issuing too many reads
	// then read the response header and message
	br := bufio.NewReader(conn)
	header := make([]byte, 2)
	if _, err := io.ReadFull(br, header); err != nil {
		return nil, err
	}
	length := int(header[0])<<8 | int(header[1])
	rawResp := make([]byte, length)
	if _, err := io.ReadFull(br, rawResp); err != nil {
		return nil, err
	}

	// 8. Parse the response and possibly log that we received it.
	respMsg := new(dns.Msg)
	if err := respMsg.Unpack(rawResp); err != nil {
		return nil, err
	}
	return dnscodec.ParseResponse(queryMsg, respMsg)
}

// newStreamMsgFrame creates a new raw frame for sending a message over a stream.
func newStreamMsgFrame(rawMsg []byte) ([]byte, error) {
	runtimex.Assert(len(rawMsg) <= math.MaxUint16)
	rawMsgFrame := []byte{byte(len(rawMsg) >> 8)}
	rawMsgFrame = append(rawMsgFrame, byte(len(rawMsg)))
	rawMsgFrame = append(rawMsgFrame, rawMsg...)
	return rawMsgFrame, nil
}
