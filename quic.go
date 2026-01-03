//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Written by @roopeshsn and @bassosimone
//
// Adapted from: https://github.com/rbmk-project/rbmk/blob/v0.17.0/pkg/dns/dnscore/doquic.go
// Adapted from: https://github.com/rbmk-project/dnscore/blob/v0.14.0/doquic.go
//
// See https://github.com/rbmk-project/dnscore/pull/18
//
// See https://datatracker.ietf.org/doc/rfc9250/
//

package dmi

import (
	"bufio"
	"context"
	"io"
	"time"

	"github.com/bassosimone/dnscodec"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// QUICDialer dials [QUICConn] connections for DoQ.
//
// The [*QUICDialConfig] type implements this interface.
type QUICDialer interface {
	DialContext(ctx context.Context, network, address string) (QUICConn, error)
}

// QUICStream is an abstract QUIC stream suitble for DoQ operations.
//
// Construct using [QUICConn.OpenStream].
type QUICStream interface {
	SetDeadline(t time.Time) error
	io.ReadWriteCloser
}

// QUICConn is an abstract QUIC connection suitable for DoQ operations.
//
// Construct using [*QUICDialer.DialContext].
type QUICConn interface {
	// CloseWithError closes the QUIC connection with an error
	CloseWithError(code quic.ApplicationErrorCode, desc string) error

	// OpenStream opens a new stream over the connection.
	OpenStream() (QUICStream, error)
}

// QUICExchanger implements [ClientExchanger] for DNS over QUIC.
//
// Construct using [NewQUICExchanger].
type QUICExchanger struct {
	// Dialer is the [*QUICDialer] to use to query.
	//
	// Set by [NewQUICExchanger] to the user-provided value.
	Dialer QUICDialer

	// Endpoint is the server endpoint to use to query.
	//
	// Set by [NewQUICExchanger] to the user-provided value.
	Endpoint string
}

// NewQUICExchanger creates a new [*QUICExchanger].
func NewQUICExchanger(dialer QUICDialer, endpoint string) *QUICExchanger {
	return &QUICExchanger{
		Dialer:   dialer,
		Endpoint: endpoint,
	}
}

// Ensure that [*QUICExchanger] implements [ClientExchanger].
var _ ClientExchanger = &QUICExchanger{}

// Exchange implements [ClientExchanger].
func (qe *QUICExchanger) Exchange(ctx context.Context, query *dnscodec.Query) (*dnscodec.Response, error) {
	// 1. create the connection
	conn, err := qe.Dialer.DialContext(ctx, "udp", qe.Endpoint)
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
		// Closing w/o specific error -- RFC 9250 Sect. 4.3
		const quicNoError = 0x00
		<-ctx.Done()
		conn.CloseWithError(quicNoError, "")
	}()

	// 3. Open a stream for sending the DoQ query.
	stream, err := conn.OpenStream()
	if err != nil {
		return nil, err
	}
	defer stream.Close()

	// 4. Use the context deadline to limit the query lifetime
	// as documented in the [*Transport.Query] function.
	if deadline, ok := ctx.Deadline(); ok {
		_ = stream.SetDeadline(deadline)
	}

	// 5. Mutate and serialize the query.
	//
	// For DoQ, by default we leave the query ID to zero, which
	// is what the RFC requires to do.
	query = query.Clone()
	query.Flags |= dnscodec.QueryFlagBlockLengthPadding | dnscodec.QueryFlagDNSSec
	query.ID = 0
	query.MaxSize = dnscodec.QueryMaxResponseSizeTCP
	queryMsg, err := query.NewMsg()
	if err != nil {
		return nil, err
	}
	rawQuery, err := queryMsg.Pack()
	if err != nil {
		return nil, err
	}

	// 6. Wrap the query into a frame
	rawQueryFrame, err := newStreamMsgFrame(rawQuery)
	if err != nil {
		return nil, err
	}

	// 7. Send the query.
	if _, err := stream.Write(rawQueryFrame); err != nil {
		return nil, err
	}

	// 8. Ensure we close the stream when using DoQ to signal the
	// upstream server that it is okay to send a response.
	//
	// RFC 9250 is very clear in this respect:
	//
	//	4.2.  Stream Mapping and Usage
	//	client MUST send the DNS query over the selected stream and MUST
	//	indicate through the STREAM FIN mechanism that no further data will
	//	be sent on that stream.
	//
	// Empirical testing during https://github.com/rbmk-project/dnscore/pull/18
	// showed that, in fact, some servers misbehave if we don't do this.
	stream.Close()

	// 9. Wrap the conn to avoid issuing too many reads
	// then read the response header and message
	br := bufio.NewReader(stream)
	header := make([]byte, 2)
	if _, err := io.ReadFull(br, header); err != nil {
		return nil, err
	}
	length := int(header[0])<<8 | int(header[1])
	rawResp := make([]byte, length)
	if _, err := io.ReadFull(br, rawResp); err != nil {
		return nil, err
	}

	// 10. Parse the response and possibly log that we received it.
	respMsg := new(dns.Msg)
	if err := respMsg.Unpack(rawResp); err != nil {
		return nil, err
	}
	return dnscodec.ParseResponse(queryMsg, respMsg)
}
