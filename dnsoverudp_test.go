// SPDX-License-Identifier: GPL-3.0-or-later

package minest

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/bassosimone/dnscodec"
	"github.com/bassosimone/netstub"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// buildRawResponseFromQuery packs a valid DNS response from a raw DNS query.
func buildRawResponseFromQuery(t *testing.T, rawQuery []byte) []byte {
	t.Helper()

	queryMsg := &dns.Msg{}
	require.NoError(t, queryMsg.Unpack(rawQuery))

	resp := &dns.Msg{}
	resp.SetReply(queryMsg)
	resp.Answer = append(resp.Answer, &dns.A{
		Hdr: dns.RR_Header{
			Name:   queryMsg.Question[0].Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    1,
		},
		A: []byte{8, 8, 8, 8},
	})
	rawResp, err := resp.Pack()
	require.NoError(t, err)

	return rawResp
}

func TestDNSOverUDPTransportExchangeDialFailure(t *testing.T) {
	expectedErr := errors.New("dial failure")
	transport := NewDNSOverUDPTransport(&netstub.FuncDialer{
		DialContextFunc: func(context.Context, string, string) (net.Conn, error) {
			return nil, expectedErr
		},
	}, netip.MustParseAddrPort("127.0.0.1:53"))
	_, err := transport.Exchange(context.Background(), dnscodec.NewQuery("example.com", dns.TypeA))
	require.ErrorIs(t, err, expectedErr)
}

func TestDNSOverUDPTransportObserveRawQuery(t *testing.T) {
	var (
		rawWritten []byte
		rawResp    []byte
		hookQuery  []byte
	)
	conn := &netstub.FuncConn{
		WriteFunc: func(b []byte) (int, error) {
			rawWritten = append([]byte{}, b...)
			rawResp = buildRawResponseFromQuery(t, rawWritten)
			return len(b), nil
		},
		ReadFunc: func(b []byte) (int, error) {
			copy(b, rawResp)
			return len(rawResp), nil
		},
	}
	transport := NewDNSOverUDPTransport(&netstub.FuncDialer{}, netip.MustParseAddrPort("127.0.0.1:53"))
	transport.ObserveRawQuery = func(p []byte) {
		hookQuery = append([]byte{}, p...)
		if len(p) > 0 {
			p[0] ^= 0xff // mutate to verify we've got a copy
		}
	}

	query := dnscodec.NewQuery("example.com", dns.TypeA)
	resp, err := transport.ExchangeWithConn(context.Background(), conn, query)

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, rawWritten, hookQuery)
}

func TestDNSOverUDPTransportObserveRawResponse(t *testing.T) {
	var (
		rawResp  []byte
		hookResp []byte
	)
	conn := &netstub.FuncConn{
		WriteFunc: func(b []byte) (int, error) {
			rawResp = buildRawResponseFromQuery(t, b)
			return len(b), nil
		},
		ReadFunc: func(b []byte) (int, error) {
			copy(b, rawResp)
			return len(rawResp), nil
		},
	}
	transport := NewDNSOverUDPTransport(&netstub.FuncDialer{}, netip.MustParseAddrPort("127.0.0.1:53"))
	transport.ObserveRawResponse = func(p []byte) {
		hookResp = append([]byte{}, p...)
		if len(p) > 0 {
			p[0] ^= 0xff // mutate to verify we've got a copy
		}
	}

	query := dnscodec.NewQuery("example.com", dns.TypeA)
	resp, err := transport.ExchangeWithConn(context.Background(), conn, query)

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, rawResp, hookResp)
}

func TestDNSOverUDPTransportSendQueryErrors(t *testing.T) {
	type testCase struct {
		// name is the subtest name.
		name string

		// query is the query to send.
		query *dnscodec.Query

		// conn is the connection to use.
		conn net.Conn

		// wantErr is the error to match, if not nil.
		wantErr error
	}

	writeErr := errors.New("write failed")

	tests := []testCase{
		{
			name:  "invalid query name",
			query: dnscodec.NewQuery("\t", dns.TypeA),
			conn:  &netstub.FuncConn{},
		},

		{
			name:  "query too large",
			query: dnscodec.NewQuery(strings.Repeat("a", 64)+".example.com", dns.TypeA),
			conn:  &netstub.FuncConn{},
		},

		{
			name:  "write error",
			query: dnscodec.NewQuery("example.com", dns.TypeA),
			conn: &netstub.FuncConn{
				WriteFunc: func([]byte) (int, error) {
					return 0, writeErr
				},
			},
			wantErr: writeErr,
		},
	}

	transport := NewDNSOverUDPTransport(&netstub.FuncDialer{}, netip.MustParseAddrPort("127.0.0.1:53"))
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := transport.SendQuery(context.Background(), tc.conn, tc.query)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				return
			}
			require.Error(t, err)
		})
	}
}

func TestDNSOverUDPTransportRecvResponseErrors(t *testing.T) {
	type testCase struct {
		// name is the subtest name.
		name string

		// read is the function used by the connection.
		read func([]byte) (int, error)

		// wantErr is the error to match, if not nil.
		wantErr error
	}

	query := dnscodec.NewQuery("example.com", dns.TypeA)
	queryMsg, err := query.NewMsg()
	require.NoError(t, err)

	invalidResp := new(dns.Msg)
	invalidResp.SetReply(queryMsg)
	invalidResp.Id = queryMsg.Id + 1
	invalidRespBytes, err := invalidResp.Pack()
	require.NoError(t, err)

	readErr := errors.New("read failed")
	tests := []testCase{
		{
			name: "read error",
			read: func([]byte) (int, error) {
				return 0, readErr
			},
			wantErr: readErr,
		},

		{
			name: "unpack error",
			read: func(b []byte) (int, error) {
				b[0] = 0xff
				return 1, nil
			},
		},

		{
			name: "invalid response",
			read: func(b []byte) (int, error) {
				copy(b, invalidRespBytes)
				return len(invalidRespBytes), nil
			},
			wantErr: dnscodec.ErrInvalidResponse,
		},
	}

	transport := NewDNSOverUDPTransport(&netstub.FuncDialer{}, netip.MustParseAddrPort("127.0.0.1:53"))
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := transport.RecvResponse(context.Background(), &netstub.FuncConn{
				ReadFunc: tc.read,
			}, queryMsg)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				return
			}
			require.Error(t, err)
		})
	}
}

func TestDNSOverUDPTransportExchangeWithConnErrors(t *testing.T) {
	type testCase struct {
		// name is the subtest name.
		name string

		// query is the query to send.
		query *dnscodec.Query

		// conn is the connection to use.
		conn net.Conn

		// wantErr is the error to match, if not nil.
		wantErr error
	}

	writeErr := errors.New("write failed")
	readErr := errors.New("read failed")

	tests := []testCase{
		{
			name:  "invalid query name",
			query: dnscodec.NewQuery("\t", dns.TypeA),
			conn:  &netstub.FuncConn{},
		},

		{
			name:  "query too large",
			query: dnscodec.NewQuery(strings.Repeat("a", 64)+".example.com", dns.TypeA),
			conn:  &netstub.FuncConn{},
		},

		{
			name:  "write error",
			query: dnscodec.NewQuery("example.com", dns.TypeA),
			conn: &netstub.FuncConn{
				WriteFunc: func([]byte) (int, error) {
					return 0, writeErr
				},
			},
			wantErr: writeErr,
		},

		{
			name:  "read error",
			query: dnscodec.NewQuery("example.com", dns.TypeA),
			conn: &netstub.FuncConn{
				WriteFunc: func(b []byte) (int, error) {
					return len(b), nil
				},
				ReadFunc: func([]byte) (int, error) {
					return 0, readErr
				},
			},
			wantErr: readErr,
		},
	}

	txp := NewDNSOverUDPTransport(&netstub.FuncDialer{}, netip.MustParseAddrPort("127.0.0.1:53"))
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := txp.ExchangeWithConn(context.Background(), tc.conn, tc.query)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				return
			}
			require.Error(t, err)
		})
	}
}
