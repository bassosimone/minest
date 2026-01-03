// SPDX-License-Identifier: GPL-3.0-or-later

package minest

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/bassosimone/dnscodec"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type connStub struct {
	read        func([]byte) (int, error)
	write       func([]byte) (int, error)
	close       func() error
	localAddr   func() net.Addr
	remoteAddr  func() net.Addr
	setDeadline func(time.Time) error
	setReadDead func(time.Time) error
	setWriteDea func(time.Time) error
}

func (cs connStub) Read(b []byte) (int, error) {
	return cs.read(b)
}

func (cs connStub) Write(b []byte) (int, error) {
	return cs.write(b)
}

func (cs connStub) Close() error {
	return cs.close()
}

func (cs connStub) LocalAddr() net.Addr {
	return cs.localAddr()
}

func (cs connStub) RemoteAddr() net.Addr {
	return cs.remoteAddr()
}

func (cs connStub) SetDeadline(t time.Time) error {
	return cs.setDeadline(t)
}

func (cs connStub) SetReadDeadline(t time.Time) error {
	return cs.setReadDead(t)
}

func (cs connStub) SetWriteDeadline(t time.Time) error {
	return cs.setWriteDea(t)
}

func TestDNSOverUDPTransportExchangeDialFailure(t *testing.T) {
	expectedErr := errors.New("dial failure")
	transport := NewDNSOverUDPTransport(netDialerStub{
		dialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, expectedErr
		},
	}, netip.MustParseAddrPort("127.0.0.1:53"))
	_, err := transport.Exchange(context.Background(), dnscodec.NewQuery("example.com", dns.TypeA))
	require.ErrorIs(t, err, expectedErr)
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
			conn:  connStub{},
		},

		{
			name:  "query too large",
			query: dnscodec.NewQuery(strings.Repeat("a", 64)+".example.com", dns.TypeA),
			conn:  connStub{},
		},

		{
			name:  "write error",
			query: dnscodec.NewQuery("example.com", dns.TypeA),
			conn: connStub{
				write: func([]byte) (int, error) {
					return 0, writeErr
				},
			},
			wantErr: writeErr,
		},
	}

	transport := NewDNSOverUDPTransport(netDialerStub{}, netip.MustParseAddrPort("127.0.0.1:53"))
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

	transport := NewDNSOverUDPTransport(netDialerStub{}, netip.MustParseAddrPort("127.0.0.1:53"))
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := transport.RecvResponse(context.Background(), connStub{
				read: tc.read,
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
			conn:  connStub{},
		},

		{
			name:  "query too large",
			query: dnscodec.NewQuery(strings.Repeat("a", 64)+".example.com", dns.TypeA),
			conn:  connStub{},
		},

		{
			name:  "write error",
			query: dnscodec.NewQuery("example.com", dns.TypeA),
			conn: connStub{
				write: func([]byte) (int, error) {
					return 0, writeErr
				},
			},
			wantErr: writeErr,
		},

		{
			name:  "read error",
			query: dnscodec.NewQuery("example.com", dns.TypeA),
			conn: connStub{
				write: func(b []byte) (int, error) {
					return len(b), nil
				},
				read: func([]byte) (int, error) {
					return 0, readErr
				},
			},
			wantErr: readErr,
		},
	}

	txp := NewDNSOverUDPTransport(netDialerStub{}, netip.MustParseAddrPort("127.0.0.1:53"))
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
