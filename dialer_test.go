// SPDX-License-Identifier: GPL-3.0-or-later

package minest

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

type resolverStub struct {
	lookupHost func(context.Context, string) ([]string, error)
}

func (rs resolverStub) LookupHost(ctx context.Context, name string) ([]string, error) {
	return rs.lookupHost(ctx, name)
}

type netDialerStub struct {
	dialContext func(context.Context, string, string) (net.Conn, error)
}

func (nds netDialerStub) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return nds.dialContext(ctx, network, address)
}

func TestDialerSplitHostPortFailure(t *testing.T) {
	dialer := NewDialer(netDialerStub{}, resolverStub{})
	_, err := dialer.DialContext(context.Background(), "tcp", "bad-address")
	require.Error(t, err)
}

func TestDialerLookupHostFailure(t *testing.T) {
	expectedErr := errors.New("lookup failed")
	resolver := resolverStub{
		lookupHost: func(context.Context, string) ([]string, error) {
			return nil, expectedErr
		},
	}
	dialer := NewDialer(netDialerStub{}, resolver)
	_, err := dialer.DialContext(context.Background(), "tcp", "example.com:80")
	require.ErrorIs(t, err, expectedErr)
}

func TestDialerSequentialConnectFailure(t *testing.T) {
	expectedErr := errors.New("dial failed")
	resolver := resolverStub{
		lookupHost: func(context.Context, string) ([]string, error) {
			return []string{"203.0.113.1", "203.0.113.2"}, nil
		},
	}
	dialer := NewDialer(netDialerStub{
		dialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, expectedErr
		},
	}, resolver)
	_, err := dialer.DialContext(context.Background(), "tcp", "example.com:80")
	require.ErrorIs(t, err, expectedErr)
}
