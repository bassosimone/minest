// SPDX-License-Identifier: GPL-3.0-or-later

package minest

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/bassosimone/netstub"
	"github.com/stretchr/testify/require"
)

func TestDialerSplitHostPortFailure(t *testing.T) {
	dialer := NewDialer(&netstub.FuncDialer{}, &netstub.FuncResolver{})
	_, err := dialer.DialContext(context.Background(), "tcp", "bad-address")
	require.Error(t, err)
}

func TestDialerLookupHostFailure(t *testing.T) {
	expectedErr := errors.New("lookup failed")
	resolver := &netstub.FuncResolver{
		LookupHostFunc: func(context.Context, string) ([]string, error) {
			return nil, expectedErr
		},
	}
	dialer := NewDialer(&netstub.FuncDialer{}, resolver)
	_, err := dialer.DialContext(context.Background(), "tcp", "example.com:80")
	require.ErrorIs(t, err, expectedErr)
}

func TestDialerSequentialConnectFailure(t *testing.T) {
	expectedErr := errors.New("dial failed")
	resolver := &netstub.FuncResolver{
		LookupHostFunc: func(context.Context, string) ([]string, error) {
			return []string{"203.0.113.1", "203.0.113.2"}, nil
		},
	}
	dialer := NewDialer(&netstub.FuncDialer{
		DialContextFunc: func(context.Context, string, string) (net.Conn, error) {
			return nil, expectedErr
		},
	}, resolver)
	_, err := dialer.DialContext(context.Background(), "tcp", "example.com:80")
	require.ErrorIs(t, err, expectedErr)
}

func TestDialerShortCircuitIPLiteral(t *testing.T) {
	var (
		gotNetwork string
		gotAddr    string
	)
	dialer := NewDialer(&netstub.FuncDialer{
		DialContextFunc: func(context.Context, string, string) (net.Conn, error) {
			gotNetwork = "tcp"
			gotAddr = "203.0.113.7:80"
			return nil, errors.New("dial failed")
		},
	}, &netstub.FuncResolver{})
	_, _ = dialer.DialContext(context.Background(), "tcp", "203.0.113.7:80")
	require.Equal(t, "tcp", gotNetwork)
	require.Equal(t, "203.0.113.7:80", gotAddr)
}
