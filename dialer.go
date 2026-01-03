//
// SPDX-License-Identifier: BSD-3-Clause
//
// Adapted from: https://github.com/ooni/netem/blob/061c5671b52a2c064cac1de5d464bb056f7ccaa8/unetstack.go
//

package minest

import (
	"context"
	"errors"
	"net"

	"github.com/bassosimone/runtimex"
)

// DialerResolver is the resolver expected by [*Dialer].
//
// Both [*net.Resolver] and [*Resolver] implement this interface.
type DialerResolver interface {
	LookupHost(ctx context.Context, name string) ([]string, error)
}

// Dialer allows to dial [net.Conn] connections pretty much like [*net.Dialer]
// except that here we use a [NetDialer] as the dialing backend.
//
// Construct using [NewDialer].
//
// This [*Dialer] does not implement happy eyeballs and is instead very
// simple and focused on measuring network interference.
type Dialer struct {
	// reso is the resolver to use.
	reso DialerResolver

	// udialer is the underlying dialer to use.
	udialer NetDialer
}

// NewDialer creates a new [*Dialer] instance.
func NewDialer(udialer NetDialer, reso DialerResolver) *Dialer {
	return &Dialer{reso, udialer}
}

// DialContext creates a new [net.Conn] connection.
func (d *Dialer) DialContext(ctx context.Context, network string, address string) (net.Conn, error) {
	// 1. separate the domain name and the port
	name, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	// 2. resolve the domain name to IP addresses
	addrs, err := d.lookupHost(ctx, name)
	if err != nil {
		return nil, err
	}
	runtimex.Assert(len(addrs) >= 1)

	// 3. attempt to connect sequentially
	errv := make([]error, 0, len(addrs))
	for _, addr := range addrs {
		conn, err := d.udialer.DialContext(ctx, network, net.JoinHostPort(addr, port))
		if err != nil {
			errv = append(errv, err)
			continue
		}
		return conn, nil
	}

	// 4. bail if all the connect attempts failed
	return nil, errors.Join(errv...)
}

// lookupHost ensures that we short circuit IP addresses.
func (d *Dialer) lookupHost(ctx context.Context, name string) ([]string, error) {
	if net.ParseIP(name) != nil {
		return []string{name}, nil
	}
	return d.reso.LookupHost(ctx, name)
}
