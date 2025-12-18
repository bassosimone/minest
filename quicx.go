//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Written by @roopeshsn and @bassosimone
//
// Adapted from: https://github.com/rbmk-project/rbmk/blob/v0.17.0/pkg/dns/dnscore/doquic.go
// Adapted from: https://github.com/rbmk-project/dnscore/blob/v0.14.0/doquic.go
//

package dmi

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"sync"

	"github.com/quic-go/quic-go"
)

// QUICListenConfig abstracts over [*net.QUICListenConfig].
type QUICListenConfig interface {
	ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error)
}

// Ensure that [*net.ListenConfig] implements [QUICListenConfig].
var _ QUICListenConfig = &net.ListenConfig{}

// QUICResolver abstracts over [*net.QUICResolver].
type QUICResolver interface {
	LookupHost(ctx context.Context, name string) ([]string, error)
}

// Ensure that [*net.Resolver] implements [QUICResolver].
var _ QUICResolver = &net.Resolver{}

// QUICDialConfig allows to dial QUIC [*quicConn] connections.
//
// Make sure you fill the MANDATORY fields.
type QUICDialConfig struct {
	// ListenConfig is the OPTIONAL [ListenConfig] to use.
	//
	// The [*net.ListenConfig] implements this interface.
	//
	// If nil, we use an empty [*net.ListenConfig]
	ListenConfig QUICListenConfig

	// QUICConfig is the OPTIONAL [*quic.Config] to use.
	//
	// If nil, we use an empty config.
	QUICConfig *quic.Config

	// Resolver is the OPTIONAL [Resolver] to use.
	//
	// The [*net.Resolver] implements this interface.
	//
	// If nil, we use an empy [*net.Resolver].
	Resolver QUICResolver

	// TLSConfig is the MANDATORY [*tls.Config] to use.
	//
	// Make sure you set ServerName or InsecureSkipVerify.
	//
	// If NextProtos is not set, we set it to "doq".
	TLSConfig *tls.Config
}

// quicConn is the internal [QUICConn] implementation.
type quicConn struct {
	// Conn is the actual [*quic.Conn].
	Conn *quic.Conn

	// PacketConn is the [PacketConn] backing the [*quic.Conn].
	PacketConn net.PacketConn

	// once provides "once" semantics for close.
	once sync.Once
}

// CloseWithError implements [QUICConn].
func (c *quicConn) CloseWithError(code quic.ApplicationErrorCode, desc string) (err error) {
	c.once.Do(func() {
		err1 := c.Conn.CloseWithError(code, desc)
		err2 := c.PacketConn.Close()
		err = errors.Join(err1, err2)
	})
	return
}

// OpenStream implements [QUICConn].
func (c *quicConn) OpenStream() (QUICStream, error) {
	return c.Conn.OpenStream()
}

// DialContext dials a new [QUICConn].
//
// This method serially loops over the resolved addresses. We could implement
// happy-eyeballs in the future. For the purpose of measuring, however, we often
// times use an IP address directly, so we don't need it for now.
func (d *QUICDialConfig) DialContext(ctx context.Context, network, address string) (QUICConn, error) {
	// 1. split domain name and the port
	domain, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	// 2. resolve the domain name
	reso := d.Resolver
	if reso == nil {
		reso = &net.Resolver{}
	}
	ipAddrs, err := reso.LookupHost(ctx, domain)
	if err != nil {
		return nil, err
	}

	// 3. attempt to dial each resolved address
	errv := make([]error, 0, len(ipAddrs))
	for _, ipAddr := range ipAddrs {
		udpAddr := net.UDPAddrFromAddrPort(netip.MustParseAddrPort(net.JoinHostPort(ipAddr, port)))
		qconn, err := d.dialUDPAddr(ctx, udpAddr)
		if err != nil {
			errv = append(errv, err)
			continue
		}
		return qconn, nil
	}
	return nil, errors.Join(errv...)
}

func (d *QUICDialConfig) dialUDPAddr(ctx context.Context, addr *net.UDPAddr) (QUICConn, error) {
	// 1. Open the UDP connection for supporting QUIC
	lc := d.ListenConfig
	if lc == nil {
		lc = &net.ListenConfig{}
	}
	pconn, err := lc.ListenPacket(ctx, "udp", ":0")
	if err != nil {
		return nil, err
	}

	// 2. Establish a QUIC connection. Note that the default
	// configuration implies a 5s timeout for handshaking and
	// a 30s idle connection timeout.
	quicConfig := d.QUICConfig
	if quicConfig == nil {
		quicConfig = &quic.Config{}
	}
	tlsConfig := d.TLSConfig.Clone()
	if len(tlsConfig.NextProtos) <= 0 {
		tlsConfig.NextProtos = []string{"doq"}
	}
	txp := &quic.Transport{
		Conn: pconn,
	}
	conn, err := txp.Dial(ctx, addr, tlsConfig, quicConfig)
	if err != nil {
		pconn.Close()
		return nil, err
	}

	// 3. fill and return the [*Conn]
	qc := &quicConn{PacketConn: pconn, Conn: conn}
	return qc, nil
}
