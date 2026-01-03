// SPDX-License-Identifier: GPL-3.0-or-later

// Package minest implements a minimal network stack.
//
// The [*Dialer] and [*Resolver] types are like [*net.Dialer] and [*net.Resolver] but
// depend on interfaces. This design choice allows to use multiple network backends
// (including, e.g., [github.com/bassosimone/uis] as the backend), with the most typical
// backend being the standard library itself.
//
// The [*Resolver] depends on [NetDialer], which is an interface implemented by
// both [*net.Dialer] and [*Dialer]. The [*Dialer] depend on [NetDialer] and
// [DialerResolver], which is an interface implemented by both [*net.Resolver]
// and [Resolver].
//
// A [*Resolver] also depends on a [DNSTransport]. This package includes
// [DNSOverUDPTransport], which implements [DNSTransport] for DNS-over-UDP
// but you can also use [github.com/bassosimone/dnsoverhttps] and
// [github.com/bassosimone/dnsoverstream] as transports. Thus, the [*Resolver]
// can query using DNS over UDP, TCP, TLS, QUIC, HTTPS, and HTTP3.
//
// This package focuses on measuring the internet, therefore it is optimized
// for simplicity and does not implement performance optimizations such as
// happy eyeballs inside its [*Dialer].
package minest
