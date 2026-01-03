// SPDX-License-Identifier: GPL-3.0-or-later

// Package minest contains DNS measurement infrastructure.
//
// It contains a reasonably correct DNS resolver implementation that can be
// useful to write DNS measurement tools.
//
// The core high-level abstraction is the [*Resolver]. It is loosely compatible with
// [*net.Resolver] (including emitting errors using the same string suffixes) and
// leverages the [DNSTransport] to exchange DNS queries with servers.
//
// We implement the following DNS protocols:
//
//  1. DNS over UDP: implemented by [DNSOverUDPTransport]
//
//  2. DNS over TCP: implemented by [StreamTransport] using [*net.Dialer]
//
//  3. DNS over TLS: implemented by [StreamTransport] using [*tls.Dialer]
//
//  4. DNS over QUIC: implemented by [QUICTransport]
//
//  5. DNS over HTTPS: implemented by [HTTPSTransport]
//
//  6. DNS over HTTP/3: implemented by [HTTPSTransport] when configured with [*http3.Transport]
//
// We also implement DNS query generation with [NewQuery] and DNS response
// parsing with [NewResponse], which can be used independently.
//
// For example, to lookup A and AAAA records for a domain:
//
//	resolver := dmi.NewResolver(dmi.NewHTTPSTransport(http.DefaultClient, "https://dns.google/dns-query"))
//	addrs, err := resolver.LookupHost(context.Background(), "dns.google")
//
// The [*DNSOverUDPTransport.ExchangeAndCollectDuplicates] method allows to
// detect duplicate responses. This could only happen for UDP and usually
// is a signature of censorship (e.g., in China) or misconfiguration
// causing packets to be duplicated. Use this feature as follows:
//
//	transport := dmi.NewUDPTransport(&net.Dialer{}, "8.8.8.8:53"))
//	query := dmi.NewQuery("dns.google", dns.TypeA)
//	resps, err := transport.ExchangeAndCollectDuplicates(ctx, query)
//
// This package also contains code for testing DNS resolvers:
//
//  1. the [*Handler] and [*HandlerConfig] implement [dns.Handler] for testing.
//
//  2. the [*UDPTestServer] allows to test DNS-over-UDP.
//
// The code in this package is an evolution of code originally written for
// [github.com/ooni/probe-cli], [github.com/rbmk-project/rbmk], [github.com/ooni/netem],
// and the standard library, where the measurement specifics have been
// removed, only leaving in place the basic infrastructure to
// perform network measurements of DNS protocols.
package minest
