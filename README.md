# Golang Minimal Network Stack

[![GoDoc](https://pkg.go.dev/badge/github.com/bassosimone/minest)](https://pkg.go.dev/github.com/bassosimone/minest) [![Build Status](https://github.com/bassosimone/minest/actions/workflows/go.yml/badge.svg)](https://github.com/bassosimone/minest/actions) [![codecov](https://codecov.io/gh/bassosimone/minest/branch/main/graph/badge.svg)](https://codecov.io/gh/bassosimone/minest)

The `minest` Go package implements a minimal network stack with a DNS
resolver that can be wired to the standard library or to
[bassosimone/uis](https://github.com/bassosimone/uis/), thus enabling to
write integration tests using TCP in userspace.

Basic usage is like:

```Go
import (
	"context"
	"log"
	"net"
	"net/netip"

	"github.com/bassosimone/minest"
)

ctx := context.Background()

// Create and use a dialer using the standard library
dialer1 := minest.NewDialer(&net.Dialer{}, &net.Resolver{})
conn1, err := dialer1.DialContext(ctx, "tcp", "8.8.8.8:443")

// Create a DNS-over-UDP resolver using the dialer to create connections
txp := minest.NewDNSOverUDPTransport(dialer1, netip.MustParseAddrPort("8.8.4.4:53"))
reso := minest.NewResolver(txp)
addrs, err := reso.LookupA(ctx, "dns.google")

// Create a second dialer using the above resolver
dialer2 := minest.NewDialer(&net.Dialer{}, reso)
conn2, err := dialer2.DialContext(ctx, "tcp", "8.8.8.8:443")
```

The `Resolver` type depends on a `DNSTransport` that is not only compatible
with the `DNSOverUDPTransport` type but also with the transports in:

- [github.com/bassosimone/dnsoverhttps](https://github.com/bassosimone/dnsoverhttps)

- [github.com/bassosimone/dnsoverstream](https://github.com/bassosimone/dnsoverstream)

Therefore, the `Resolver` can use DNS over UDP, TCP, TLS, QUIC, HTTPS and HTTP3.

## Installation

To add this package as a dependency to your module:

```sh
go get github.com/bassosimone/minest
```

## Development

To run the tests:

```sh
go test -v .
```

To measure test coverage:

```sh
go test -v -cover .
```

## License

```
SPDX-License-Identifier: GPL-3.0-or-later
```

## History

Adapted from [rbmk-project/rbmk](https://github.com/rbmk-project/rbmk/tree/v0.17.0)
and [ooni/netem](https://github.com/ooni/netem).
