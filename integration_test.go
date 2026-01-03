// SPDX-License-Identifier: GPL-3.0-or-later

package minest_test

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"testing"

	"github.com/bassosimone/minest"
	"github.com/stretchr/testify/assert"
)

func TestIntegrationDNSOverUDPWorks(t *testing.T) {
	ctx := context.Background()
	dialer := minest.NewDialer(&net.Dialer{}, &net.Resolver{})
	txp := minest.NewDNSOverUDPTransport(dialer, netip.MustParseAddrPort("8.8.4.4:53"))
	reso := minest.NewResolver(txp)
	addrs, err := reso.LookupA(ctx, "dns.google")
	assert.NoError(t, err)
	slices.Sort(addrs)
	expectAddrs := []string{"8.8.4.4", "8.8.8.8"}
	assert.Equal(t, expectAddrs, addrs)
}
