// SPDX-License-Identifier: GPL-3.0-or-later

package minest

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIntegrationDNSOverUDPWorks(t *testing.T) {
	if testing.Short() {
		t.Skip("skip test in short mode")
	}
	ctx := context.Background()
	resolver := NewResolver(NewDNSOverUDPTransport(&net.Dialer{}, netip.MustParseAddrPort("8.8.4.4:53")))
	addrs, err := resolver.LookupA(ctx, "dns.google")
	assert.NoError(t, err)
	slices.Sort(addrs)
	expectAddrs := []string{"8.8.4.4", "8.8.8.8"}
	assert.Equal(t, expectAddrs, addrs)
}
