// SPDX-License-Identifier: GPL-3.0-or-later

package minest

import (
	"context"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/bassosimone/dnscodec"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestIntegrationDNSOverUDPWorks(t *testing.T) {
	if testing.Short() {
		t.Skip("skip test in short mode")
	}
	ctx := context.Background()
	client := NewClient(NewUDPExchanger(&net.Dialer{}, "8.8.4.4:53"))
	addrs, err := client.LookupA(ctx, "dns.google")
	assert.NoError(t, err)
	slices.Sort(addrs)
	expectAddrs := []string{"8.8.4.4", "8.8.8.8"}
	assert.Equal(t, expectAddrs, addrs)
}

func TestIntegrationDNSOverUDPExchangeAndCollectDuplicatesWork(t *testing.T) {
	if testing.Short() {
		t.Skip("skip test in short mode")
	}
	// collect potentially duplicate responses for one second
	// note: may be flaky when run on high-latency networks
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	exchanger := NewUDPExchanger(&net.Dialer{}, "8.8.4.4:53")
	query := dnscodec.NewQuery("dns.google", dns.TypeA)
	resps, err := exchanger.ExchangeAndCollectDuplicates(ctx, query)
	assert.NoError(t, err)
	assert.True(t, len(resps) >= 1)
}
