// SPDX-License-Identifier: GPL-3.0-or-later

package dmi

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/assert"
)

func TestDNSOverHTTPSWorks(t *testing.T) {
	if testing.Short() {
		t.Skip("skip test in short mode")
	}
	ctx := context.Background()
	client := NewClient(NewHTTPSExchanger(http.DefaultClient, "https://dns.google/dns-query"))
	addrs, err := client.LookupA(ctx, "dns.google")
	assert.NoError(t, err)
	slices.Sort(addrs)
	expectAddrs := []string{"8.8.4.4", "8.8.8.8"}
	assert.Equal(t, expectAddrs, addrs)
}

func TestDNSOverHTTP3Works(t *testing.T) {
	if testing.Short() {
		t.Skip("skip test in short mode")
	}
	ctx := context.Background()
	httpClient := &http.Client{
		Transport: &http3.Transport{},
	}
	client := NewClient(NewHTTPSExchanger(httpClient, "https://dns.google/dns-query"))
	addrs, err := client.LookupA(ctx, "dns.google")
	assert.NoError(t, err)
	slices.Sort(addrs)
	expectAddrs := []string{"8.8.4.4", "8.8.8.8"}
	assert.Equal(t, expectAddrs, addrs)
}

func TestDNSOverUDPWorks(t *testing.T) {
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

func TestDNSOverUDPExchangeAndCollectDuplicatesWork(t *testing.T) {
	if testing.Short() {
		t.Skip("skip test in short mode")
	}
	// collect potentially duplicate responses for one second
	// note: may be flaky when run on high-latency networks
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	exchanger := NewUDPExchanger(&net.Dialer{}, "8.8.4.4:53")
	query := NewQuery("dns.google", dns.TypeA)
	resps, err := exchanger.ExchangeAndCollectDuplicates(ctx, query)
	assert.NoError(t, err)
	assert.True(t, len(resps) >= 1)
}

func TestDNSOverTCPWorks(t *testing.T) {
	if testing.Short() {
		t.Skip("skip test in short mode")
	}
	ctx := context.Background()
	client := NewClient(NewStreamExchanger(&net.Dialer{}, "8.8.4.4:53"))
	addrs, err := client.LookupA(ctx, "dns.google")
	assert.NoError(t, err)
	slices.Sort(addrs)
	expectAddrs := []string{"8.8.4.4", "8.8.8.8"}
	assert.Equal(t, expectAddrs, addrs)
}

func TestDNSOverTLSWorks(t *testing.T) {
	if testing.Short() {
		t.Skip("skip test in short mode")
	}
	ctx := context.Background()
	tlsDialer := &tls.Dialer{
		NetDialer: &net.Dialer{},
		Config: &tls.Config{
			ServerName: "dns.google",
		},
	}
	client := NewClient(NewStreamExchanger(tlsDialer, "8.8.4.4:853"))
	addrs, err := client.LookupA(ctx, "dns.google")
	assert.NoError(t, err)
	slices.Sort(addrs)
	expectAddrs := []string{"8.8.4.4", "8.8.8.8"}
	assert.Equal(t, expectAddrs, addrs)
}

func TestDNSOverQUICWorks(t *testing.T) {
	if testing.Short() {
		t.Skip("skip test in short mode")
	}
	ctx := context.Background()
	quicDialer := &QUICDialConfig{
		TLSConfig: &tls.Config{
			ServerName: "dns.adguard.com",
		},
	}
	client := NewClient(NewQUICExchanger(quicDialer, "dns.adguard.com:853"))
	addrs, err := client.LookupA(ctx, "dns.google")
	assert.NoError(t, err)
	slices.Sort(addrs)
	expectAddrs := []string{"8.8.4.4", "8.8.8.8"}
	assert.Equal(t, expectAddrs, addrs)
}
