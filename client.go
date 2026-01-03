// SPDX-License-Identifier: GPL-3.0-or-later

package dmi

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/bassosimone/dnscodec"
	"github.com/bassosimone/runtimex"
	"github.com/miekg/dns"
)

// DefaultClientTimeout is the default lookup timeout used by [*Client].
const DefaultClientTimeout = 10 * time.Second

// ClientExchanger performs a DNS messages exchange.
type ClientExchanger interface {
	Exchange(ctx context.Context, query *dnscodec.Query) (*dnscodec.Response, error)
}

// Client behaves like [*net.Resolver] but uses a custom round tripper.
//
// Construct using [NewClient].
type Client struct {
	// Exchangers are the [ClientExchanger] to use.
	//
	// Set by [NewClient] to the user-provided value.
	Exchangers []ClientExchanger

	// Timeout is the overall lookup timeout.
	//
	// Set by [NewClient] to [DefaultClientTimeout].
	Timeout time.Duration
}

// NewClient creactes a new [*Client] instance.
func NewClient(exchanger ...ClientExchanger) *Client {
	return &Client{
		Exchangers: exchanger,
		Timeout:    DefaultClientTimeout,
	}
}

// clientResponse is an asynchronous DNS response.
type clientResponse[T any] struct {
	// Err is the error or nil.
	Err error

	// Value is the value or zero.
	Value T
}

// LookupHost resolves a domain to IPv4 and IPv6 addrs.
func (c *Client) LookupHost(ctx context.Context, domain string) ([]string, error) {
	// prepare for asynchronous lookup
	ach := make(chan clientResponse[[]string], 1)
	aaaach := make(chan clientResponse[[]string], 1)
	wg := &sync.WaitGroup{}

	// async lookup A
	wg.Go(func() {
		var r clientResponse[[]string]
		r.Value, r.Err = c.LookupA(ctx, domain)
		ach <- r
	})

	// async lookup AAAA
	wg.Go(func() {
		var r clientResponse[[]string]
		r.Value, r.Err = c.LookupAAAA(ctx, domain)
		aaaach <- r
	})

	// be patient
	wg.Wait()

	// read results
	ares := <-ach
	aaaares := <-aaaach

	// merge errors if both failed
	if ares.Err != nil && aaaares.Err != nil {
		return nil, errors.Join(ares.Err, aaaares.Err)
	}

	// join addresses and deal with no data
	addrs := append(ares.Value, aaaares.Value...)
	if len(addrs) < 1 {
		return nil, dnscodec.ErrNoData
	}
	return addrs, nil
}

// LookupA resolves a domain to IPv4 addrs.
func (c *Client) LookupA(ctx context.Context, domain string) ([]string, error) {
	query := dnscodec.NewQuery(domain, dns.TypeA)
	resp, err := c.lookup(ctx, query)
	if err != nil {
		return nil, err
	}
	return resp.RecordsA()
}

// LookupAAAA resolves a domain to IPv6 addrs.
func (c *Client) LookupAAAA(ctx context.Context, domain string) ([]string, error) {
	query := dnscodec.NewQuery(domain, dns.TypeAAAA)
	resp, err := c.lookup(ctx, query)
	if err != nil {
		return nil, err
	}
	return resp.RecordsAAAA()
}

// LookupCNAME resolves a domain to its CNAME.
func (c *Client) LookupCNAME(ctx context.Context, domain string) (string, error) {
	query := dnscodec.NewQuery(domain, dns.TypeCNAME)
	resp, err := c.lookup(ctx, query)
	if err != nil {
		return "", err
	}
	cnames, err := resp.RecordsCNAME()
	if err != nil {
		return "", err
	}
	runtimex.Assert(len(cnames) > 0)
	return cnames[0], nil
}

// lookup is the function performing the actual lookup.
func (c *Client) lookup(ctx context.Context, query *dnscodec.Query) (*dnscodec.Response, error) {
	// TODO(bassosimone): wrap the error like the stdlib does, if possible.

	// Honour the configured lookup timeout
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()

	// Try with each exchanger
	errv := make([]error, 0, len(c.Exchangers))
	for _, exc := range c.Exchangers {
		if ctx.Err() != nil {
			break
		}
		resp, err := exc.Exchange(ctx, query)
		if err != nil {
			errv = append(errv, err)
			continue
		}
		return resp, nil
	}

	return nil, errors.Join(errv...)
}
