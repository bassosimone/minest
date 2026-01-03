// SPDX-License-Identifier: GPL-3.0-or-later

package minest

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/bassosimone/dnscodec"
	"github.com/bassosimone/runtimex"
	"github.com/miekg/dns"
)

// DefaultResolverTimeout is the default lookup timeout used by [*Resolver].
const DefaultResolverTimeout = 10 * time.Second

// DNSTransport performs a DNS messages exchange.
type DNSTransport interface {
	Exchange(ctx context.Context, query *dnscodec.Query) (*dnscodec.Response, error)
}

// Resolver behaves like [*net.Resolver] but uses a [DNSTransport].
//
// Construct using [NewResolver].
type Resolver struct {
	// Transports are the [DNSTransport] to use.
	//
	// Set by [NewResolver] to the user-provided value.
	Transports []DNSTransport

	// Timeout is the overall lookup timeout.
	//
	// Set by [NewResolver] to [DefaultResolverTimeout].
	Timeout time.Duration
}

// NewResolver creactes a new [*Resolver] instance.
func NewResolver(transport ...DNSTransport) *Resolver {
	return &Resolver{
		Transports: transport,
		Timeout:    DefaultResolverTimeout,
	}
}

// resolverResponse is an asynchronous DNS response.
type resolverResponse[T any] struct {
	// Err is the error or nil.
	Err error

	// Value is the value or zero.
	Value T
}

// LookupHost resolves a domain to IPv4 and IPv6 addrs.
func (r *Resolver) LookupHost(ctx context.Context, domain string) ([]string, error) {
	// prepare for asynchronous lookup
	ach := make(chan resolverResponse[[]string], 1)
	aaaach := make(chan resolverResponse[[]string], 1)
	wg := &sync.WaitGroup{}

	// async lookup A
	wg.Go(func() {
		var rr resolverResponse[[]string]
		rr.Value, rr.Err = r.LookupA(ctx, domain)
		ach <- rr
	})

	// async lookup AAAA
	wg.Go(func() {
		var rr resolverResponse[[]string]
		rr.Value, rr.Err = r.LookupAAAA(ctx, domain)
		aaaach <- rr
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
func (r *Resolver) LookupA(ctx context.Context, domain string) ([]string, error) {
	query := dnscodec.NewQuery(domain, dns.TypeA)
	resp, err := r.lookup(ctx, query)
	if err != nil {
		return nil, err
	}
	return resp.RecordsA()
}

// LookupAAAA resolves a domain to IPv6 addrs.
func (r *Resolver) LookupAAAA(ctx context.Context, domain string) ([]string, error) {
	query := dnscodec.NewQuery(domain, dns.TypeAAAA)
	resp, err := r.lookup(ctx, query)
	if err != nil {
		return nil, err
	}
	return resp.RecordsAAAA()
}

// LookupCNAME resolves a domain to its CNAME.
func (r *Resolver) LookupCNAME(ctx context.Context, domain string) (string, error) {
	query := dnscodec.NewQuery(domain, dns.TypeCNAME)
	resp, err := r.lookup(ctx, query)
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
func (r *Resolver) lookup(ctx context.Context, query *dnscodec.Query) (*dnscodec.Response, error) {
	// Handle the case where there are no transports
	if len(r.Transports) <= 0 {
		return nil, errors.New("no configured transport")
	}

	// Honour the configured lookup timeout
	ctx, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()

	// Try with each transport
	errv := make([]error, 0, len(r.Transports))
	for _, exc := range r.Transports {
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

	// Assemble a composed error
	runtimex.Assert(len(errv) >= 1)
	return nil, errors.Join(errv...)
}
