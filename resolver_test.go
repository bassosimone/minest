// SPDX-License-Identifier: GPL-3.0-or-later

package minest

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"testing"

	"github.com/bassosimone/dnscodec"
	"github.com/bassosimone/dnstest"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newResolver creates a resolver backed by a UDP test server.
func newResolver(t *testing.T, handler *dnstest.Handler) *Resolver {
	t.Helper()

	server := dnstest.MustNewUDPServer(&net.ListenConfig{}, "127.0.0.1:0", handler)
	t.Cleanup(server.Close)

	endpoint, err := netip.ParseAddrPort(server.Address())
	require.NoError(t, err)
	return NewResolver(NewDNSOverUDPTransport(&net.Dialer{}, endpoint))
}

// lookupA returns a lookup function for A records.
func lookupA(domain string) func(*Resolver, context.Context) ([]string, error) {
	return func(r *Resolver, ctx context.Context) ([]string, error) {
		return r.LookupA(ctx, domain)
	}
}

// lookupAAAA returns a lookup function for AAAA records.
func lookupAAAA(domain string) func(*Resolver, context.Context) ([]string, error) {
	return func(r *Resolver, ctx context.Context) ([]string, error) {
		return r.LookupAAAA(ctx, domain)
	}
}

// lookupCNAME returns a lookup function for CNAME records.
func lookupCNAME(domain string) func(*Resolver, context.Context) ([]string, error) {
	return func(r *Resolver, ctx context.Context) ([]string, error) {
		cname, err := r.LookupCNAME(ctx, domain)
		if err != nil {
			return nil, err
		}
		return []string{cname}, nil
	}
}

// lookupHost returns a lookup function for A and AAAA records.
func lookupHost(domain string) func(*Resolver, context.Context) ([]string, error) {
	return func(r *Resolver, ctx context.Context) ([]string, error) {
		return r.LookupHost(ctx, domain)
	}
}

type transportStub struct {
	exchange func(context.Context, *dnscodec.Query) (*dnscodec.Response, error)
}

func (ts transportStub) Exchange(ctx context.Context, query *dnscodec.Query) (*dnscodec.Response, error) {
	return ts.exchange(ctx, query)
}

func TestResolverLookupSuccess(t *testing.T) {

	type testCase struct {
		// name is the subtest name.
		name string

		// setup configures the handler records.
		setup func(*dnstest.HandlerConfig)

		// lookup runs the resolver method under test.
		lookup func(*Resolver, context.Context) ([]string, error)

		// want contains the expected results.
		want []string
	}

	// sortedStrings returns a sorted copy of the input.
	sortedStrings := func(in []string) []string {
		out := slices.Clone(in)
		slices.Sort(out)
		return out
	}

	tests := []testCase{
		{
			name: "LookupA success",
			setup: func(config *dnstest.HandlerConfig) {
				config.AddNetipAddr("example.com", netip.MustParseAddr("93.184.216.34"))
			},
			lookup: lookupA("example.com"),
			want:   []string{"93.184.216.34"},
		},

		{
			name: "LookupAAAA success",
			setup: func(config *dnstest.HandlerConfig) {
				config.AddNetipAddr("example.com", netip.MustParseAddr("2001:db8::1"))
			},
			lookup: lookupAAAA("example.com"),
			want:   []string{"2001:db8::1"},
		},

		{
			name: "LookupCNAME success",
			setup: func(config *dnstest.HandlerConfig) {
				config.AddCNAME("www.example.com", "example.com")
				config.AddNetipAddr("example.com", netip.MustParseAddr("93.184.216.34"))
			},
			lookup: lookupCNAME("www.example.com"),
			want:   []string{"example.com."},
		},

		{
			name: "LookupHost success",
			setup: func(config *dnstest.HandlerConfig) {
				config.AddCNAME("www.example.com", "example.com")
				config.AddNetipAddr("example.com", netip.MustParseAddr("93.184.216.34"))
				config.AddNetipAddr("example.com", netip.MustParseAddr("2001:db8::1"))
			},
			lookup: lookupHost("www.example.com"),
			want:   []string{"2001:db8::1", "93.184.216.34"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config := dnstest.NewHandlerConfig()
			tc.setup(config)
			reso := newResolver(t, dnstest.NewHandler(config))
			got, err := tc.lookup(reso, context.Background())
			require.NoError(t, err)
			assert.Equal(t, sortedStrings(tc.want), sortedStrings(got))
		})
	}
}

func TestResolverLookupNXDOMAIN(t *testing.T) {

	type testCase struct {
		// name is the subtest name.
		name string

		// lookup runs the resolver method under test.
		lookup func(*Resolver, context.Context) ([]string, error)
	}

	tests := []testCase{
		{
			name:   "LookupA NXDOMAIN",
			lookup: lookupA("example.com"),
		},

		{
			name:   "LookupAAAA NXDOMAIN",
			lookup: lookupAAAA("example.com"),
		},

		{
			name:   "LookupCNAME NXDOMAIN",
			lookup: lookupCNAME("www.example.com"),
		},

		{
			name:   "LookupHost NXDOMAIN",
			lookup: lookupHost("www.example.com"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config := dnstest.NewHandlerConfig()
			reso := newResolver(t, dnstest.NewHandler(config))
			got, err := tc.lookup(reso, context.Background())
			require.Error(t, err)
			assert.Empty(t, got)
		})
	}
}

func TestResolverLookupNoAnswer(t *testing.T) {

	type testCase struct {
		// name is the subtest name.
		name string

		// setup configures the handler records.
		setup func(*dnstest.HandlerConfig)

		// lookup runs the resolver method under test.
		lookup func(*Resolver, context.Context) ([]string, error)
	}

	tests := []testCase{
		{
			name: "LookupA no answer",
			setup: func(config *dnstest.HandlerConfig) {
				config.AddNetipAddr("example.com", netip.MustParseAddr("2001:db8::1"))
			},
			lookup: lookupA("example.com"),
		},

		{
			name: "LookupAAAA no answer",
			setup: func(config *dnstest.HandlerConfig) {
				config.AddNetipAddr("example.com", netip.MustParseAddr("93.184.216.34"))
			},
			lookup: lookupAAAA("example.com"),
		},

		{
			name: "LookupCNAME no answer",
			setup: func(config *dnstest.HandlerConfig) {
				config.AddNetipAddr("www.example.com", netip.MustParseAddr("93.184.216.34"))
			},
			lookup: lookupCNAME("www.example.com"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config := dnstest.NewHandlerConfig()
			tc.setup(config)
			reso := newResolver(t, dnstest.NewHandler(config))
			got, err := tc.lookup(reso, context.Background())
			require.Error(t, err)
			assert.ErrorIs(t, err, dnscodec.ErrNoData)
			assert.Empty(t, got)
		})
	}
}

func TestResolverLookupCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	config := dnstest.NewHandlerConfig()
	reso := newResolver(t, dnstest.NewHandler(config))
	addrs, err := reso.LookupHost(ctx, "example.com")
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, addrs)
}

func TestResolverLookupNoTransport(t *testing.T) {
	reso := NewResolver()
	addrs, err := reso.LookupHost(context.Background(), "example.com")
	require.Error(t, err)
	assert.Empty(t, addrs)
}

func TestResolverLookupCNAMEWithOnlyARecords(t *testing.T) {
	// We need a stubbed transport to model a misbehaving server that
	// returns A records to a CNAME query, which the dnstest handler
	// cannot generate. Note that an A response to a CNAME query could
	// for example happen with bad censorship equipment.
	query := dnscodec.NewQuery("example.com", dns.TypeCNAME)
	query.ID = 1
	queryMsg, err := query.NewMsg()
	require.NoError(t, err)

	respMsg := new(dns.Msg)
	respMsg.SetReply(queryMsg)
	respMsg.Answer = append(respMsg.Answer, &dns.A{
		Hdr: dns.RR_Header{
			Name:   queryMsg.Question[0].Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    60,
		},
		A: netip.MustParseAddr("93.184.216.34").AsSlice(),
	})

	resp, err := dnscodec.ParseResponse(queryMsg, respMsg)
	require.NoError(t, err)

	reso := NewResolver(transportStub{
		exchange: func(context.Context, *dnscodec.Query) (*dnscodec.Response, error) {
			return resp, nil
		},
	})

	cname, err := reso.LookupCNAME(context.Background(), "example.com")
	require.ErrorIs(t, err, dnscodec.ErrNoData)
	assert.Empty(t, cname)
}
