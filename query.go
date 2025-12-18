//
// SPDX-License-Identifier: BSD-3-Clause
//
// Adapted from: https://github.com/ooni/probe-engine/blob/v0.23.0/netx/resolver/encoder.go
// Adapted from: https://github.com/rbmk-project/rbmk/blob/v0.17.0/pkg/dns/dnscore/query.go
//

package dmi

import (
	"github.com/miekg/dns"
	"golang.org/x/net/idna"
)

const (
	// queryFlagBlockLengthPadding enables using RFC8467 block lengthpadding.
	queryFlagBlockLengthPadding = 1 << iota

	// queryFlagDNSSec enables requesting for DNSSEC signatures.
	queryFlagDNSSec
)

const (
	// queryMaxResponseSizeUDP is the maximum response size when using UDP
	// and is consistent with what the standard library uses.
	queryMaxResponseSizeUDP = 1232

	// queryMaxResponseSizeTCP is the maximum response size when using TCP
	// and is consistent with what the standard library uses.
	queryMaxResponseSizeTCP = 4096
)

// Query is a DNS query.
//
// This struct contain private fields used by the transports
// to control how to marshal the query.
//
// Construct using [NewQuery].
type Query struct {
	// Name is the MANDATORY domain name to query.
	Name string

	// Type is the query type.
	Type uint16

	// flags OPTIONALLY modify the query flags.
	flags uint16

	// ID is the OPTIONAL query ID.
	id uint16

	// MaxSize is the OPTIONAL maximum response size
	// to include in the query using EDNS(0).
	maxSize uint16
}

// NewQuery constructs a new [*Query].
func NewQuery(name string, qtype uint16) *Query {
	return &Query{
		Name:    name,
		Type:    qtype,
		flags:   0,
		id:      0,
		maxSize: queryMaxResponseSizeUDP,
	}
}

// Clone returns a deep copy of the query.
func (q *Query) Clone() *Query {
	return &Query{
		Name:    q.Name,
		Type:    q.Type,
		flags:   q.flags,
		id:      q.id,
		maxSize: q.maxSize,
	}
}

// NewMsg creates a new [*dns.Msg] from the [*Query].
func (q *Query) NewMsg() (*dns.Msg, error) {
	// IDNA encode the domain name.
	punyName, err := idna.Lookup.ToASCII(q.Name)
	if err != nil {
		return nil, err
	}

	// Ensure the domain name is fully qualified.
	if !dns.IsFqdn(punyName) {
		punyName = dns.Fqdn(punyName)
	}

	// Create the query message.
	question := dns.Question{
		Name:   punyName,
		Qtype:  q.Type,
		Qclass: dns.ClassINET,
	}
	msg := new(dns.Msg)
	msg.Id = q.id
	msg.RecursionDesired = true
	msg.Question = make([]dns.Question, 1)
	msg.Question[0] = question

	// Set the EDNS(0) query options
	msg.SetEdns0(q.maxSize, q.flags&queryFlagDNSSec != 0)

	// Clients SHOULD pad queries to the closest multiple of
	// 128 octets RFC8467#section-4.1. We inflate the query
	// length by the size of the option (i.e. 4 octets). The
	// cast to uint is necessary to make the modulus operation
	// work as intended when the desiredBlockSize is smaller
	// than (query.Len()+4) ¯\_(ツ)_/¯.
	if q.flags&queryFlagBlockLengthPadding != 0 {
		const desiredSize = 128
		remainder := (desiredSize - uint16(msg.Len()+4)) % desiredSize
		opt := new(dns.EDNS0_PADDING)
		opt.Padding = make([]byte, remainder)
		msg.IsEdns0().Option = append(msg.IsEdns0().Option, opt)
	}

	return msg, nil
}
