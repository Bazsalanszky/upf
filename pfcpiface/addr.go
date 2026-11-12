// SPDX-FileCopyrightText: 2026 Balázs Toldi
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
)

// The rule model keeps addresses as netip.Addr and netip.Prefix, of either family. The
// BESS datapath matches and rewrites IPv4 only, in 32-bit fields, so the conversion to
// those fields happens where a rule is handed to it, and refuses an IPv6 address rather
// than keeping some 32 bits of it.

// errNotIPv4 is returned for an IPv6 address on its way into a 32-bit datapath field.
var errNotIPv4 = errors.New("not an IPv4 address")

// addrFromIP converts an address decoded by go-pfcp or the net package. An IPv4 address
// in its 16-byte form becomes a 4-byte one, so that it compares equal to the same
// address decoded from 4 bytes. A nil or malformed IP gives the zero Addr.
func addrFromIP(ip net.IP) netip.Addr {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}
	}

	return a.Unmap()
}

// ipFromAddr is the inverse of addrFromIP, for the go-pfcp encoders. The zero Addr gives
// a nil IP.
func ipFromAddr(a netip.Addr) net.IP {
	if !a.IsValid() {
		return nil
	}

	return net.IP(a.AsSlice())
}

// isZeroAddr reports whether a names no address: it is the zero Addr or the unspecified
// address. The datapath writes both as 0, which it reads as "none" or "any".
func isZeroAddr(a netip.Addr) bool {
	return !a.IsValid() || a.IsUnspecified()
}

// hostPrefix returns the prefix that matches a and nothing else: a /32 or a /128. The
// zero Addr gives the zero Prefix, which matches any address.
func hostPrefix(a netip.Addr) netip.Prefix {
	if !a.IsValid() {
		return netip.Prefix{}
	}

	return netip.PrefixFrom(a, a.BitLen())
}

// matchPrefix puts p in the form a rule keeps a match in: the host bits cleared, and the
// zero Prefix for a prefix of length 0. Two rules with the same match then hold equal
// prefixes. A /0 says nothing about the family; the rule it is part of does.
func matchPrefix(p netip.Prefix) netip.Prefix {
	if !p.IsValid() || p.Bits() == 0 {
		return netip.Prefix{}
	}

	return p.Masked()
}

// ipv4Field returns the value a 32-bit datapath field carries for a. The zero Addr is 0,
// as is the unspecified address. An IPv6 address is an error: the datapath has no field
// for it, and any 32 bits of it would name a different host.
func ipv4Field(a netip.Addr) (uint32, error) {
	if !a.IsValid() {
		return 0, nil
	}

	if !a.Is4() {
		return 0, fmt.Errorf("%w: %v", errNotIPv4, a)
	}

	b := a.As4()

	return binary.BigEndian.Uint32(b[:]), nil
}

// ipv4MatchFields returns the value and mask of a 32-bit datapath match field for p. The
// zero Prefix matches any address, which is value and mask 0. An IPv6 prefix is an
// error, for the reason ipv4Field gives.
func ipv4MatchFields(p netip.Prefix) (value, mask uint32, err error) {
	if !p.IsValid() {
		return 0, 0, nil
	}

	value, err = ipv4Field(p.Masked().Addr())
	if err != nil {
		return 0, 0, err
	}

	if p.Bits() > 0 {
		mask = ^uint32(0) << (32 - p.Bits())
	}

	return value, mask, nil
}

// addrFromIPv4Field is the address a 32-bit datapath field holds, for what the datapath
// reports back.
func addrFromIPv4Field(v uint32) netip.Addr {
	var b [4]byte

	binary.BigEndian.PutUint32(b[:], v)

	return netip.AddrFrom4(b)
}

// ipv4WithOffset returns the IPv4 address n addresses after ip, wrapping as the 32-bit
// datapath field would. It is for the simulation mode, whose sessions are numbered from
// a configured start address. An ip that is not IPv4 gives the zero Addr.
func ipv4WithOffset(ip net.IP, n uint32) netip.Addr {
	a := addrFromIP(ip)
	if !a.Is4() {
		return netip.Addr{}
	}

	b := a.As4()

	return addrFromIPv4Field(binary.BigEndian.Uint32(b[:]) + n)
}
