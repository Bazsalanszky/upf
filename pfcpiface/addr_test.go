// SPDX-FileCopyrightText: 2026 Balázs Toldi
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/wmnsk/go-pfcp/ie"
)

func TestAddrFromIP(t *testing.T) {
	for _, tc := range []struct {
		name string
		ip   net.IP
		want netip.Addr
	}{
		{"nil", nil, netip.Addr{}},
		{"malformed", net.IP{1, 2, 3}, netip.Addr{}},
		{"IPv4, 4 bytes", net.IP{10, 0, 0, 1}, netip.MustParseAddr("10.0.0.1")},
		{"IPv4, 16 bytes", net.ParseIP("10.0.0.1"), netip.MustParseAddr("10.0.0.1")},
		{"IPv6 address", net.ParseIP("2001:db8::1"), netip.MustParseAddr("2001:db8::1")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := addrFromIP(tc.ip)
			if got != tc.want {
				t.Fatalf("addrFromIP(%v) = %v, want %v", tc.ip, got, tc.want)
			}

			if back := ipFromAddr(got); got.IsValid() && !back.Equal(tc.ip) {
				t.Errorf("ipFromAddr(%v) = %v, want %v", got, back, tc.ip)
			}
		})
	}

	if ipFromAddr(netip.Addr{}) != nil {
		t.Error("ipFromAddr of the zero Addr is not nil")
	}
}

func TestIPv4Field(t *testing.T) {
	for _, tc := range []struct {
		name    string
		addr    netip.Addr
		want    uint32
		wantErr bool
	}{
		{"none", netip.Addr{}, 0, false},
		{"unspecified", netip.IPv4Unspecified(), 0, false},
		{"IPv4 address", netip.MustParseAddr("10.10.3.200"), 0x0a0a03c8, false},
		{"broadcast", netip.MustParseAddr("255.255.255.255"), 0xffffffff, false},
		// The old ip2int kept the last four bytes of these: 0.0.0.1 and 10.0.0.1.
		{"IPv6 address", netip.MustParseAddr("2001:db8::1"), 0, true},
		{"IPv4-mapped IPv6", netip.MustParseAddr("::ffff:10.0.0.1"), 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ipv4Field(tc.addr)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ipv4Field(%v) error = %v, wantErr %v", tc.addr, err, tc.wantErr)
			}

			if err != nil && !errors.Is(err, errNotIPv4) {
				t.Errorf("ipv4Field(%v) error = %v, want errNotIPv4", tc.addr, err)
			}

			if got != tc.want {
				t.Errorf("ipv4Field(%v) = %#x, want %#x", tc.addr, got, tc.want)
			}

			if !tc.wantErr && tc.addr.IsValid() && addrFromIPv4Field(got) != tc.addr {
				t.Errorf("addrFromIPv4Field(%#x) = %v, want %v", got, addrFromIPv4Field(got), tc.addr)
			}
		})
	}
}

func TestIPv4MatchFields(t *testing.T) {
	for _, tc := range []struct {
		name      string
		prefix    netip.Prefix
		wantValue uint32
		wantMask  uint32
		wantErr   bool
	}{
		{"any", netip.Prefix{}, 0, 0, false},
		{"IPv4 /0", netip.MustParsePrefix("0.0.0.0/0"), 0, 0, false},
		{"IPv4 host", netip.MustParsePrefix("10.250.0.5/32"), 0x0afa0005, 0xffffffff, false},
		{"IPv4 /26", netip.MustParsePrefix("203.0.113.64/26"), 0xcb007140, 0xffffffc0, false},
		{"IPv4 /26, host bits set", netip.MustParsePrefix("203.0.113.77/26"), 0xcb007140, 0xffffffc0, false},
		{"IPv4 /1", netip.MustParsePrefix("128.0.0.0/1"), 0x80000000, 0x80000000, false},
		// The old ipMask2int read the low 32 bits of the mask: 0, so a /64 matched anything.
		{"IPv6 /64", netip.MustParsePrefix("2001:db8:1:2::/64"), 0, 0, true},
		{"IPv6 /0", netip.MustParsePrefix("::/0"), 0, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value, mask, err := ipv4MatchFields(tc.prefix)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ipv4MatchFields(%v) error = %v, wantErr %v", tc.prefix, err, tc.wantErr)
			}

			if value != tc.wantValue || mask != tc.wantMask {
				t.Errorf("ipv4MatchFields(%v) = %#x/%#x, want %#x/%#x",
					tc.prefix, value, mask, tc.wantValue, tc.wantMask)
			}
		})
	}
}

func TestMatchPrefix(t *testing.T) {
	for _, tc := range []struct {
		in, want netip.Prefix
	}{
		{netip.Prefix{}, netip.Prefix{}},
		{netip.MustParsePrefix("0.0.0.0/0"), netip.Prefix{}},
		{netip.MustParsePrefix("10.1.2.3/0"), netip.Prefix{}},
		{netip.MustParsePrefix("::/0"), netip.Prefix{}},
		{netip.MustParsePrefix("10.1.2.3/8"), netip.MustParsePrefix("10.0.0.0/8")},
		{netip.MustParsePrefix("2001:db8::1/64"), netip.MustParsePrefix("2001:db8::/64")},
		{netip.MustParsePrefix("2001:db8::1/128"), netip.MustParsePrefix("2001:db8::1/128")},
	} {
		if got := matchPrefix(tc.in); got != tc.want {
			t.Errorf("matchPrefix(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestIPv4WithOffset(t *testing.T) {
	if got, want := ipv4WithOffset(net.ParseIP("10.0.0.254"), 3), netip.MustParseAddr("10.0.1.1"); got != want {
		t.Errorf("ipv4WithOffset = %v, want %v", got, want)
	}

	if got := ipv4WithOffset(net.ParseIP("2001:db8::1"), 1); got.IsValid() {
		t.Errorf("ipv4WithOffset of an IPv6 address = %v, want the zero Addr", got)
	}
}

// A rule whose address is IPv6 is refused where it is converted for the datapath: the
// datapath has no field for it, and the 32 bits the old conversion kept name another
// host. The refusal reaches the batch as a rule that was not programmed.
func TestTheDatapathRefusesAnIPv6Rule(t *testing.T) {
	v6 := netip.MustParseAddr("2001:db8::1")

	for _, tc := range []struct {
		name  string
		rules PacketForwardingRules
	}{
		{"PDR tunnel destination", PacketForwardingRules{pdrs: []pdr{{tunnelIPDst: hostPrefix(v6)}}}},
		{"PDR source address", PacketForwardingRules{pdrs: []pdr{{appFilter: applicationFilter{srcIP: hostPrefix(v6)}}}}},
		{"PDR destination address", PacketForwardingRules{pdrs: []pdr{{appFilter: applicationFilter{dstIP: hostPrefix(v6)}}}}},
		{"FAR tunnel source", PacketForwardingRules{fars: []far{{tunnelIPSrc: v6}}}},
		{"FAR tunnel destination", PacketForwardingRules{fars: []far{{tunnelIPDst: v6}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &recordingModuleClient{}
			b := &bess{client: client}

			if cause := b.SendMsgToUPF(upfMsgTypeAdd, tc.rules, PacketForwardingRules{}); cause != ie.CauseRequestRejected {
				t.Errorf("SendMsgToUPF() = %d for an IPv6 rule, want CauseRequestRejected", cause)
			}

			if got := client.take(); len(got) != 0 {
				t.Errorf("the datapath was sent %v", got)
			}
		})
	}
}

func TestNoEndMarkerForAnIPv6Tunnel(t *testing.T) {
	var markers [][]byte

	addEndMarker(far{tunnelIPSrc: netip.MustParseAddr("10.0.0.9"), tunnelIPDst: netip.MustParseAddr("2001:db8::1")}, &markers)
	if len(markers) != 0 {
		t.Errorf("addEndMarker made %d markers for an IPv6 tunnel, want none", len(markers))
	}
}
