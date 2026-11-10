// SPDX-FileCopyrightText: 2026 Balázs Toldi
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
)

// Addresses and names the N4 tests share. The repo's goconst settings count literals
// across the package's tests, so they are named once here.
// loopbackV4 and loopbackV6 are in node_addr_test.go.
const (
	anyIPv4         = "0.0.0.0"
	testAddr4       = "192.0.2.1"
	testAddr6       = "2001:db8::1"
	testN4Addr4     = "10.0.0.1"
	testN4Addr6     = "2001:db8::10"
	testNodeIDAddr4 = "10.0.0.10"
	testZonedAddr   = "fe80::1%eth0"
	testHostname    = "upf"
	testUPFFQDN     = "upf.example.org"
	testSMFFQDN     = "smf.example.org"
)

func addrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, 0, len(ss))
	for _, s := range ss {
		out = append(out, netip.MustParseAddr(s))
	}

	return out
}

// TestNewLocalNodeID covers where the advertised Node ID comes from: node_id as it is,
// hostname (or use_fqdn) resolved to every address, or nothing.
func TestNewLocalNodeID(t *testing.T) {
	resolved := map[string][]string{
		testHostname:  {testN4Addr6, testNodeIDAddr4},
		"upf-v4":      {testNodeIDAddr4},
		"upf-0.lab":   {"10.0.0.20"},
		testZonedAddr: {testZonedAddr}, // LookupHost hands a literal back as it is
		"junk":        {"not-an-address"},
	}

	tests := []struct {
		name     string
		conf     CPIfaceInfo
		want     localNodeID
		wantErr  bool
		noLookup bool
	}{
		{name: "nothing configured", conf: CPIfaceInfo{}, want: localNodeID{}, noLookup: true},
		{
			name: "node_id IPv4", conf: CPIfaceInfo{AdvertisedNodeID: testN4Addr4},
			want: localNodeID{fixed: testN4Addr4}, noLookup: true,
		},
		{
			name: "node_id IPv6, non-canonical", conf: CPIfaceInfo{AdvertisedNodeID: "2001:DB8:0:0::1"},
			want: localNodeID{fixed: testAddr6}, noLookup: true,
		},
		{
			name: "node_id IPv4-mapped is IPv4", conf: CPIfaceInfo{AdvertisedNodeID: "::ffff:10.0.0.1"},
			want: localNodeID{fixed: testN4Addr4}, noLookup: true,
		},
		{
			name: "node_id FQDN, not resolved", conf: CPIfaceInfo{AdvertisedNodeID: "upf.example.org."},
			want: localNodeID{fixed: testUPFFQDN}, noLookup: true,
		},
		{
			name: "node_id wins over hostname",
			conf: CPIfaceInfo{AdvertisedNodeID: testUPFFQDN, NodeID: testHostname, UseFQDN: true},
			want: localNodeID{fixed: testUPFFQDN}, noLookup: true,
		},
		{
			name: "hostname keeps every address, in resolver order", conf: CPIfaceInfo{NodeID: testHostname},
			want: localNodeID{addrs: addrs(testN4Addr6, testNodeIDAddr4)},
		},
		{
			name: "hostname IPv4 only, as before", conf: CPIfaceInfo{NodeID: "upf-v4"},
			want: localNodeID{addrs: addrs(testNodeIDAddr4)},
		},
		{
			name: "hostname literal with a zone loses the zone", conf: CPIfaceInfo{NodeID: testZonedAddr},
			want: localNodeID{addrs: addrs("fe80::1")},
		},
		{
			name: "use_fqdn resolves the host name", conf: CPIfaceInfo{UseFQDN: true},
			want: localNodeID{addrs: addrs("10.0.0.20")},
		},
		{name: "hostname that does not resolve", conf: CPIfaceInfo{NodeID: "nowhere"}, wantErr: true},
		{name: "hostname that resolves to no address", conf: CPIfaceInfo{NodeID: "junk"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			looked := false
			lookup := func(_ context.Context, h string) ([]string, error) {
				looked = true

				if r, ok := resolved[h]; ok {
					return r, nil
				}

				return nil, &net.DNSError{Err: "no such host", Name: h, IsNotFound: true}
			}
			hostname := func() (string, error) { return "upf-0.lab", nil }

			got, err := newLocalNodeID(context.Background(), tt.conf, lookup, hostname)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("got %+v, want an error", got)
				}

				return
			}

			if err != nil {
				t.Fatal(err)
			}

			if got.fixed != tt.want.fixed || !slices.Equal(got.addrs, tt.want.addrs) {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}

			if tt.noLookup && looked {
				t.Error("resolved a name that is advertised as it is")
			}
		})
	}
}

// TestLocalNodeIDChoose: the Node ID an association advertises follows the family of
// its socket's local address, which is the peer's family.
func TestLocalNodeIDChoose(t *testing.T) {
	v4 := net.ParseIP(testAddr4).To4()
	v4mapped := net.ParseIP(testAddr4) // how a dual-stack socket reports an IPv4 peer
	v6 := net.ParseIP(testAddr6)

	tests := []struct {
		name  string
		id    localNodeID
		local net.IP
		want  string
	}{
		{name: "none, IPv4 socket", local: v4, want: testAddr4},
		{name: "none, dual-stack socket to an IPv4 peer", local: v4mapped, want: testAddr4},
		{name: "none, IPv6 socket", local: v6, want: testAddr6},
		{name: "FQDN, IPv4", id: localNodeID{fixed: testUPFFQDN}, local: v4, want: testUPFFQDN},
		{name: "FQDN, IPv6", id: localNodeID{fixed: testUPFFQDN}, local: v6, want: testUPFFQDN},
		{name: "node_id IPv4 on an IPv6 association, as given", id: localNodeID{fixed: testN4Addr4}, local: v6, want: testN4Addr4},
		{
			name: "both families, IPv4 peer", id: localNodeID{addrs: addrs(testN4Addr6, testNodeIDAddr4)},
			local: v4mapped, want: testNodeIDAddr4,
		},
		{
			name: "both families, IPv6 peer", id: localNodeID{addrs: addrs(testNodeIDAddr4, testN4Addr6)},
			local: v6, want: testN4Addr6,
		},
		{
			name: "IPv4 only, IPv4 peer: unchanged", id: localNodeID{addrs: addrs(testNodeIDAddr4)},
			local: v4, want: testNodeIDAddr4,
		},
		{
			name: "IPv4 only, IPv6 peer: the first address", id: localNodeID{addrs: addrs(testNodeIDAddr4)},
			local: v6, want: testNodeIDAddr4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.id.choose(tt.local); got != tt.want {
				t.Errorf("choose(%v) = %q, want %q", tt.local, got, tt.want)
			}
		})
	}
}

// TestNodeIDIE: the encoding of each kind of Node ID (TS 29.244 clause 8.2.38), and
// that it decodes back to the same string.
func TestNodeIDIE(t *testing.T) {
	tests := []struct {
		id      string
		payload []byte
		want    string // after peerNodeID
	}{
		{id: testAddr4, payload: []byte{nodeIDTypeIPv4, 192, 0, 2, 1}, want: testAddr4},
		{id: "::ffff:192.0.2.1", payload: []byte{nodeIDTypeIPv4, 192, 0, 2, 1}, want: testAddr4},
		{
			id:      testAddr6,
			payload: []byte{nodeIDTypeIPv6, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			want:    testAddr6,
		},
		{
			id:      "upf.example",
			payload: []byte{nodeIDTypeFQDN, 3, 'u', 'p', 'f', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e'},
			want:    "upf.example",
		},
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			got := nodeIDIE(tt.id)
			if got == nil {
				t.Fatal("no IE")
			}

			if got.Type != ie.NodeID {
				t.Fatalf("IE type %d, want Node ID", got.Type)
			}

			if !bytes.Equal(got.Payload, tt.payload) {
				t.Errorf("payload %x, want %x", got.Payload, tt.payload)
			}

			back, err := peerNodeID(got)
			if err != nil || back != tt.want {
				t.Errorf("peerNodeID = %q, %v; want %q", back, err, tt.want)
			}
		})
	}

	if nodeIDIE("") != nil {
		t.Error("an empty Node ID has an IE")
	}
}

// TestPeerNodeID covers the decoding a peer's Node ID is matched by. Valid addresses
// decode to the same string go-pfcp's NodeID() gives, so association keys and metric
// labels are unchanged for them.
func TestPeerNodeID(t *testing.T) {
	v6 := func(s string) []byte {
		return append([]byte{nodeIDTypeIPv6}, netip.MustParseAddr(s).AsSlice()...)
	}

	tests := []struct {
		name     string
		ie       *ie.IE
		want     string
		wantErr  bool
		pfcpSame bool // go-pfcp's NodeID() gives the same string
	}{
		{name: "IPv4", ie: ie.NewNodeID(testAddr4, "", ""), want: testAddr4, pfcpSame: true},
		{name: "IPv6", ie: ie.NewNodeID("", testAddr6, ""), want: testAddr6, pfcpSame: true},
		{
			name: "IPv6 written out in full", ie: ie.NewNodeID("", "2001:0DB8:0000:0000:0000:0000:0000:0001", ""),
			want: testAddr6, pfcpSame: true,
		},
		{
			name: "IPv6, longest zero run compressed", ie: ie.New(ie.NodeID, v6("2001:db8:0:1:0:0:0:1")),
			want: "2001:db8:0:1::1", pfcpSame: true,
		},
		{
			name: "IPv4-mapped IPv6 reads as IPv4, as before", ie: ie.New(ie.NodeID, v6("::ffff:192.0.2.1")),
			want: testAddr4, pfcpSame: true,
		},
		{name: "FQDN", ie: ie.NewNodeID("", "", testSMFFQDN), want: testSMFFQDN, pfcpSame: true},
		{name: "FQDN in mixed case", ie: ie.NewNodeID("", "", "SMF.Example.ORG"), want: testSMFFQDN},
		{
			name: "FQDN with the root label's zero octet",
			ie:   ie.New(ie.NodeID, []byte{nodeIDTypeFQDN, 3, 's', 'm', 'f', 3, 'o', 'r', 'g', 0}),
			want: "smf.org",
		},
		{
			name: "spare bits in the type octet are ignored",
			ie:   ie.New(ie.NodeID, []byte{0xf0 | nodeIDTypeIPv4, 192, 0, 2, 1}),
			want: testAddr4,
		},
		{name: "IPv4 too short", ie: ie.New(ie.NodeID, []byte{nodeIDTypeIPv4, 192, 0, 2}), wantErr: true},
		{name: "IPv6 too short", ie: ie.New(ie.NodeID, v6(testAddr6)[:9]), wantErr: true},
		{name: "empty FQDN", ie: ie.New(ie.NodeID, []byte{nodeIDTypeFQDN, 0}), wantErr: true},
		{name: "unknown type", ie: ie.New(ie.NodeID, []byte{3, 1, 2, 3, 4}), wantErr: true},
		{name: "no address", ie: ie.New(ie.NodeID, []byte{nodeIDTypeIPv4}), wantErr: true},
		{name: "not a Node ID", ie: ie.NewRecoveryTimeStamp(time.Now()), wantErr: true},
		{name: "missing", ie: nil, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := peerNodeID(tt.ie)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("got %q, want an error", got)
				}

				return
			}

			if err != nil {
				t.Fatal(err)
			}

			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}

			if tt.pfcpSame {
				if old, err := tt.ie.NodeID(); err != nil || old != got {
					t.Errorf("go-pfcp NodeID() = %q, %v; peerNodeID = %q", old, err, got)
				}
			}
		})
	}

	// The case peerNodeID exists for: go-pfcp turned every short address into "<nil>",
	// so two different malformed Node IDs matched each other.
	if old, err := ie.New(ie.NodeID, []byte{nodeIDTypeIPv6, 1, 2, 3}).NodeID(); err != nil || old != "<nil>" {
		t.Logf("go-pfcp now decodes a short IPv6 Node ID as %q, %v", old, err)
	}

	if _, err := peerNodeID(nil); !errors.Is(err, errNodeIDMissing) {
		t.Errorf("a missing Node ID gave %v", err)
	}
}

// TestUPFSEID: the UP F-SEID carries the association's local address in the slot of its
// family, and only that one.
func TestUPFSEID(t *testing.T) {
	tests := []struct {
		name   string
		local  net.IP
		wantV4 net.IP
		wantV6 net.IP
	}{
		{name: "IPv4 socket", local: net.ParseIP(testAddr4).To4(), wantV4: net.ParseIP(testAddr4)},
		{name: "dual-stack socket, IPv4 peer", local: net.ParseIP(testAddr4), wantV4: net.ParseIP(testAddr4)},
		{name: "IPv6 socket", local: net.ParseIP(testAddr6), wantV6: net.ParseIP(testAddr6)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := upFSEID(0x1122334455667788, tt.local).FSEID()
			if err != nil {
				t.Fatal(err)
			}

			if f.SEID != 0x1122334455667788 {
				t.Errorf("SEID %#x", f.SEID)
			}

			if f.HasIPv4() != (tt.wantV4 != nil) || f.HasIPv6() != (tt.wantV6 != nil) {
				t.Fatalf("flags %#x: V4 %v, V6 %v", f.Flags, f.HasIPv4(), f.HasIPv6())
			}

			if tt.wantV4 != nil && !f.IPv4Address.Equal(tt.wantV4) {
				t.Errorf("IPv4 %v, want %v", f.IPv4Address, tt.wantV4)
			}

			if tt.wantV6 != nil && !f.IPv6Address.Equal(tt.wantV6) {
				t.Errorf("IPv6 %v, want %v", f.IPv6Address, tt.wantV6)
			}
		})
	}
}
