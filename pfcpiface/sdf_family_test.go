// SPDX-FileCopyrightText: 2026 Balázs Toldi
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"errors"
	"math"
	"net/netip"
	"testing"

	"github.com/wmnsk/go-pfcp/ie"
)

// A flow description names addresses of one family, or of none ("any", "assigned"), and
// it applies to the families it names. "assigned" is the UE's address of the family the
// rule is applied to.

func TestEndpointParseNetFamilies(t *testing.T) {
	for _, tc := range []struct {
		in         string
		want       endpoint
		wantFamily int
		wantErr    bool
	}{
		{in: "any", want: endpoint{}},
		{in: "assigned", want: endpoint{assigned: true}},
		{in: "10.0.0.9", want: endpoint{prefix: netip.MustParsePrefix("10.0.0.9/32")}, wantFamily: 4},
		{in: "10.0.0.1/8", want: endpoint{prefix: netip.MustParsePrefix("10.0.0.0/8")}, wantFamily: 4},
		{in: "0.0.0.0/0", want: endpoint{prefix: netip.MustParsePrefix("0.0.0.0/0")}, wantFamily: 4},
		// A bare IPv6 host is a /128; it used to be given "/32" and become a /32 prefix.
		{in: "2001:db8::1", want: endpoint{prefix: netip.MustParsePrefix("2001:db8::1/128")}, wantFamily: 6},
		{in: "ff02::2/128", want: endpoint{prefix: netip.MustParsePrefix("ff02::2/128")}, wantFamily: 6},
		// The prefix is kept whole; its low 32 bits used to be all that was left.
		{
			in:   "2001:db8:1:2::77/64",
			want: endpoint{prefix: netip.MustParsePrefix("2001:db8:1:2::/64")}, wantFamily: 6,
		},
		{in: "::/0", want: endpoint{prefix: netip.MustParsePrefix("::/0")}, wantFamily: 6},
		{in: "fe80::1%eth0", wantErr: true},
		{in: "2001:db8::/129", wantErr: true},
		{in: "10.0.0.1/33", wantErr: true},
	} {
		t.Run(tc.in, func(t *testing.T) {
			var got endpoint

			err := got.parseNet(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("parseNet(%q) error = %v, wantErr %v", tc.in, err, tc.wantErr)
			}

			if err != nil {
				return
			}

			if got != tc.want {
				t.Errorf("parseNet(%q) = %+v, want %+v", tc.in, got, tc.want)
			}

			if got.family() != tc.wantFamily {
				t.Errorf("family() = %d, want %d", got.family(), tc.wantFamily)
			}
		})
	}
}

func TestParseFlowDescFamilies(t *testing.T) {
	for _, tc := range []struct {
		flowDesc   string
		wantFamily int
		wantErr    bool
	}{
		{flowDesc: flowAnyToAssigned, wantFamily: 0},
		{flowDesc: "permit out 17 from 192.0.2.0/24 8000 to assigned", wantFamily: 4},
		{flowDesc: "permit out 58 from ff02::2/128 to assigned", wantFamily: 6},
		{flowDesc: "permit out ip from 2001:db8::/32 to 2001:db8:1::/48", wantFamily: 6},
		{flowDesc: "permit out ip from 192.0.2.1 to 2001:db8::1", wantErr: true},
	} {
		t.Run(tc.flowDesc, func(t *testing.T) {
			ipf, err := parseFlowDesc(tc.flowDesc)
			if (err != nil) != tc.wantErr {
				t.Fatalf("parseFlowDesc() error = %v, wantErr %v", err, tc.wantErr)
			}

			if err == nil && ipf.family() != tc.wantFamily {
				t.Errorf("family() = %d, want %d", ipf.family(), tc.wantFamily)
			}
		})
	}
}

func TestSDFFilterPerFamily(t *testing.T) {
	ueV4 := netip.MustParseAddr(testUEIPv4)
	ueV6 := netip.PrefixFrom(netip.MustParseAddr(testUEIPv6Full), 64)
	ueV6Match := ueV6.Masked()
	ueV4Match := hostPrefix(ueV4)

	any4 := newWildcardPortRange()

	type ue struct {
		v4 netip.Addr
		v6 netip.Prefix
	}

	v4only, v6only, dual := ue{v4: ueV4}, ue{v6: ueV6}, ue{v4: ueV4, v6: ueV6}

	ipFilter := func(src, dst netip.Prefix) applicationFilter {
		return applicationFilter{srcIP: src, dstIP: dst, srcPortRange: any4, dstPortRange: any4}
	}

	for _, tc := range []struct {
		name       string
		ue         ue
		iface      uint8
		flowDesc   string
		want4      *applicationFilter // nil: the PDR has no IPv4 rule
		want6      *applicationFilter // nil: the PDR has no IPv6 rule
		wantReject bool
	}{
		{
			name: "any to assigned, IPv4 UE, downlink", ue: v4only, iface: core,
			flowDesc: flowAnyToAssigned,
			want4:    &applicationFilter{dstIP: ueV4Match, srcPortRange: any4, dstPortRange: any4},
		},
		{
			name: "any to assigned, IPv6 UE, downlink", ue: v6only, iface: core,
			flowDesc: flowAnyToAssigned,
			// "assigned" has no IPv4 address to stand for, and matches any, as an
			// "assigned" without a UE address did before. The PDR is refused for its UE.
			want4:      &applicationFilter{srcPortRange: any4, dstPortRange: any4},
			want6:      &applicationFilter{dstIP: ueV6Match, srcPortRange: any4, dstPortRange: any4},
			wantReject: true,
		},
		{
			name: "any to assigned, IPv4v6 UE, downlink", ue: dual, iface: core,
			flowDesc: flowAnyToAssigned,
			want4:    &applicationFilter{dstIP: ueV4Match, srcPortRange: any4, dstPortRange: any4},
			want6:    &applicationFilter{dstIP: ueV6Match, srcPortRange: any4, dstPortRange: any4},
		},
		{
			name: "any to assigned, IPv4v6 UE, uplink", ue: dual, iface: access,
			flowDesc: flowAnyToAssigned,
			want4:    &applicationFilter{srcIP: ueV4Match, srcPortRange: any4, dstPortRange: any4},
			want6:    &applicationFilter{srcIP: ueV6Match, srcPortRange: any4, dstPortRange: any4},
		},
		{
			name: "IPv4 prefix, IPv4v6 UE: IPv4 only", ue: dual, iface: core,
			flowDesc: "permit out ip from 192.0.2.0/24 to assigned",
			want4: func() *applicationFilter {
				f := ipFilter(netip.MustParsePrefix("192.0.2.0/24"), ueV4Match)
				return &f
			}(),
		},
		{
			name: "IPv6 prefix with a port, IPv4v6 UE: IPv6 only", ue: dual, iface: core,
			flowDesc: "permit out 17 from 2001:db8:1:2::/64 to assigned 5000",
			want6: &applicationFilter{
				srcIP: netip.MustParsePrefix("2001:db8:1:2::/64"), dstIP: ueV6Match,
				// The downlink port workaround moves the destination port to the source.
				srcPortRange: newExactMatchPortRange(5000), dstPortRange: any4,
				proto: 17, protoMask: math.MaxUint8,
			},
			wantReject: true,
		},
		{
			// The SMF's router solicitation PDR (smf ipv6/router-advertisement).
			name: "router solicitation, IPv4v6 UE, uplink", ue: dual, iface: access,
			flowDesc: "permit out 58 from ff02::2/128 to assigned",
			want6: &applicationFilter{
				srcIP: ueV6Match, dstIP: netip.MustParsePrefix("ff02::2/128"),
				srcPortRange: any4, dstPortRange: any4, proto: 58, protoMask: math.MaxUint8,
			},
			wantReject: true,
		},
		{
			name: "IPv6 filter, IPv4 UE: assigned has no IPv6 address", ue: v4only, iface: core,
			flowDesc: "permit out ip from 2001:db8::/32 to assigned",
			want6: func() *applicationFilter {
				f := ipFilter(netip.MustParsePrefix("2001:db8::/32"), netip.Prefix{})
				return &f
			}(),
			wantReject: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := pdr{srcIface: tc.iface, ueAddress: tc.ue.v4, ueIPv6: tc.ue.v6}

			if err := p.parseSDFFilter(ie.NewSDFFilter(tc.flowDesc, "", "", "", 0)); err != nil {
				t.Fatalf("parseSDFFilter() = %v", err)
			}

			if got := !p.noIPv4Rule; got != (tc.want4 != nil) {
				t.Errorf("IPv4 rule = %v, want %v", got, tc.want4 != nil)
			} else if tc.want4 != nil && p.appFilter != *tc.want4 {
				t.Errorf("IPv4 filter = %v, want %v", p.appFilter, *tc.want4)
			}

			if p.hasIPv6Rule != (tc.want6 != nil) {
				t.Errorf("IPv6 rule = %v, want %v", p.hasIPv6Rule, tc.want6 != nil)
			} else if tc.want6 != nil && p.appFilter6 != *tc.want6 {
				t.Errorf("IPv6 filter = %v, want %v", p.appFilter6, *tc.want6)
			}

			err := p.checkDatapathSupport()
			if (err != nil) != tc.wantReject {
				t.Errorf("checkDatapathSupport() = %v, wantReject %v", err, tc.wantReject)
			}

			if err != nil && !errors.Is(err, errUnsupported) {
				t.Errorf("checkDatapathSupport() = %v, want an unsupported-feature error", err)
			}
		})
	}
}

// A PDR whose UE IP Address IE is read sets the IPv6 match before any filter, the way
// the IPv4 one is set: a PDR without an SDF filter matches the UE's whole prefix.
func TestThePDIMatchesTheUEPrefix(t *testing.T) {
	pdrIE := ie.NewCreatePDR(
		ie.NewPDRID(1),
		ie.NewPrecedence(255),
		ie.NewPDI(
			ie.NewSourceInterface(ie.SrcInterfaceCore),
			ie.NewUEIPAddress(0x47, testUEIPv4, testUEIPv6Full, 0, 64),
		),
		ie.NewFARID(1),
	)

	var p pdr
	if err := p.parsePDR(pdrIE, 1, nil, nil); err != nil {
		t.Fatalf("parsePDR() = %v", err)
	}

	if want := netip.MustParsePrefix("2a0e:8f02:f07b:500::/64"); !p.hasIPv6Rule || p.appFilter6.dstIP != want {
		t.Errorf("IPv6 rule %v, destination %v; want one, %v", p.hasIPv6Rule, p.appFilter6.dstIP, want)
	}

	if want := hostPrefix(netip.MustParseAddr(testUEIPv4)); p.appFilter.dstIP != want {
		t.Errorf("IPv4 destination %v, want %v", p.appFilter.dstIP, want)
	}
}

// A filter that does not parse refuses the PDR. The error used to be dropped, and the
// PDR installed without its filter.
func TestABadSDFFilterRefusesThePDR(t *testing.T) {
	for _, flowDesc := range []string{
		"permit out ip from 10.0.0.1/33 to assigned",
		"permit out ip from 192.0.2.1 to 2001:db8::1",
		"permit sideways ip from any to assigned",
	} {
		t.Run(flowDesc, func(t *testing.T) {
			pdrIE := goldenPDR(1, 255, 1, []*ie.IE{
				ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewUEIPAddress(ueIPFlagV4, testUEIPv4, "", 0, 0),
				ie.NewSDFFilter(flowDesc, "", "", "", 0),
			})

			var p pdr

			err := p.parsePDR(pdrIE, 1, nil, nil)
			if !errors.Is(err, errBadFilterDesc) {
				t.Fatalf("parsePDR() = %v, want errBadFilterDesc", err)
			}

			pConn, client, _ := goldenConn(t, nil)

			assertRequestRejected(t, pConn, pdrIE)

			if got := client.take(); len(got) != 0 {
				t.Errorf("the datapath was sent %v", got)
			}
		})
	}
}

// The SMF installs a router-solicitation PDR in an IPv4v6 session only when it has a
// GTP-U endpoint of its own (cpGtpu). This datapath cannot match it, and refuses it
// rather than installing the IPv4 rule its filter used to be truncated into.
func TestARouterSolicitationPDRIsRefused(t *testing.T) {
	pConn, client, _ := goldenConn(t, nil)

	assertRequestRejected(t, pConn,
		goldenPDR(1, 0, 1, []*ie.IE{
			ie.NewSourceInterface(ie.SrcInterfaceAccess),
			ie.NewFTEID(0x0d, 0, nil, nil, 1),
			ie.NewUEIPAddress(0x43, testUEIPv4, testUEIPv6Full, 0, 64),
			ie.NewSDFFilter("permit out 58 from ff02::2/128 to assigned", "", "", "", 0),
		}),
	)

	if got := client.take(); len(got) != 0 {
		t.Errorf("the datapath was sent %v", got)
	}
}
