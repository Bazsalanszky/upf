// SPDX-FileCopyrightText: 2026 Balázs Toldi
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// The IPv6 forms of the IEs the rule model reads are parsed into it, and a PDR or FAR
// the IPv4 datapath cannot install as meant is refused with Request rejected. The IPv6
// part of a rule that also matches IPv4 is kept and not installed.

const (
	ueIPFlagSD   = 0x04
	ueIPFlagV6D  = 0x08
	ueIPFlagIP6L = 0x40

	// testUEIPv6Full is what the SMF sends: the UE's /64 and its interface identifier.
	testUEIPv6Full = "2a0e:8f02:f07b:500:1c2b:3d4e:5f60:7a8b"
)

func TestParseUEAddressIE(t *testing.T) {
	v4 := netip.MustParseAddr(testUEIPv4)
	full := netip.MustParseAddr(testUEIPv6Full)

	for _, tc := range []struct {
		name     string
		ie       *ie.IE
		wantV4   netip.Addr
		wantV6   netip.Prefix
		wantErr  bool
		badInput bool // an invalid IE, rather than an unsupported one
	}{
		{
			name:   "IPv4 address",
			ie:     ie.NewUEIPAddress(ueIPFlagV4, testUEIPv4, "", 0, 0),
			wantV4: v4,
		},
		{
			name:   "IPv4, S/D",
			ie:     ie.NewUEIPAddress(ueIPFlagV4|ueIPFlagSD, testUEIPv4, "", 0, 0),
			wantV4: v4,
		},
		{
			name:   "IPv6 without a prefix length is a /64",
			ie:     ie.NewUEIPAddress(ueIPFlagV6, "", testUEIPv6Full, 0, 0),
			wantV6: netip.PrefixFrom(full, 64),
		},
		{
			name:   "IPv6 with IP6PL, as the SMF sends it",
			ie:     ie.NewUEIPAddress(ueIPFlagV6|ueIPFlagIP6L, "", testUEIPv6Full, 0, 64),
			wantV6: netip.PrefixFrom(full, 64),
		},
		{
			name:   "IPv6 with IP6PL /56",
			ie:     ie.NewUEIPAddress(ueIPFlagV6|ueIPFlagIP6L|ueIPFlagSD, "", testUEIPv6Full, 0, 56),
			wantV6: netip.PrefixFrom(full, 56),
		},
		{
			name:   "IPv4v6",
			ie:     ie.NewUEIPAddress(ueIPFlagV4|ueIPFlagV6, testUEIPv4, testUEIPv6Full, 0, 0),
			wantV4: v4,
			wantV6: netip.PrefixFrom(full, 64),
		},
		{
			name:   "IPv4v6 with IP6PL and S/D, as the SMF sends it (0x47)",
			ie:     ie.NewUEIPAddress(0x47, testUEIPv4, testUEIPv6Full, 0, 64),
			wantV4: v4,
			wantV6: netip.PrefixFrom(full, 64),
		},
		{
			name:   "IPv4 with CHV6 keeps the IPv4 address",
			ie:     ie.NewUEIPAddress(ueIPFlagV4|ueIPFlagCHV6, testUEIPv4, "", 0, 0),
			wantV4: v4,
		},
		{
			name:    "CHV6 alone",
			ie:      ie.NewUEIPAddress(ueIPFlagCHV6, "", "", 0, 0),
			wantErr: true,
		},
		{
			name:     "IP6PL 0",
			ie:       ie.NewUEIPAddress(ueIPFlagV6|ueIPFlagIP6L, "", testUEIPv6Full, 0, 0),
			wantErr:  true,
			badInput: true,
		},
		{
			name:     "IP6PL 129",
			ie:       ie.NewUEIPAddress(ueIPFlagV4|ueIPFlagV6|ueIPFlagIP6L, testUEIPv4, testUEIPv6Full, 0, 129),
			wantErr:  true,
			badInput: true,
		},
		{
			name:    "prefix delegation",
			ie:      ie.NewUEIPAddress(ueIPFlagV4|ueIPFlagV6|ueIPFlagV6D, testUEIPv4, testUEIPv6Full, 8, 0),
			wantErr: true,
		},
		{
			name:     "IPv4-mapped IPv6 address",
			ie:       ie.NewUEIPAddress(ueIPFlagV6, "", "::ffff:10.0.0.1", 0, 0),
			wantErr:  true,
			badInput: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var p pdr

			err := p.parseUEAddressIE(tc.ie, nil)
			if (err != nil) != tc.wantErr {
				t.Fatalf("parseUEAddressIE() error = %v, wantErr %v", err, tc.wantErr)
			}

			if err != nil {
				if !tc.badInput && !errors.Is(err, errUnsupported) {
					t.Errorf("parseUEAddressIE() error = %v, want an unsupported-feature error", err)
				}

				return
			}

			if p.ueAddress != tc.wantV4 {
				t.Errorf("ueAddress = %v, want %v", p.ueAddress, tc.wantV4)
			}

			if p.ueIPv6 != tc.wantV6 {
				t.Errorf("ueIPv6 = %v, want %v", p.ueIPv6, tc.wantV6)
			}

			// The interface identifier is kept; a match uses the prefix.
			if tc.wantV6.IsValid() && p.ueIPv6.Addr() != full {
				t.Errorf("ueIPv6 address = %v, want the full address %v", p.ueIPv6.Addr(), full)
			}

			if p.allocIPFlag {
				t.Error("allocIPFlag is set for an address the control plane supplied")
			}
		})
	}
}

func TestParseFTEID(t *testing.T) {
	n3v4 := net.ParseIP("10.10.3.1")
	n3v6 := net.ParseIP("2a0e:8f02:f07b:630::1")

	for _, tc := range []struct {
		name       string
		ie         *ie.IE
		wantV4     netip.Prefix
		wantV6     netip.Prefix
		wantChoose bool
		wantErr    bool
	}{
		{
			name:   "V4 flag",
			ie:     ie.NewFTEID(0x01, 0x100, n3v4, nil, 0),
			wantV4: netip.MustParsePrefix("10.10.3.1/32"),
		},
		{
			name:   "V6 flag",
			ie:     ie.NewFTEID(0x02, 0x100, nil, n3v6, 0),
			wantV6: netip.MustParsePrefix("2a0e:8f02:f07b:630::1/128"),
		},
		{
			name:   "IPv4 and IPv6",
			ie:     ie.NewFTEID(0x03, 0x100, n3v4, n3v6, 0),
			wantV4: netip.MustParsePrefix("10.10.3.1/32"),
			wantV6: netip.MustParsePrefix("2a0e:8f02:f07b:630::1/128"),
		},
		{
			name:       "CHOOSE IPv4",
			ie:         ie.NewFTEID(0x05, 0, nil, nil, 0),
			wantChoose: true,
		},
		{
			name:       "CHOOSE IPv4 and IPv6",
			ie:         ie.NewFTEID(0x07, 0, nil, nil, 0),
			wantChoose: true,
		},
		{
			name:       "CHOOSE IPv6 only",
			ie:         ie.NewFTEID(0x06, 0, nil, nil, 0),
			wantChoose: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var p pdr

			err := p.parseFTEID(tc.ie)
			if (err != nil) != tc.wantErr {
				t.Fatalf("parseFTEID() error = %v, wantErr %v", err, tc.wantErr)
			}

			if err != nil {
				if !errors.Is(err, errUnsupported) {
					t.Errorf("parseFTEID() error = %v, want an unsupported-feature error", err)
				}

				return
			}

			if p.tunnelIPDst != tc.wantV4 || p.tunnelIPv6Dst != tc.wantV6 || p.UPAllocateFteid != tc.wantChoose {
				t.Errorf("got IPv4 %v, IPv6 %v, choose %v; want %v, %v, %v", p.tunnelIPDst, p.tunnelIPv6Dst,
					p.UPAllocateFteid, tc.wantV4, tc.wantV6, tc.wantChoose)
			}
		})
	}
}

func TestPDRDatapathSupport(t *testing.T) {
	uplink := func(pdi ...*ie.IE) *ie.IE {
		return ie.NewCreatePDR(
			ie.NewPDRID(1),
			ie.NewPrecedence(255),
			ie.NewPDI(append([]*ie.IE{ie.NewSourceInterface(ie.SrcInterfaceAccess)}, pdi...)...),
			ie.NewFARID(1),
		)
	}
	withOHR := func(desc uint8) *ie.IE {
		return ie.NewCreatePDR(
			ie.NewPDRID(1),
			ie.NewPrecedence(255),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, 0x100, net.ParseIP("10.10.3.1"), nil, 0)),
			ie.NewOuterHeaderRemoval(desc, 0),
			ie.NewFARID(1),
		)
	}

	for _, tc := range []struct {
		name          string
		ie            *ie.IE
		wantErr       bool
		wantNeedDecap uint8
	}{
		{name: "IPv4 UE", ie: uplink(ie.NewUEIPAddress(ueIPFlagV4, testUEIPv4, "", 0, 0))},
		{name: "IPv4v6 UE", ie: uplink(ie.NewUEIPAddress(0x43, testUEIPv4, testUEIPv6Full, 0, 64))},
		{name: "IPv6 UE", ie: uplink(ie.NewUEIPAddress(0x41, "", testUEIPv6Full, 0, 64))},
		{name: "IPv4 F-TEID", ie: uplink(ie.NewFTEID(0x01, 0x100, net.ParseIP("10.10.3.1"), nil, 0))},
		{
			name: "IPv4v6 F-TEID",
			ie:   uplink(ie.NewFTEID(0x03, 0x100, net.ParseIP("10.10.3.1"), net.ParseIP("2001:db8::1"), 0)),
		},
		// Matched by the low 32 bits of the address (see pdr.tunnelMatches).
		{name: "IPv6 F-TEID", ie: uplink(ie.NewFTEID(0x02, 0x100, nil, net.ParseIP("2001:db8::1"), 0))},
		{name: "OHR GTP-U/UDP/IPv4", ie: withOHR(0), wantNeedDecap: 1},
		{name: "OHR GTP-U/UDP/IPv6", ie: withOHR(1), wantNeedDecap: 1},
		{name: "OHR UDP/IPv4", ie: withOHR(2)},
		{name: "OHR UDP/IPv6", ie: withOHR(3), wantErr: true},
		{name: "OHR IPv6", ie: withOHR(5), wantErr: true},
		// GTP-U/UDP/IP: either family. It used not to set needDecap, which left the
		// GTP-U header on uplink packets.
		{name: "OHR GTP-U/UDP/IP", ie: withOHR(6), wantNeedDecap: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var p pdr

			err := p.parsePDR(tc.ie, 1, nil, nil)
			if (err != nil) != tc.wantErr {
				t.Fatalf("parsePDR() error = %v, wantErr %v", err, tc.wantErr)
			}

			if err != nil {
				if !errors.Is(err, errUnsupported) {
					t.Errorf("parsePDR() error = %v, want an unsupported-feature error", err)
				}

				return
			}

			if p.needDecap != tc.wantNeedDecap {
				t.Errorf("needDecap = %d, want %d", p.needDecap, tc.wantNeedDecap)
			}
		})
	}
}

func TestParseFAROuterHeaderCreation(t *testing.T) {
	u := &upf{accessIP: net.ParseIP("10.10.3.1"), coreIP: net.ParseIP("10.10.6.1")}

	for _, tc := range []struct {
		name    string
		desc    uint16
		v4, v6  string
		wantDst netip.Addr
		wantErr bool
	}{
		{name: "GTP-U/UDP/IPv4", desc: 0x0100, v4: "10.10.3.200", wantDst: netip.MustParseAddr("10.10.3.200")},
		{name: "GTP-U/UDP/IPv6", desc: 0x0200, v6: "2a0e:8f02:f07b:630::200", wantErr: true},
		{
			name: "GTP-U/UDP/IPv4 and IPv6 picks IPv4", desc: 0x0300,
			v4: "10.10.3.200", v6: "2a0e:8f02:f07b:630::200", wantDst: netip.MustParseAddr("10.10.3.200"),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			farIE := ie.NewCreateFAR(
				ie.NewFARID(1),
				ie.NewApplyAction(ActionForward),
				ie.NewForwardingParameters(
					ie.NewDestinationInterface(ie.DstInterfaceAccess),
					ie.NewOuterHeaderCreation(tc.desc, 0x100, tc.v4, tc.v6, 0, 0, 0),
				),
			)

			var f far

			err := f.parseFAR(farIE, 1, u, create)
			if (err != nil) != tc.wantErr {
				t.Fatalf("parseFAR() error = %v, wantErr %v", err, tc.wantErr)
			}

			if err != nil {
				if !errors.Is(err, errUnsupported) {
					t.Errorf("parseFAR() error = %v, want an unsupported-feature error", err)
				}

				if want := netip.MustParseAddr(tc.v6); f.tunnelIPDst != want {
					t.Errorf("tunnelIPDst = %v, want the IPv6 peer %v", f.tunnelIPDst, want)
				}

				return
			}

			if f.tunnelIPDst != tc.wantDst {
				t.Errorf("tunnelIPDst = %v, want %v", f.tunnelIPDst, tc.wantDst)
			}
		})
	}
}

// An IPv4v6 session programs exactly what the same session with an IPv4 UE address
// programs, and its IPv6 rules besides, in pdrLookup6 only: one per PDR.
func TestADualStackSessionProgramsTheIPv4Rules(t *testing.T) {
	program := func(ueIP *ie.IE) []string {
		pConn, client, _ := goldenConn(t, nil)

		sereq := message.NewSessionEstablishmentRequest(0, 0, 0, 1, 0,
			ie.NewNodeID("", "", testRemoteNodeID),
			ie.NewFSEID(0x1001, net.ParseIP("10.10.4.2"), nil),
			goldenPDR(1, 255, 1, []*ie.IE{
				ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x0d, 0, nil, nil, 1),
				ueIP,
				ie.NewSDFFilter(flowAnyToAssigned, "", "", "", 0),
			}, ie.NewOuterHeaderRemoval(0, 0)),
			goldenPDR(2, 255, 2, []*ie.IE{
				ie.NewSourceInterface(ie.SrcInterfaceCore),
				ueIP,
				ie.NewSDFFilter(flowAnyToAssigned, "", "", "", 0),
			}),
			ie.NewCreateFAR(
				ie.NewFARID(1),
				ie.NewApplyAction(ActionForward),
				ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore)),
			),
			ie.NewCreateFAR(
				ie.NewFARID(2),
				ie.NewApplyAction(ActionForward),
				ie.NewForwardingParameters(
					ie.NewDestinationInterface(ie.DstInterfaceAccess),
					ie.NewOuterHeaderCreation(0x0100, 0xabcd, "10.10.3.200", "", 0, 0, 0),
				),
			),
		)

		rsp, err := pConn.handleSessionEstablishmentRequest(sereq)
		if err != nil {
			t.Fatalf("establishment refused: %v", err)
		}

		seres, ok := rsp.(*message.SessionEstablishmentResponse)
		if !ok {
			t.Fatalf("expected a Session Establishment Response, got %T", rsp)
		}

		assertAccepted(t, seres.Cause, "establishment")

		return client.take()
	}

	v4 := program(ie.NewUEIPAddress(ueIPFlagV4, testUEIPv4, "", 0, 0))
	dual := program(ie.NewUEIPAddress(ueIPFlagV4|ueIPFlagV6|ueIPFlagIP6L, testUEIPv4, testUEIPv6Full, 0, 64))

	var dual4, dual6 []string

	for _, l := range dual {
		if strings.HasPrefix(l, PdrLookup6+" ") {
			dual6 = append(dual6, l)
		} else {
			dual4 = append(dual4, l)
		}
	}

	if len(v4) == 0 || !slices.Equal(v4, dual4) {
		t.Errorf("besides pdrLookup6, an IPv4v6 session programs\n%v\nand the IPv4 session\n%v", dual4, v4)
	}

	if len(dual6) != 2 {
		t.Errorf("an IPv4v6 session of two PDRs programs %d pdrLookup6 rules, want 2: %v", len(dual6), dual6)
	}
}

// A rule the datapath cannot install is refused before any of the session reaches it:
// here, a tunnel to an IPv6 peer from a UPF with no IPv6 address to send it from.
func TestAnIPv6RuleIsRejectedBeforeTheDatapath(t *testing.T) {
	for _, tc := range []struct {
		name string
		rule *ie.IE
	}{
		{
			name: "IPv6 outer header",
			rule: ie.NewCreateFAR(
				ie.NewFARID(1),
				ie.NewApplyAction(ActionForward),
				ie.NewForwardingParameters(
					ie.NewDestinationInterface(ie.DstInterfaceAccess),
					ie.NewOuterHeaderCreation(0x0200, 0xabcd, "", "2001:db8::200", 0, 0, 0),
				),
			),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pConn, client, _ := goldenConn(t, nil)

			assertRequestRejected(t, pConn, tc.rule)

			if got := client.take(); len(got) != 0 {
				t.Errorf("the datapath was sent %v", got)
			}
		})
	}
}

// assertRequestRejected sends an establishment carrying rules and checks that it is
// refused with Request rejected, the cause a rule the UPF does not support gets.
func assertRequestRejected(t *testing.T, pConn *PFCPConn, rules ...*ie.IE) {
	t.Helper()

	ies := append([]*ie.IE{
		ie.NewNodeID("", "", testRemoteNodeID),
		ie.NewFSEID(0x2001, net.ParseIP("10.10.4.2"), nil),
	}, rules...)

	rsp, err := pConn.handleSessionEstablishmentRequest(
		message.NewSessionEstablishmentRequest(0, 0, 0, 1, 0, ies...))
	if err == nil {
		t.Fatal("the establishment was accepted")
	}

	seres, ok := rsp.(*message.SessionEstablishmentResponse)
	if !ok || seres.Cause == nil {
		t.Fatalf("expected a Session Establishment Response with a Cause, got %T", rsp)
	}

	if cause, err := seres.Cause.Cause(); err != nil || cause != ie.CauseRequestRejected {
		t.Fatalf("the establishment was refused with cause %d (%v), want %d",
			cause, err, ie.CauseRequestRejected)
	}
}
