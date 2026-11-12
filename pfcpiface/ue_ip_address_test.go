// SPDX-FileCopyrightText: 2026 Balázs Toldi
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"net"
	"net/netip"
	"testing"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// The flags octet of the UE IP Address IE (TS 29.244 clause 8.2.62). Bit 1 is the least
// significant bit of the octet.
const (
	ueIPFlagV6   uint8 = 0x01 // bit 1: an IPv6 address is present (unless CHV6)
	ueIPFlagV4   uint8 = 0x02 // bit 2: an IPv4 address is present (unless CHV4)
	ueIPFlagCHV4 uint8 = 0x10 // bit 5: the UP function is to choose the IPv4 address
	ueIPFlagCHV6 uint8 = 0x20 // bit 6: the UP function is to choose the IPv6 address
)

const (
	testUEIPv4 = "10.250.0.1"
	testUEIPv6 = "2001:db8::1"
)

// TestFlagBitHelpers checks every hasNthBit helper against every octet. has5thBit used
// to compare the masked octet with 1, which no value other than bit 1 can equal, so it
// never saw CHV4.
func TestFlagBitHelpers(t *testing.T) {
	helpers := []struct {
		name string
		bit  uint
		fn   func(uint8) bool
	}{
		{"has1stBit", 1, has1stBit},
		{"has2ndBit", 2, has2ndBit},
		{"has5thBit", 5, has5thBit},
		{"has6thBit", 6, has6thBit},
	}

	for _, h := range helpers {
		for f := range 256 {
			want := f&(1<<(h.bit-1)) != 0
			if got := h.fn(uint8(f)); got != want {
				t.Errorf("%s(0x%02x) = %v, want %v", h.name, f, got, want)
			}
		}
	}
}

// TestNeedAllocIPOnlyForCHV4 pins the allocation decision to the one flag that asks for
// it. An IE that carries no IPv4 address is not, by itself, a request to allocate one.
func TestNeedAllocIPOnlyForCHV4(t *testing.T) {
	tests := []struct {
		name  string
		flags uint8
		want  bool
	}{
		{"V4: address supplied", ueIPFlagV4, false},
		{"CHV4 alone", ueIPFlagCHV4, true},
		{"V4 and CHV4", ueIPFlagV4 | ueIPFlagCHV4, true},
		{"CHV4 and CHV6", ueIPFlagCHV4 | ueIPFlagCHV6, true},
		{"V6: IPv6 address only", ueIPFlagV6, false},
		{"V4 and V6: both addresses supplied", ueIPFlagV4 | ueIPFlagV6, false},
		{"V6 and CHV6: choose IPv6 only", ueIPFlagV6 | ueIPFlagCHV6, false},
		{"no flags at all", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := needAllocIP(&ie.UEIPAddressFields{Flags: tt.flags}); got != tt.want {
				t.Errorf("needAllocIP(flags=0x%02x) = %v, want %v", tt.flags, got, tt.want)
			}
		})
	}
}

// ueAddressPDR is a downlink Create PDR whose PDI carries ueIP and nothing else that
// could fail, so the UE IP Address IE decides whether it is accepted.
func ueAddressPDR(ueIP *ie.IE) *ie.IE {
	return ie.NewCreatePDR(
		ie.NewPDRID(downlinkPDRID),
		ie.NewPrecedence(0),
		ie.NewPDI(
			ie.NewSourceInterface(ie.SrcInterfaceCore),
			ueIP,
		),
		ie.NewFARID(downlinkFARID),
	)
}

// rejectUEAddress sends a one-PDR establishment carrying ueIP and asserts that it was
// refused with Request Rejected, the cause the establishment handler gives every PDR
// that fails to parse.
func rejectUEAddress(t *testing.T, pConn *PFCPConn, ueIP *ie.IE) {
	t.Helper()

	sereq := message.NewSessionEstablishmentRequest(0, 0, 0, 1, 0,
		ie.NewNodeID("", "", testRemoteNodeID),
		ie.NewFSEID(0xC0FFEE, net.ParseIP("127.0.0.1"), nil),
		ueAddressPDR(ueIP),
		downlinkFAR(),
	)

	rsp, err := pConn.handleSessionEstablishmentRequest(sereq)
	if err == nil {
		t.Fatal("the establishment was accepted")
	}

	seres, ok := rsp.(*message.SessionEstablishmentResponse)
	if !ok {
		t.Fatalf("expected a Session Establishment Response, got %T", rsp)
	}

	if seres.Cause == nil {
		t.Fatal("the rejection carries no Cause IE")
	}

	cause, err := seres.Cause.Cause()
	if err != nil {
		t.Fatalf("could not read the Cause of the rejection: %v", err)
	}

	if cause != ie.CauseRequestRejected {
		t.Fatalf("the establishment was refused with cause %d, expected %d (Request Rejected)",
			cause, ie.CauseRequestRejected)
	}

	if len(seres.CreatedPDR) != 0 {
		t.Error("the rejection reports a Created PDR")
	}
}

// establishWithUEAddress sends a one-PDR establishment that is expected to be accepted
// and returns the response. Rejections are asserted with rejectUEAddress instead.
func establishWithUEAddress(t *testing.T, pConn *PFCPConn, ueIP *ie.IE) *message.SessionEstablishmentResponse {
	t.Helper()

	sereq := message.NewSessionEstablishmentRequest(0, 0, 0, 1, 0,
		ie.NewNodeID("", "", testRemoteNodeID),
		ie.NewFSEID(0xC0FFEE, net.ParseIP("127.0.0.1"), nil),
		ueAddressPDR(ueIP),
		downlinkFAR(),
	)

	rsp, err := pConn.handleSessionEstablishmentRequest(sereq)
	if err != nil {
		t.Fatalf("establishment refused: %v", err)
	}

	seres, ok := rsp.(*message.SessionEstablishmentResponse)
	if !ok {
		t.Fatalf("expected a Session Establishment Response, got %T", rsp)
	}

	return seres
}

// createdUEAddress returns the IPv4 address reported in the response's Created PDR, or
// nil when the response reports none.
func createdUEAddress(t *testing.T, seres *message.SessionEstablishmentResponse) net.IP {
	t.Helper()

	for _, created := range seres.CreatedPDR {
		fields, err := created.UEIPAddress()
		if err != nil {
			continue
		}

		return fields.IPv4Address
	}

	return nil
}

// TestAnIPv6OnlyUEAddressIsRejectedWithoutAPool is the default deployment:
// enable_ue_ip_alloc is off, so there is no pool. An IPv6-only UE IP Address IE used to
// be taken as a request to allocate an IPv4 address from that absent pool, and the
// agent dereferenced the nil pool and exited.
func TestAnIPv6OnlyUEAddressIsRejectedWithoutAPool(t *testing.T) {
	pConn := establishingConn(t, nil)

	rejectUEAddress(t, pConn, ie.NewUEIPAddress(ueIPFlagV6, "", testUEIPv6, 0, 0))
}

// TestAnIPv6OnlyUEAddressAllocatesNothing is the same IE where a pool exists. The
// session used to be accepted with an IPv4 address the control plane never asked for.
func TestAnIPv6OnlyUEAddressAllocatesNothing(t *testing.T) {
	pool, err := NewIPPool(tinyPoolCIDR)
	if err != nil {
		t.Fatal(err)
	}

	pConn := establishingConn(t, pool)

	rejectUEAddress(t, pConn, ie.NewUEIPAddress(ueIPFlagV6, "", testUEIPv6, 0, 0))

	assertPoolIsWhole(t, pool, "an establishment with an IPv6-only UE address")
}

// TestChooseIPv6AloneIsRejected: CHV6 asks the UPF to choose an IPv6 address, which it
// cannot do, and there is no IPv4 part to fall back on.
func TestChooseIPv6AloneIsRejected(t *testing.T) {
	pool, err := NewIPPool(tinyPoolCIDR)
	if err != nil {
		t.Fatal(err)
	}

	pConn := establishingConn(t, pool)

	rejectUEAddress(t, pConn, ie.NewUEIPAddress(ueIPFlagV6|ueIPFlagCHV6, "", "", 0, 0))

	assertPoolIsWhole(t, pool, "an establishment asking the UPF to choose an IPv6 address")
}

// TestAUEAddressWithNoFlagsIsRejected is the reproduction from omec-project/upf#381: an
// IE that neither carries an address nor asks for one is refused, pool or not.
func TestAUEAddressWithNoFlagsIsRejected(t *testing.T) {
	t.Run("without a pool", func(t *testing.T) {
		pConn := establishingConn(t, nil)

		rejectUEAddress(t, pConn, ie.NewUEIPAddress(0, "", "", 0, 0))
	})

	t.Run("with a pool", func(t *testing.T) {
		pool, err := NewIPPool(tinyPoolCIDR)
		if err != nil {
			t.Fatal(err)
		}

		pConn := establishingConn(t, pool)

		rejectUEAddress(t, pConn, ie.NewUEIPAddress(0, "", "", 0, 0))

		assertPoolIsWhole(t, pool, "an establishment with an empty UE address")
	})
}

// TestChooseIPv4WithoutAPoolIsRejected: a control plane that asks the UPF to choose
// while enable_ue_ip_alloc is off gets a rejection, not a crashed agent.
func TestChooseIPv4WithoutAPoolIsRejected(t *testing.T) {
	pConn := establishingConn(t, nil)

	rejectUEAddress(t, pConn, ie.NewUEIPAddress(ueIPFlagCHV4, "", "", 0, 0))
}

// TestChooseIPv4Allocates covers CHV4 alone, which is what TS 29.244 specifies and what
// the omec-project SMF sends, and CHV4 with V4. The clause says V4 shall not be set with
// CHV4, but go-pfcp decodes that IE as carrying no IPv4 address (the address is present
// only when V4 is set and CHV4 is not), so the only reading that does not drop the
// request is CHV4's. It used to be read as "address supplied" and refused for its
// missing address.
func TestChooseIPv4Allocates(t *testing.T) {
	for _, flags := range []uint8{
		ueIPFlagCHV4,
		ueIPFlagV4 | ueIPFlagCHV4,
	} {
		pool, err := NewIPPool(tinyPoolCIDR)
		if err != nil {
			t.Fatal(err)
		}

		pConn := establishingConn(t, pool)

		seres := establishWithUEAddress(t, pConn, ie.NewUEIPAddress(flags, "", "", 0, 0))
		assertAccepted(t, seres.Cause, "establishment")

		got := createdUEAddress(t, seres)
		if got == nil || !net.ParseIP("10.251.0.1").Equal(got) {
			t.Errorf("flags=0x%02x: the response reports UE address %v, want the pool's first "+
				"address 10.251.0.1", flags, got)
		}
	}
}

// TestASuppliedIPv4AddressIsUsedAsIs is the ordinary IPv4 case, with and without a pool:
// the address is taken from the IE, nothing is allocated, and nothing is reported back.
func TestASuppliedIPv4AddressIsUsedAsIs(t *testing.T) {
	for _, withPool := range []bool{false, true} {
		var pool *IPPool

		if withPool {
			var err error

			pool, err = NewIPPool(tinyPoolCIDR)
			if err != nil {
				t.Fatal(err)
			}
		}

		pConn := establishingConn(t, pool)

		seres := establishWithUEAddress(t, pConn, ie.NewUEIPAddress(ueIPFlagV4, testUEIPv4, "", 0, 0))
		assertAccepted(t, seres.Cause, "establishment")

		if got := createdUEAddress(t, seres); got != nil {
			t.Errorf("pool=%v: the response reports allocated UE address %v for a session "+
				"whose address the control plane supplied", withPool, got)
		}

		if withPool {
			assertPoolIsWhole(t, pool, "an establishment with a supplied IPv4 address")
		}
	}
}

// TestTheIPv6PartOfADualStackUEAddressIsIgnored keeps what an IPv4v6 IE did before: the
// IPv4 part is installed and the IPv6 part, which the datapath cannot use yet, is
// ignored. CHV6 next to an IPv4 part is ignored the same way.
func TestTheIPv6PartOfADualStackUEAddressIsIgnored(t *testing.T) {
	t.Run("both addresses supplied", func(t *testing.T) {
		pConn := establishingConn(t, nil)

		seres := establishWithUEAddress(t, pConn,
			ie.NewUEIPAddress(ueIPFlagV4|ueIPFlagV6, testUEIPv4, testUEIPv6, 0, 0))
		assertAccepted(t, seres.Cause, "establishment")
	})

	t.Run("choose both", func(t *testing.T) {
		pool, err := NewIPPool(tinyPoolCIDR)
		if err != nil {
			t.Fatal(err)
		}

		pConn := establishingConn(t, pool)

		seres := establishWithUEAddress(t, pConn,
			ie.NewUEIPAddress(ueIPFlagV4|ueIPFlagV6|ueIPFlagCHV4|ueIPFlagCHV6, "", "", 0, 0))
		assertAccepted(t, seres.Cause, "establishment")

		if got := createdUEAddress(t, seres); got == nil {
			t.Error("the response reports no allocated IPv4 address")
		}
	})
}

// TestTheParsedPDRCarriesTheSuppliedIPv4Address checks the rule itself, not only the
// response: the IPv4 part of an IPv4v6 IE is what lands in the PDR.
func TestTheParsedPDRCarriesTheSuppliedIPv4Address(t *testing.T) {
	var p pdr

	err := p.parseUEAddressIE(ie.NewUEIPAddress(ueIPFlagV4|ueIPFlagV6, testUEIPv4, testUEIPv6, 0, 0), nil)
	if err != nil {
		t.Fatalf("parseUEAddressIE: %v", err)
	}

	if want := netip.MustParseAddr(testUEIPv4); p.ueAddress != want {
		t.Errorf("ueAddress = %v, want %v", p.ueAddress, testUEIPv4)
	}

	if p.allocIPFlag {
		t.Error("allocIPFlag is set for an address the control plane supplied")
	}
}

func TestANilPoolAllocatesNothing(t *testing.T) {
	var pool *IPPool

	ip, err := pool.LookupOrAllocIP(1)
	if err == nil {
		t.Fatalf("LookupOrAllocIP on a nil pool returned %v and no error", ip)
	}

	if s := pool.String(); s == "" {
		t.Error("String on a nil pool returned nothing")
	}
}
