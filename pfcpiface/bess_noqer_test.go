// SPDX-FileCopyrightText: 2026 Balázs Toldi
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"slices"
	"testing"

	pb "github.com/omec-project/upf-epc/pfcpiface/bess_pb"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// ownQERCalls are the appQERLookup calls (of cmd) for qer_id id, as (src_iface, gate) pairs.
func ownQERCalls(t *testing.T, calls []moduleCall, cmd string, id uint64) [][2]uint64 {
	t.Helper()

	var out [][2]uint64

	for _, c := range only(calls, "appQERLookup", cmd) {
		var fields []*pb.FieldData

		gate := uint64(0)

		switch a := c.arg.(type) {
		case *pb.QosCommandAddArg:
			fields, gate = a.GetFields(), a.GetGate()
		case *pb.QosCommandDeleteArg:
			fields = a.GetFields()
		default:
			t.Fatalf("appQERLookup %s with a %T", cmd, c.arg)
		}

		if fieldValue(t, fields[1]) == id {
			out = append(out, [2]uint64{fieldValue(t, fields[0]), gate})
		}
	}

	slices.SortFunc(out, func(a, b [2]uint64) int { return int(a[0]) - int(b[0]) })

	return out
}

// The SMF's UP2CP PDR has no QER (TS 29.244 clause 7.5.2.2 makes it optional). Its rule
// carries a qer_id of its own, which gets an unmetered appQERLookup entry on access and
// core before the rule, so the router solicitation is not dropped in appQERLookup; the
// deletion removes both. A PDR with a QER, or one with an IPv4 rule, gets none.
func TestAPDRWithoutAQERGetsAnUnmeteredQEROfItsOwn(t *testing.T) {
	dual := ie.NewUEIPAddress(ueIPFlagV4|ueIPFlagV6|ueIPFlagIP6L, testUEIPv4, testUEIPv6Full, 0, 64)
	pConn, rec, seid, calls := ipv6Session(t,
		goldenPDR(1, 255, 1, []*ie.IE{
			ie.NewSourceInterface(ie.SrcInterfaceAccess),
			ie.NewFTEID(0x0d, 0, nil, nil, 1),
			dual,
			ie.NewSDFFilter(flowAnyToAssigned, "", "", "", 0),
		}, ie.NewOuterHeaderRemoval(6, 0)),
		goldenPDR(3, 0, 3, []*ie.IE{
			ie.NewSourceInterface(ie.SrcInterfaceAccess),
			ie.NewFTEID(0x0d, 0, nil, nil, 1),
			ie.NewSDFFilter(flowRouterSolicitation, "", "", "", 0),
		}, ie.NewOuterHeaderRemoval(6, 0)),
		forwardFAR(1, ie.DstInterfaceCore),
		forwardFAR(3, ie.DstInterfaceCPFunction,
			ie.NewOuterHeaderCreation(0x0100, 0x1001, testSMFGtpu, "", 0, 0, 0)),
	)

	const up2cp = uint64(ownQERIDFlag | 3)

	rsIdx := -1

	for i, c := range calls {
		if c.module != PdrLookup6 || c.cmd != upfMethodAdd {
			continue
		}

		a := c.arg.(*pb.WildcardMatchCommandAddArg)
		pdrID, qerID := fieldValue(t, a.GetValuesv()[0]), fieldValue(t, a.GetValuesv()[3])

		switch pdrID {
		case 3:
			if qerID != up2cp {
				t.Errorf("UP2CP qer_id %#x, want %#x", qerID, up2cp)
			}

			rsIdx = i
		case 1:
			// Dual: it has an IPv4 rule, so it keeps qer_id 0 in both tables.
			if qerID != 0 {
				t.Errorf("the dual PDR's pdrLookup6 qer_id %#x, want 0", qerID)
			}
		}
	}

	if rsIdx < 0 {
		t.Fatal("no pdrLookup6 rule for UP2CP")
	}

	want := [][2]uint64{{access, qerGateUnmeter}, {core, qerGateUnmeter}}
	if got := ownQERCalls(t, calls, upfMethodAdd, up2cp); !slices.Equal(got, want) {
		t.Fatalf("UP2CP appQERLookup adds (src_iface, gate) %v, want %v", got, want)
	}

	for i, c := range calls[rsIdx:] {
		if c.module == "appQERLookup" {
			t.Errorf("call %d: appQERLookup %s after UP2CP's rule; its QER must come first", rsIdx+i, c.cmd)
		}
	}

	if got := ownQERCalls(t, calls, upfMethodAdd, 0); len(got) != 0 {
		t.Errorf("appQERLookup adds for qer_id 0: %v; a PDR with an IPv4 rule gets no QER of its own", got)
	}

	if _, err := pConn.handleSessionDeletionRequest(
		message.NewSessionDeletionRequest(0, 0, seid, 3, 0)); err != nil {
		t.Fatalf("deletion refused: %v", err)
	}

	deleted := rec.takeAll()
	if got := ownQERCalls(t, deleted, upfMethodDelete, up2cp); !slices.Equal(got, [][2]uint64{{access, 0}, {core, 0}}) {
		t.Errorf("UP2CP appQERLookup deletes (src_iface) %v, want access and core", got)
	}
}

func TestAppQERID(t *testing.T) {
	v6 := pdr{pdrID: 7, noIPv4Rule: true}
	if got := v6.appQERID(); got != ownQERIDFlag|7 {
		t.Errorf("IPv6-only, no QER: %#x", got)
	}

	withQER := v6
	withQER.qerIDList = []uint32{9, 4}

	if got := withQER.appQERID(); got != 9 || withQER.hasOwnQER() {
		t.Errorf("IPv6-only with QERs: %#x, own %v", got, withQER.hasOwnQER())
	}

	if v4 := (pdr{pdrID: 7}); v4.appQERID() != 0 || v4.hasOwnQER() {
		t.Errorf("IPv4, no QER: %#x, own %v", v4.appQERID(), v4.hasOwnQER())
	}
}
