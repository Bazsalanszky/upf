// SPDX-FileCopyrightText: 2026 Balázs Toldi
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"math"
	"net"
	"net/netip"
	"slices"
	"testing"

	pb "github.com/omec-project/upf-epc/pfcpiface/bess_pb"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// IPv6 UE sessions (stage 3): the PDRs of IPv6 packets in pdrLookup6, the SMF's router
// solicitation (UP2CP) and advertisement (CP2UP) rules, and the FAR to the CP-function.

const (
	// The SMF's UP2CP filter (smf ipv6/router-advertisement).
	flowRouterSolicitation = "permit out 58 from ff02::2/128 to assigned"
	testSMFGtpu            = "10.10.3.101"
	// The UE prefix of testUEIPv6Full, 2a0e:8f02:f07b:500::/64, as pdrLookup6 holds it.
	testUEPrefixHi = 0x2a0e8f02f07b0500
	allOnes32      = math.MaxUint32
	allOnes64      = uint64(math.MaxUint64)
)

// takeAll returns every call since the last take, in the order made.
func (c *callRecorder) takeAll() []moduleCall {
	c.mu.Lock()
	defer c.mu.Unlock()

	out := c.calls
	c.calls = nil

	return out
}

func only(calls []moduleCall, module, cmd string) []moduleCall {
	var out []moduleCall

	for _, c := range calls {
		if c.module == module && c.cmd == cmd {
			out = append(out, c)
		}
	}

	return out
}

func fieldValues(t *testing.T, fs []*pb.FieldData) []uint64 {
	t.Helper()

	out := make([]uint64, 0, len(fs))
	for _, f := range fs {
		out = append(out, fieldValue(t, f))
	}

	return out
}

func TestIPv6PrefixFields(t *testing.T) {
	for _, tc := range []struct {
		prefix                 string
		hi, lo, hiMask, loMask uint64
	}{
		{"", 0, 0, 0, 0},
		{"::/0", 0, 0, 0, 0},
		{"2a0e:8f02:f07b:500::/56", 0x2a0e8f02f07b0500, 0, 0xffffffffffffff00, 0},
		// The interface identifier the SMF sends is masked off.
		{"2a0e:8f02:f07b:500:1:2:3:4/64", testUEPrefixHi, 0, allOnes64, 0},
		{"ff02::2/128", 0xff02000000000000, 2, allOnes64, allOnes64},
		{"2001:db8::1:0/112", 0x20010db800000000, 0x10000, allOnes64, 0xffffffffffff0000},
	} {
		t.Run(tc.prefix, func(t *testing.T) {
			var p netip.Prefix
			if tc.prefix != "" {
				p = netip.MustParsePrefix(tc.prefix)
			}

			hi, lo, hiMask, loMask := ipv6PrefixFields(p)
			if hi != tc.hi || lo != tc.lo || hiMask != tc.hiMask || loMask != tc.loMask {
				t.Errorf("ipv6PrefixFields(%v) = %#x %#x / %#x %#x, want %#x %#x / %#x %#x",
					p, hi, lo, hiMask, loMask, tc.hi, tc.lo, tc.hiMask, tc.loMask)
			}
		})
	}
}

// The pdrLookup6 key, field by field, as BESS's module test (gtpu_ue_ipv6.py) programs
// it: src_iface, teid, src_ip6_hi, src_ip6_lo, dst_ip6_hi, dst_ip6_lo, l4_ports, ip_proto.
func TestPdrLookup6Keys(t *testing.T) {
	ueV6 := ie.NewUEIPAddress(ueIPFlagV6|ueIPFlagIP6L, "", testUEIPv6Full, 0, 64)
	dual := ie.NewUEIPAddress(ueIPFlagV4|ueIPFlagV6|ueIPFlagIP6L, testUEIPv4, testUEIPv6Full, 0, 64)

	for _, tc := range []struct {
		name          string
		pdr           *ie.IE
		wantIPv4      bool
		values, masks []uint64
	}{
		{
			name: "IPv6 UE, downlink",
			pdr: goldenPDR(2, 255, 2, []*ie.IE{
				ie.NewSourceInterface(ie.SrcInterfaceCore), ueV6,
				ie.NewSDFFilter(flowAnyToAssigned, "", "", "", 0),
			}),
			values: []uint64{core, 0, 0, 0, testUEPrefixHi, 0, 0, 0},
			masks:  []uint64{0xff, 0, 0, 0, allOnes64, 0, 0, 0},
		},
		{
			name: "IPv6 UE, uplink",
			pdr: goldenPDR(1, 255, 1, []*ie.IE{
				ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, 0x100, net.ParseIP("10.10.3.1"), nil, 0), ueV6,
				ie.NewSDFFilter(flowAnyToAssigned, "", "", "", 0),
			}, ie.NewOuterHeaderRemoval(6, 0)),
			values: []uint64{access, 0x100, testUEPrefixHi, 0, 0, 0, 0, 0},
			masks:  []uint64{0xff, allOnes32, allOnes64, 0, 0, 0, 0, 0},
		},
		{
			name: "IPv4v6 UE, downlink, TCP from a host port",
			pdr: goldenPDR(2, 10, 2, []*ie.IE{
				ie.NewSourceInterface(ie.SrcInterfaceCore), dual,
				ie.NewSDFFilter("permit out 6 from 2001:db8::7 443 to assigned", "", "", "", 0),
			}),
			values: []uint64{core, 0, 0x20010db800000000, 7, testUEPrefixHi, 0, 443 << 16, 6},
			masks:  []uint64{0xff, 0, allOnes64, allOnes64, allOnes64, 0, 0xffff << 16, 0xff},
		},
		{
			// The SMF's UP2CP PDR: precedence 0, no UE IP Address, the session's F-TEID.
			name: "router solicitation (UP2CP)",
			pdr: goldenPDR(3, 0, 3, []*ie.IE{
				ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, 0x100, net.ParseIP("10.10.3.1"), nil, 0),
				ie.NewSDFFilter(flowRouterSolicitation, "", "", "", 0),
			},
				ie.NewOuterHeaderRemoval(6, 0)),
			values: []uint64{access, 0x100, 0, 0, 0xff02000000000000, 2, 0, 58},
			masks:  []uint64{0xff, allOnes32, 0, 0, allOnes64, allOnes64, 0, 0xff},
		},
		{
			// The SMF's CP2UP PDR: its own F-TEID, on any interface, either family.
			name: "router advertisement (CP2UP)",
			pdr: goldenPDR(4, 255, 2, []*ie.IE{
				ie.NewSourceInterface(ie.SrcInterfaceCPFunction),
				ie.NewFTEID(0x01, 0x200, net.ParseIP("10.10.3.1"), nil, 0),
			},
				ie.NewOuterHeaderRemoval(6, 0)),
			wantIPv4: true,
			values:   []uint64{0, 0x200, 0, 0, 0, 0, 0, 0},
			masks:    []uint64{0, allOnes32, 0, 0, 0, 0, 0, 0},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var p pdr
			if err := p.parsePDR(tc.pdr, 1, nil, nil); err != nil {
				t.Fatalf("parsePDR() = %v", err)
			}

			if p.installsIPv4Rule() != tc.wantIPv4 {
				t.Errorf("installsIPv4Rule() = %v, want %v", p.installsIPv4Rule(), tc.wantIPv4)
			}

			keys, err := p.pdrLookup6Keys()
			if err != nil || len(keys) != 1 {
				t.Fatalf("pdrLookup6Keys() = %d keys, %v; want one", len(keys), err)
			}

			if got := fieldValues(t, keys[0].values); !slices.Equal(got, tc.values) {
				t.Errorf("values %#x, want %#x", got, tc.values)
			}

			if got := fieldValues(t, keys[0].masks); !slices.Equal(got, tc.masks) {
				t.Errorf("masks %#x, want %#x", got, tc.masks)
			}
		})
	}
}

// A port range is one pdrLookup6 rule per ternary rule, as in pdrLookup.
func TestAPortRangeIsOneIPv6RulePerTernaryRule(t *testing.T) {
	var p pdr
	if err := p.parsePDR(goldenPDR(2, 10, 2, []*ie.IE{
		ie.NewSourceInterface(ie.SrcInterfaceCore),
		ie.NewUEIPAddress(ueIPFlagV6|ueIPFlagIP6L, "", testUEIPv6Full, 0, 64),
		ie.NewSDFFilter("permit out 17 from 2001:db8::/32 8000-8010 to assigned", "", "", "", 0),
	}), 1, nil, nil); err != nil {
		t.Fatalf("parsePDR() = %v", err)
	}

	keys, err := p.pdrLookup6Keys()
	if err != nil {
		t.Fatal(err)
	}

	want, err := CreatePortRangeCartesianProduct(p.appFilter6.srcPortRange, p.appFilter6.dstPortRange)
	if err != nil {
		t.Fatal(err)
	}

	if len(keys) != len(want) || len(keys) < 2 {
		t.Fatalf("%d rules, want %d (more than one)", len(keys), len(want))
	}

	for i, k := range keys {
		ports, mask := fieldValue(t, k.values[6]), fieldValue(t, k.masks[6])
		if ports != uint64(want[i].srcPort)<<16 || mask != uint64(want[i].srcMask)<<16 {
			t.Errorf("rule %d: l4_ports %#x/%#x, want %#x/%#x", i, ports, mask,
				uint64(want[i].srcPort)<<16, uint64(want[i].srcMask)<<16)
		}
	}
}

// ipv6Session establishes a session of the given PDRs and FARs on a recording datapath,
// and returns its connection, recorder, local SEID and the establishment's calls.
func ipv6Session(t *testing.T, rules ...*ie.IE) (*PFCPConn, *callRecorder, uint64, []moduleCall) {
	t.Helper()

	pConn, rec, _ := n3v6Conn(t, testN3v4, netip.Addr{}, "")

	sereq := message.NewSessionEstablishmentRequest(0, 0, 0, 1, 0,
		append([]*ie.IE{
			ie.NewNodeID("", "", testRemoteNodeID),
			ie.NewFSEID(0x1001, net.ParseIP("10.10.4.2"), nil),
		}, rules...)...)

	rsp, err := pConn.handleSessionEstablishmentRequest(sereq)
	if err != nil {
		t.Fatalf("establishment refused: %v", err)
	}

	seres, ok := rsp.(*message.SessionEstablishmentResponse)
	if !ok {
		t.Fatalf("expected a Session Establishment Response, got %T", rsp)
	}

	assertAccepted(t, seres.Cause, "establishment")

	fseid, err := seres.UPFSEID.FSEID()
	if err != nil {
		t.Fatal(err)
	}

	return pConn, rec, fseid.SEID, rec.takeAll()
}

// establishedCalls is ipv6Session's establishment calls alone.
func establishedCalls(t *testing.T, rules ...*ie.IE) []moduleCall {
	t.Helper()

	_, _, _, calls := ipv6Session(t, rules...) //nolint:dogsled // the calls are all a caller needs

	return calls
}

func forwardFAR(id uint32, dst uint8, ohc ...*ie.IE) *ie.IE {
	return ie.NewCreateFAR(ie.NewFARID(id), ie.NewApplyAction(ActionForward),
		ie.NewForwardingParameters(append([]*ie.IE{ie.NewDestinationInterface(dst)}, ohc...)...))
}

// An IPv6 PDU session is rules in pdrLookup6 only, and its deletion removes exactly the
// keys it added.
func TestAnIPv6SessionIsPdrLookup6RulesOnly(t *testing.T) {
	ueV6 := ie.NewUEIPAddress(ueIPFlagV6|ueIPFlagIP6L, "", testUEIPv6Full, 0, 64)
	pConn, rec, seid, calls := ipv6Session(t,
		goldenPDR(1, 255, 1, []*ie.IE{
			ie.NewSourceInterface(ie.SrcInterfaceAccess),
			ie.NewFTEID(0x0d, 0, nil, nil, 1), // CH, CHID 1, V4
			ueV6,
			ie.NewSDFFilter(flowAnyToAssigned, "", "", "", 0),
		}, ie.NewOuterHeaderRemoval(6, 0)),
		goldenPDR(2, 255, 2, []*ie.IE{
			ie.NewSourceInterface(ie.SrcInterfaceCore),
			ueV6,
			ie.NewSDFFilter(flowAnyToAssigned, "", "", "", 0),
		}),
		forwardFAR(1, ie.DstInterfaceCore),
		forwardFAR(2, ie.DstInterfaceAccess, ie.NewOuterHeaderCreation(0x0100, 0xabcd, "10.10.3.200", "", 0, 0, 0)),
	)

	if got := only(calls, "pdrLookup", upfMethodAdd); len(got) != 0 {
		t.Errorf("an IPv6 session added %d pdrLookup rules", len(got))
	}

	added := only(calls, PdrLookup6, upfMethodAdd)
	if len(added) != 2 {
		t.Fatalf("an IPv6 session of two PDRs added %d pdrLookup6 rules", len(added))
	}

	if _, err := pConn.handleSessionDeletionRequest(
		message.NewSessionDeletionRequest(0, 0, seid, 3, 0)); err != nil {
		t.Fatalf("deletion refused: %v", err)
	}

	deleted := only(rec.takeAll(), PdrLookup6, upfMethodDelete)
	if len(deleted) != len(added) {
		t.Fatalf("deleted %d pdrLookup6 rules, added %d", len(deleted), len(added))
	}

	key := func(values, masks []*pb.FieldData) string {
		return string(uintsToBytes(fieldValues(t, values))) + "/" + string(uintsToBytes(fieldValues(t, masks)))
	}

	var addKeys, delKeys []string

	for _, c := range added {
		a := c.arg.(*pb.WildcardMatchCommandAddArg)
		addKeys = append(addKeys, key(a.GetValues(), a.GetMasks()))
	}

	for _, c := range deleted {
		d := c.arg.(*pb.WildcardMatchCommandDeleteArg)
		delKeys = append(delKeys, key(d.GetValues(), d.GetMasks()))
	}

	slices.Sort(addKeys)
	slices.Sort(delKeys)

	if !slices.Equal(addKeys, delKeys) {
		t.Error("the deletion's pdrLookup6 keys are not the establishment's")
	}
}

func uintsToBytes(vs []uint64) []byte {
	out := make([]byte, 0, 8*len(vs))
	for _, v := range vs {
		for i := 7; i >= 0; i-- {
			out = append(out, byte(v>>(8*i)))
		}
	}

	return out
}

// The SMF's router solicitation path (TS 23.501 clause 5.8.2.2.3): UP2CP, a PDR on the
// uplink F-TEID (same CHOOSE ID) for ICMPv6 to ff02::2, to a FAR that tunnels it to the
// SMF's GTP-U endpoint through access. The PDR is an IPv6 rule only, and the FAR forwards
// with an outer header from the access address.
func TestTheSMFsRouterSolicitationPath(t *testing.T) {
	dual := ie.NewUEIPAddress(ueIPFlagV4|ueIPFlagV6|ueIPFlagIP6L, testUEIPv4, testUEIPv6Full, 0, 64)

	calls := establishedCalls(t,
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

	// The UL PDR in both tables, UP2CP in pdrLookup6 only, sharing the TEID.
	if got := only(calls, "pdrLookup", upfMethodAdd); len(got) != 1 {
		t.Errorf("%d pdrLookup rules, want the UL PDR's one", len(got))
	}

	added := only(calls, PdrLookup6, upfMethodAdd)
	if len(added) != 2 {
		t.Fatalf("%d pdrLookup6 rules, want the UL PDR's and UP2CP's", len(added))
	}

	var teids []uint64

	for _, c := range added {
		a := c.arg.(*pb.WildcardMatchCommandAddArg)
		teids = append(teids, fieldValue(t, a.GetValues()[1]))

		if fieldValue(t, a.GetValues()[7]) == 58 && a.GetPriority() != math.MaxUint32 {
			t.Errorf("UP2CP priority %d, want the highest (precedence 0)", a.GetPriority())
		}
	}

	if teids[0] == 0 || teids[0] != teids[1] {
		t.Errorf("TEIDs %v: UP2CP does not share the uplink F-TEID", teids)
	}

	var far3 *pb.ExactMatchCommandAddArg

	for _, c := range only(calls, farLookup, upfMethodAdd) {
		a := c.arg.(*pb.ExactMatchCommandAddArg)
		if fieldValue(t, a.GetFields()[0]) == 3 {
			far3 = a
		}
	}

	if far3 == nil {
		t.Fatal("no farLookup rule for the UP2CP FAR")
	}

	got := fieldValues(t, far3.GetValues())
	if want := []uint64{farForwardD, farGateEncap, 0x0a0a0301, 0x0a0a0365, 0x1001, tunnelGTPUPort}; !slices.Equal(got, want) {
		t.Errorf("UP2CP FAR values %#x, want %#x (forward to access, encap 10.10.3.1 -> %s)", got, want, testSMFGtpu)
	}
}

// The SMF's router advertisement path: CP2UP, a CP-function PDR on its own F-TEID, to the
// session's downlink FAR. It is a rule in both tables on any interface: the SMF reaches the
// UPF on whichever interface routes to it.
func TestTheSMFsRouterAdvertisementPDR(t *testing.T) {
	calls := establishedCalls(t,
		goldenPDR(4, 255, 2, []*ie.IE{
			ie.NewSourceInterface(ie.SrcInterfaceCPFunction),
			ie.NewFTEID(0x05, 0, nil, nil, 0), // CH, V4
		}, ie.NewOuterHeaderRemoval(6, 0)),
		forwardFAR(2, ie.DstInterfaceAccess, ie.NewOuterHeaderCreation(0x0100, 0xabcd, "10.10.3.200", "", 0, 0, 0)),
	)

	v4 := only(calls, "pdrLookup", upfMethodAdd)
	v6 := only(calls, PdrLookup6, upfMethodAdd)

	if len(v4) != 1 || len(v6) != 1 {
		t.Fatalf("%d pdrLookup and %d pdrLookup6 rules, want one each", len(v4), len(v6))
	}

	for _, a := range []*pb.WildcardMatchCommandAddArg{
		v4[0].arg.(*pb.WildcardMatchCommandAddArg), v6[0].arg.(*pb.WildcardMatchCommandAddArg),
	} {
		if fieldValue(t, a.GetValues()[0]) != 0 || fieldValue(t, a.GetMasks()[0]) != 0 {
			t.Errorf("src_iface %d/%d, want any", fieldValue(t, a.GetValues()[0]), fieldValue(t, a.GetMasks()[0]))
		}

		if a.GetGate() != 1 {
			t.Errorf("gate %d, want GTPUDecap (1)", a.GetGate())
		}
	}
}

func TestACPFunctionFARSendsThroughTheConfiguredInterface(t *testing.T) {
	for _, tc := range []struct {
		via        uint8
		wantAction uint8
		wantSrc    netip.Addr
	}{
		{ie.DstInterfaceAccess, farForwardD, testN3v4},
		{ie.DstInterfaceCore, farForwardU, netip.MustParseAddr("10.10.6.1")},
	} {
		u := &upf{accessIP: ipFromAddr(testN3v4), coreIP: net.ParseIP("10.10.6.1"), cpFunctionIntf: tc.via}

		var f far
		if err := f.parseFAR(forwardFAR(3, ie.DstInterfaceCPFunction,
			ie.NewOuterHeaderCreation(0x0100, 0x1001, testSMFGtpu, "", 0, 0, 0)), 1, u, create); err != nil {
			t.Fatalf("parseFAR() = %v", err)
		}

		if got := (&bess{}).setActionValue(f); got != tc.wantAction {
			t.Errorf("via %d: action %d, want %d", tc.via, got, tc.wantAction)
		}

		if f.tunnelIPSrc != tc.wantSrc {
			t.Errorf("via %d: tunnel source %v, want %v", tc.via, f.tunnelIPSrc, tc.wantSrc)
		}
	}
}

func TestCPFunctionInterfaceConfig(t *testing.T) {
	for _, tc := range []struct {
		value   string
		wantErr bool
	}{
		{"", false}, {"access", false}, {"core", false}, {"n6", true},
	} {
		confPath := t.TempDir() + "/conf.jsonc"
		mustWriteStringToDisk(`{"mode": "dpdk", "cpiface": {"cp_function_interface": "`+tc.value+`"}}`, confPath)

		conf, err := LoadConfigFile(confPath)
		if (err != nil) != tc.wantErr {
			t.Errorf("cp_function_interface %q: LoadConfigFile() = %v, wantErr %v", tc.value, err, tc.wantErr)
		}

		if err == nil && conf.CPIface.CPFunctionInterface != tc.value {
			t.Errorf("cp_function_interface %q read as %q", tc.value, conf.CPIface.CPFunctionInterface)
		}
	}
}

// An IPv6 rule on "assigned" for a UE with only an IPv4 address would match every UE's
// IPv6 traffic: refused, before the datapath.
func TestAnIPv6AssignedFilterOfAnIPv4UEIsRefused(t *testing.T) {
	pConn, client, _ := goldenConn(t, nil)

	assertRequestRejected(t, pConn,
		goldenPDR(2, 255, 1, []*ie.IE{
			ie.NewSourceInterface(ie.SrcInterfaceCore),
			ie.NewUEIPAddress(ueIPFlagV4, testUEIPv4, "", 0, 0),
			ie.NewSDFFilter("permit out ip from 2001:db8::/32 to assigned", "", "", "", 0),
		}),
	)

	if got := client.take(); len(got) != 0 {
		t.Errorf("the datapath was sent %v", got)
	}
}
