// SPDX-FileCopyrightText: 2026 Balázs Toldi
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"

	pb "github.com/omec-project/upf-epc/pfcpiface/bess_pb"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

// GTP-U over IPv6 on N3 (stage 2): the F-TEIDs the UPF hands out, the rules it writes to
// pdrLookup, farLookup and farLookup6, path monitoring and end markers.

// farLookup is the FAR table's module name, as bess.go writes it.
const farLookup = "farLookup"

var (
	testN3v4  = netip.MustParseAddr("10.10.3.1")
	testN3v6  = netip.MustParseAddr("2001:db8:630::1")
	testGnbV6 = netip.MustParseAddr("2001:db8:630::10")
)

// moduleCall is one module command pfcpiface sent the datapath.
type moduleCall struct {
	module, cmd string
	arg         proto.Message
}

// callRecorder answers every module command and keeps it, decoded.
type callRecorder struct {
	pb.BESSControlClient

	mu    sync.Mutex
	calls []moduleCall
}

func (c *callRecorder) ModuleCommand(
	_ context.Context, req *pb.CommandRequest, _ ...grpc.CallOption,
) (*pb.CommandResponse, error) {
	var arg proto.Message

	if req.GetArg() != nil {
		var err error
		if arg, err = req.GetArg().UnmarshalNew(); err != nil {
			return nil, err
		}
	}

	c.mu.Lock()
	c.calls = append(c.calls, moduleCall{req.GetName(), req.GetCmd(), arg})
	c.mu.Unlock()

	return &pb.CommandResponse{}, nil
}

// take returns the calls to module made since the last take, in the order made, and
// forgets every call made so far.
func (c *callRecorder) take(module string) []moduleCall {
	c.mu.Lock()
	defer c.mu.Unlock()

	var out []moduleCall

	for _, call := range c.calls {
		if call.module == module {
			out = append(out, call)
		}
	}

	c.calls = nil

	return out
}

// n3v6Conn is goldenConn's connection, with the given N3 addresses and transport family,
// and a recorder that decodes the module commands.
func n3v6Conn(t *testing.T, v4, v6 netip.Addr, family string) (*PFCPConn, *callRecorder, *bess) {
	t.Helper()

	pConn, _, b := goldenConn(t, nil)
	rec := &callRecorder{}
	b.client = rec
	pConn.upf.accessIP = ipFromAddr(v4)
	pConn.upf.accessIP6 = v6
	pConn.upf.n3Family = family
	b.ipv6Tunnels = v6.IsValid()

	return pConn, rec, b
}

func fieldValue(t *testing.T, f *pb.FieldData) uint64 {
	t.Helper()

	v, ok := f.GetEncoding().(*pb.FieldData_ValueInt)
	if !ok {
		t.Fatalf("field %v is not an integer", f)
	}

	return v.ValueInt
}

func low32(a netip.Addr) uint64 {
	b := a.As16()

	return uint64(binary.BigEndian.Uint32(b[12:]))
}

// createdFTEIDs returns the F-TEIDs of the Created PDRs of an establishment response.
func createdFTEIDs(t *testing.T, rsp message.Message) []*ie.FTEIDFields {
	t.Helper()

	seres, ok := rsp.(*message.SessionEstablishmentResponse)
	if !ok {
		t.Fatalf("expected a Session Establishment Response, got %T", rsp)
	}

	assertAccepted(t, seres.Cause, "establishment")

	var out []*ie.FTEIDFields

	for _, created := range seres.CreatedPDR {
		ies, err := created.CreatedPDR()
		if err != nil {
			t.Fatal(err)
		}

		for _, x := range ies {
			if x.Type == ie.FTEID {
				f, err := x.FTEID()
				if err != nil {
					t.Fatal(err)
				}

				out = append(out, f)
			}
		}
	}

	return out
}

func establishN3(t *testing.T, pConn *PFCPConn, seid uint64, rules ...*ie.IE) (message.Message, error) {
	t.Helper()

	ies := append([]*ie.IE{
		ie.NewNodeID("", "", testRemoteNodeID),
		ie.NewFSEID(seid, net.ParseIP("10.10.4.2"), nil),
	}, rules...)

	return pConn.handleSessionEstablishmentRequest(
		message.NewSessionEstablishmentRequest(0, 0, 0, 1, 0, ies...))
}

func uplinkCH(flags uint8) *ie.IE {
	return goldenPDR(1, 255, 1, []*ie.IE{
		ie.NewSourceInterface(ie.SrcInterfaceAccess),
		ie.NewFTEID(flags, 0, nil, nil, 1),
		ie.NewUEIPAddress(0x02, "10.250.0.5", "", 0, 0),
	}, ie.NewOuterHeaderRemoval(0, 0))
}

func coreFAR() *ie.IE {
	return ie.NewCreateFAR(
		ie.NewFARID(1),
		ie.NewApplyAction(ActionForward),
		ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore)),
	)
}

// The F-TEID the UPF chooses: an address of each family the control plane asks for and
// N3 offers.
func TestChosenFTEIDFamilies(t *testing.T) {
	for _, tc := range []struct {
		name       string
		v4, v6     netip.Addr
		family     string
		chFlags    uint8 // CH (0x04) with V4 (0x01) and/or V6 (0x02)
		want4      bool
		want6      bool
		wantReject bool
	}{
		{name: "IPv4 UPF, CH V4", v4: testN3v4, chFlags: 0x05, want4: true},
		{name: "IPv4 UPF, CH V4V6", v4: testN3v4, chFlags: 0x07, want4: true},
		{name: "IPv4 UPF, CH V6", v4: testN3v4, chFlags: 0x06, wantReject: true},
		{name: "dual UPF, CH V4", v4: testN3v4, v6: testN3v6, chFlags: 0x05, want4: true},
		{name: "dual UPF, CH V6", v4: testN3v4, v6: testN3v6, chFlags: 0x06, want6: true},
		{name: "dual UPF, CH V4V6", v4: testN3v4, v6: testN3v6, chFlags: 0x07, want4: true, want6: true},
		{name: "dual UPF, CH alone", v4: testN3v4, v6: testN3v6, chFlags: 0x04, want4: true},
		{
			name: "dual UPF restricted to IPv6, CH V4V6", v4: testN3v4, v6: testN3v6, family: transportFamilyIPv6,
			chFlags: 0x07, want6: true,
		},
		{
			name: "dual UPF restricted to IPv6, CH V4", v4: testN3v4, v6: testN3v6, family: transportFamilyIPv6,
			chFlags: 0x05, wantReject: true,
		},
		{name: "IPv6 UPF, CH V4V6", v6: testN3v6, chFlags: 0x07, want6: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pConn, rec, _ := n3v6Conn(t, tc.v4, tc.v6, tc.family)

			rsp, err := establishN3(t, pConn, 0x3001, uplinkCH(tc.chFlags), coreFAR())
			if tc.wantReject {
				if err == nil {
					t.Fatalf("establishment accepted")
				}

				if got := rec.take("pdrLookup"); len(got) != 0 {
					t.Errorf("the datapath was sent %v", got)
				}

				return
			}

			if err != nil {
				t.Fatalf("establishment refused: %v", err)
			}

			fteids := createdFTEIDs(t, rsp)
			if len(fteids) != 1 {
				t.Fatalf("got %d Created PDR F-TEIDs, want 1", len(fteids))
			}

			f := fteids[0]
			if f.HasIPv4() != tc.want4 || f.HasIPv6() != tc.want6 {
				t.Errorf("F-TEID flags 0x%02x, want V4 %v V6 %v", f.Flags, tc.want4, tc.want6)
			}

			if tc.want4 && addrFromIP(f.IPv4Address) != tc.v4 {
				t.Errorf("F-TEID IPv4 %v, want %v", f.IPv4Address, tc.v4)
			}

			if tc.want6 && addrFromIP(f.IPv6Address) != tc.v6 {
				t.Errorf("F-TEID IPv6 %v, want %v", f.IPv6Address, tc.v6)
			}

			// One pdrLookup rule per address, the IPv6 one by its low 32 bits, with the
			// F-TEID's TEID.
			var want []uint64
			if tc.want4 {
				want = append(want, low32(tc.v4))
			}

			if tc.want6 {
				want = append(want, low32(tc.v6))
			}

			var got []uint64

			for _, call := range rec.take("pdrLookup") {
				arg := call.arg.(*pb.WildcardMatchCommandAddArg)
				got = append(got, fieldValue(t, arg.GetValues()[1]))

				if teid := fieldValue(t, arg.GetValues()[2]); teid != uint64(f.TEID) {
					t.Errorf("rule TEID %#x, want %#x", teid, f.TEID)
				}

				if mask := fieldValue(t, arg.GetMasks()[1]); mask != 0xffffffff {
					t.Errorf("tunnel_ipv4_dst mask %#x", mask)
				}
			}

			if len(got) != len(want) || (len(got) > 0 && got[0] != want[0]) ||
				(len(got) > 1 && got[1] != want[1]) {
				t.Errorf("tunnel_ipv4_dst values %#x, want %#x", got, want)
			}
		})
	}
}

// A downlink FAR to an IPv6 gNB: farLookup6 holds the peer, farLookup sends there; the
// FAR moving to an IPv4 gNB gets an IPv6 end marker for the old tunnel and frees its
// farLookup6 entry.
func TestFARToAnIPv6Peer(t *testing.T) {
	pConn, rec, b := n3v6Conn(t, testN3v4, testN3v6, "")
	enableGtpuPathMonitoring = true

	t.Cleanup(func() { enableGtpuPathMonitoring = false })

	rsp, err := establishN3(t, pConn, 0x3002, uplinkCH(0x07), coreFAR(),
		ie.NewCreateFAR(
			ie.NewFARID(2),
			ie.NewApplyAction(ActionForward),
			ie.NewForwardingParameters(
				ie.NewDestinationInterface(ie.DstInterfaceAccess),
				ie.NewOuterHeaderCreation(0x0200, 0xabcd, "", testGnbV6.String(), 0, 0, 0),
			),
		))
	if err != nil {
		t.Fatalf("establishment refused: %v", err)
	}

	createdFTEIDs(t, rsp)

	rec.mu.Lock()
	calls := rec.calls
	rec.mu.Unlock()

	far6At, far2At := -1, -1

	for i, call := range calls {
		switch {
		case call.module == FarLookup6 && call.cmd == upfMethodAdd:
			far6At = i
			arg := call.arg.(*pb.ExactMatchCommandAddArg)
			hi, lo := ipv6Halves(testGnbV6)

			if fieldValue(t, arg.GetValues()[0]) != hi || fieldValue(t, arg.GetValues()[1]) != lo {
				t.Errorf("farLookup6 values %v, want %#x %#x", arg.GetValues(), hi, lo)
			}

			if arg.GetGate() != farGateEncap || fieldValue(t, arg.GetFields()[0]) != 2 {
				t.Errorf("farLookup6 gate %d, FAR %v", arg.GetGate(), arg.GetFields())
			}
		case call.module == farLookup && call.cmd == upfMethodAdd:
			arg := call.arg.(*pb.ExactMatchCommandAddArg)
			if fieldValue(t, arg.GetFields()[0]) != 2 {
				if arg.GetGate() != 0 {
					t.Errorf("the core FAR has gate %d", arg.GetGate())
				}

				continue
			}

			far2At = i

			if arg.GetGate() != farGateEncap6 {
				t.Errorf("farLookup gate %d, want %d", arg.GetGate(), farGateEncap6)
			}

			if dst := fieldValue(t, arg.GetValues()[3]); dst != 0 {
				t.Errorf("farLookup IPv4 peer %#x, want 0", dst)
			}

			if teid := fieldValue(t, arg.GetValues()[4]); teid != 0xabcd {
				t.Errorf("farLookup TEID %#x", teid)
			}
		case call.module == GtpuPathMonitoringMeasure && call.cmd == upfMethodAdd:
			arg := call.arg.(*pb.GtpuPathMonitoringCommandAddDeleteArg)
			if got, _ := netip.AddrFromSlice(arg.GetGnbIp6()); got != testGnbV6 || arg.GetGnbIp() != 0 {
				t.Errorf("path monitoring of %v / %#x, want %v", got, arg.GetGnbIp(), testGnbV6)
			}
		}
	}

	if far6At < 0 || far2At < 0 || far6At > far2At {
		t.Errorf("farLookup6 written at %d, the FAR in farLookup at %d: want both, farLookup6 first",
			far6At, far2At)
	}

	rec.take("")

	// Handover to an IPv4 gNB, with an end marker on the old tunnel.
	seres := rsp.(*message.SessionEstablishmentResponse)

	fseid, err := seres.UPFSEID.FSEID()
	if err != nil {
		t.Fatal(err)
	}

	_, err = pConn.handleSessionModificationRequest(message.NewSessionModificationRequest(0, 0, fseid.SEID, 2, 0,
		ie.NewUpdateFAR(
			ie.NewFARID(2),
			ie.NewApplyAction(ActionForward),
			ie.NewUpdateForwardingParameters(
				ie.NewDestinationInterface(ie.DstInterfaceAccess),
				ie.NewOuterHeaderCreation(0x0100, 0xabce, "10.10.3.201", "", 0, 0, 0),
				ie.NewPFCPSMReqFlags(0x02),
			),
		)))
	if err != nil {
		t.Fatalf("modification refused: %v", err)
	}

	markers := takeEndMarkerPackets(b)
	if len(markers) != 1 {
		t.Fatalf("got %d end markers, want 1", len(markers))
	}

	checkEndMarker6(t, markers[0], testN3v6, testGnbV6, 0xabcd)

	rec.mu.Lock()
	calls = rec.calls
	rec.calls = nil
	rec.mu.Unlock()

	var deleted6, moved bool

	for _, call := range calls {
		switch {
		case call.module == FarLookup6 && call.cmd == upfMethodDelete:
			deleted6 = true
		case call.module == farLookup && call.cmd == upfMethodAdd:
			arg := call.arg.(*pb.ExactMatchCommandAddArg)
			moved = arg.GetGate() == farGateEncap && fieldValue(t, arg.GetValues()[3]) == 0x0a0a03c9
		case call.module == GtpuPathMonitoringMeasure && call.cmd == upfMethodDelete:
			arg := call.arg.(*pb.GtpuPathMonitoringCommandAddDeleteArg)
			if got, _ := netip.AddrFromSlice(arg.GetGnbIp6()); got != testGnbV6 {
				t.Errorf("path monitoring unregistered %v, want %v", got, testGnbV6)
			}
		}
	}

	if !moved || !deleted6 {
		t.Errorf("FAR moved to the IPv4 gNB %v, its farLookup6 entry deleted %v", moved, deleted6)
	}

	// The session going away deletes farLookup6 nothing more.
	if _, err = pConn.handleSessionDeletionRequest(
		message.NewSessionDeletionRequest(0, 0, fseid.SEID, 3, 0)); err != nil {
		t.Fatalf("deletion refused: %v", err)
	}

	if got := rec.take(FarLookup6); len(got) != 0 {
		t.Errorf("farLookup6 was sent %v", got)
	}
}

func takeEndMarkerPackets(b *bess) [][]byte {
	var out [][]byte

	for {
		select {
		case m := <-b.endMarkerChan:
			out = append(out, m)
		default:
			return out
		}
	}
}

// checkEndMarker6 checks an End Marker over IPv6, including its UDP checksum, which an
// IPv6 receiver checks (RFC 8200 section 8.1).
func checkEndMarker6(t *testing.T, pkt []byte, src, dst netip.Addr, teid uint32) {
	t.Helper()

	if len(pkt) != endMarker6Size || binary.BigEndian.Uint16(pkt[12:]) != 0x86dd || pkt[14]>>4 != 6 {
		t.Fatalf("not an IPv6 frame of %d bytes: %x", endMarker6Size, pkt)
	}

	ip := pkt[14:]
	if binary.BigEndian.Uint16(ip[4:]) != 16 || ip[6] != 17 {
		t.Errorf("payload length %d, next header %d", binary.BigEndian.Uint16(ip[4:]), ip[6])
	}

	if got, _ := netip.AddrFromSlice(ip[8:24]); got != src {
		t.Errorf("source %v, want %v", got, src)
	}

	if got, _ := netip.AddrFromSlice(ip[24:40]); got != dst {
		t.Errorf("destination %v, want %v", got, dst)
	}

	udp := ip[40:]
	gtp := udp[8:]

	if gtp[1] != gtpEndMarkerType || binary.BigEndian.Uint32(gtp[4:]) != teid {
		t.Errorf("GTP-U type %d TEID %#x", gtp[1], binary.BigEndian.Uint32(gtp[4:]))
	}

	// The one's complement sum over the pseudo-header and the datagram, its checksum
	// included, is 0xffff when the checksum is right.
	var sum uint32
	for i := 8; i < 40; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(ip[i:]))
	}

	sum += uint32(len(udp)) + 17
	for i := 0; i < len(udp); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(udp[i:]))
	}

	for sum>>16 != 0 {
		sum = (sum >> 16) + (sum & 0xffff)
	}

	if sum != 0xffff || binary.BigEndian.Uint16(udp[6:]) == 0 {
		t.Errorf("UDP checksum %#04x does not verify (sum %#x)", binary.BigEndian.Uint16(udp[6:]), sum)
	}
}

// An IPv4 FAR on a UPF with IPv6 N3 never touches farLookup6, and is written as before.
func TestIPv4FARLeavesFarLookup6Alone(t *testing.T) {
	pConn, rec, _ := n3v6Conn(t, testN3v4, testN3v6, "")

	_, err := establishN3(t, pConn, 0x3003, uplinkCH(0x05), coreFAR(),
		ie.NewCreateFAR(
			ie.NewFARID(2),
			ie.NewApplyAction(ActionForward),
			ie.NewForwardingParameters(
				ie.NewDestinationInterface(ie.DstInterfaceAccess),
				ie.NewOuterHeaderCreation(0x0100, 0xabcd, "10.10.3.200", "", 0, 0, 0),
			),
		))
	if err != nil {
		t.Fatalf("establishment refused: %v", err)
	}

	rec.mu.Lock()
	defer rec.mu.Unlock()

	for _, call := range rec.calls {
		if call.module == FarLookup6 {
			t.Errorf("farLookup6 was sent %v", call)
		}

		if arg, ok := call.arg.(*pb.ExactMatchCommandAddArg); ok && call.module == farLookup &&
			fieldValue(t, arg.GetFields()[0]) == 2 && arg.GetGate() != farGateEncap {
			t.Errorf("the IPv4 FAR has gate %d", arg.GetGate())
		}
	}
}

func TestOHCPeerChoice(t *testing.T) {
	v4 := netip.MustParseAddr("10.10.3.10")

	for _, tc := range []struct {
		name   string
		v4, v6 netip.Addr
		family string
		want   netip.Addr
	}{
		{name: "IPv4 only", v4: v4, want: v4},
		{name: "IPv6 only", v6: testGnbV6, want: testGnbV6},
		{name: "both given", v4: v4, v6: testGnbV6, want: v4},
		{name: "both, N3 restricted to IPv4", v4: v4, v6: testGnbV6, family: transportFamilyIPv4, want: v4},
		{name: "both, N3 restricted to IPv6", v4: v4, v6: testGnbV6, family: transportFamilyIPv6, want: testGnbV6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ohcPeer(tc.v4, tc.v6, tc.family); got != tc.want {
				t.Errorf("ohcPeer() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParseFARToAnIPv6Peer(t *testing.T) {
	far6 := ie.NewCreateFAR(
		ie.NewFARID(2),
		ie.NewApplyAction(ActionForward),
		ie.NewForwardingParameters(
			ie.NewDestinationInterface(ie.DstInterfaceAccess),
			ie.NewOuterHeaderCreation(0x0200, 0xabcd, "", testGnbV6.String(), 0, 0, 0),
		),
	)

	var f far

	u := &upf{accessIP: ipFromAddr(testN3v4), accessIP6: testN3v6}
	if err := f.parseFAR(far6, 1, u, create); err != nil {
		t.Fatalf("parseFAR() = %v", err)
	}

	if f.tunnelIPDst != testGnbV6 || f.tunnelIPSrc != testN3v6 {
		t.Errorf("tunnel %v -> %v, want %v -> %v", f.tunnelIPSrc, f.tunnelIPDst, testN3v6, testGnbV6)
	}

	// Without an IPv6 address on the interface, the tunnel cannot be built.
	f = far{}
	u = &upf{accessIP: ipFromAddr(testN3v4)}

	if err := f.parseFAR(far6, 1, u, create); !errors.Is(err, errUnsupported) {
		t.Errorf("parseFAR() = %v, want an unsupported-feature error", err)
	}
}

func TestUPIPResourceInformationFamilies(t *testing.T) {
	for _, tc := range []struct {
		name      string
		v4, v6    netip.Addr
		family    string
		wantFlags uint8
	}{
		{name: "IPv4 N3", v4: testN3v4, wantFlags: 0x41},
		{name: "dual", v4: testN3v4, v6: testN3v6, wantFlags: 0x43},
		{name: "dual, restricted to IPv4", v4: testN3v4, v6: testN3v6, family: transportFamilyIPv4, wantFlags: 0x41},
		{name: "dual, restricted to IPv6", v4: testN3v4, v6: testN3v6, family: transportFamilyIPv6, wantFlags: 0x42},
		{name: "IPv6 N3", v6: testN3v6, wantFlags: 0x42},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pConn, _, _ := n3v6Conn(t, tc.v4, tc.v6, tc.family)

			var info *ie.UserPlaneIPResourceInformationFields

			for _, x := range pConn.associationIEs() {
				if x.Type == ie.UserPlaneIPResourceInformation {
					var err error
					if info, err = x.UserPlaneIPResourceInformation(); err != nil {
						t.Fatal(err)
					}
				}
			}

			if info == nil {
				t.Fatal("no UP IP Resource Information")
			}

			if info.Flags != tc.wantFlags {
				t.Errorf("flags %#02x, want %#02x", info.Flags, tc.wantFlags)
			}

			if tc.wantFlags&0x01 != 0 && addrFromIP(info.IPv4Address) != tc.v4 {
				t.Errorf("IPv4 %v, want %v", info.IPv4Address, tc.v4)
			}

			if tc.wantFlags&0x02 != 0 && addrFromIP(info.IPv6Address) != tc.v6 {
				t.Errorf("IPv6 %v, want %v", info.IPv6Address, tc.v6)
			}
		})
	}
}

func TestResolveTunnelAddrs(t *testing.T) {
	ifaceV4 := netip.MustParseAddr("10.10.3.1")
	ifaceV6 := netip.MustParseAddr("2001:db8:630::99")
	lookup := func(v4, v6 netip.Addr) func(string) (netip.Addr, netip.Addr, error) {
		return func(string) (netip.Addr, netip.Addr, error) { return v4, v6, nil }
	}

	for _, tc := range []struct {
		name           string
		iface          IfaceType
		lookup4        netip.Addr
		lookup6        netip.Addr
		want4, want6   netip.Addr
		wantErr        bool
		wantValidation bool
	}{
		{name: "the interface's", lookup4: ifaceV4, lookup6: ifaceV6, want4: ifaceV4, want6: ifaceV6},
		{name: "IPv6-only interface", lookup6: ifaceV6, want6: ifaceV6},
		{
			name: "explicit IPv6", iface: IfaceType{IPv6: testN3v6.String()}, lookup4: ifaceV4, lookup6: ifaceV6,
			want4: ifaceV4, want6: testN3v6,
		},
		{
			name: "restricted to IPv4", iface: IfaceType{TransportFamily: transportFamilyIPv4},
			lookup4: ifaceV4, lookup6: ifaceV6, want4: ifaceV4,
		},
		{name: "no address", wantErr: true},
		{name: "bad family", iface: IfaceType{TransportFamily: "ip6"}, wantValidation: true},
		{name: "bad IPv6", iface: IfaceType{IPv6: "fe80::1"}, wantValidation: true},
		{name: "IPv4 as IPv6", iface: IfaceType{IPv6: testN4Addr4}, wantValidation: true},
		{name: "bad IPv4", iface: IfaceType{IPv4: testAddr6}, wantValidation: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateIface("access", tc.iface); (err != nil) != tc.wantValidation {
				t.Fatalf("validateIface() = %v, want error %v", err, tc.wantValidation)
			}

			if tc.wantValidation {
				return
			}

			v4, v6, err := resolveTunnelAddrs(tc.iface, lookup(tc.lookup4, tc.lookup6))
			if (err != nil) != tc.wantErr {
				t.Fatalf("resolveTunnelAddrs() error = %v, want error %v", err, tc.wantErr)
			}

			if v4 != tc.want4 || v6 != tc.want6 {
				t.Errorf("resolveTunnelAddrs() = %v %v, want %v %v", v4, v6, tc.want4, tc.want6)
			}
		})
	}
}

func TestTunnelAddrsSkipLinkLocal(t *testing.T) {
	addrs := []net.Addr{
		&net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)},
		&net.IPNet{IP: net.ParseIP("2001:db8:630::1"), Mask: net.CIDRMask(64, 128)},
		&net.IPNet{IP: net.ParseIP("10.10.3.1"), Mask: net.CIDRMask(24, 32)},
		&net.IPNet{IP: net.ParseIP("2001:db8:630::2"), Mask: net.CIDRMask(64, 128)},
		&net.IPNet{IP: net.ParseIP("10.10.3.2"), Mask: net.CIDRMask(24, 32)},
	}

	v4, v6 := tunnelAddrs(addrs)
	if v4 != testN3v4 || v6 != testN3v6 {
		t.Errorf("tunnelAddrs() = %v %v, want %v %v", v4, v6, testN3v4, testN3v6)
	}
}

// PDRs on the same TEID and the two addresses of one F-TEID are one entry each, and an
// F-TEID whose addresses share their low 32 bits one entry in all.
func TestTunnelMatches(t *testing.T) {
	v4 := hostPrefix(testN3v4)
	clash := hostPrefix(netip.MustParseAddr("2001:db8::a0a:301")) // low 32 bits 10.10.3.1

	for _, tc := range []struct {
		name   string
		p      pdr
		values []uint32
	}{
		{name: "no F-TEID", p: pdr{}, values: []uint32{0}},
		{name: "IPv4 F-TEID", p: pdr{tunnelIPDst: v4}, values: []uint32{0x0a0a0301}},
		{name: "IPv6 F-TEID", p: pdr{tunnelIPv6Dst: hostPrefix(testN3v6)}, values: []uint32{1}},
		{name: "dual F-TEID", p: pdr{tunnelIPDst: v4, tunnelIPv6Dst: hostPrefix(testN3v6)}, values: []uint32{0x0a0a0301, 1}},
		{name: "both, same low 32 bits", p: pdr{tunnelIPDst: v4, tunnelIPv6Dst: clash}, values: []uint32{0x0a0a0301}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, err := tc.p.ipv4Match()
			if err != nil {
				t.Fatal(err)
			}

			got := tc.p.tunnelMatches(m)
			if len(got) != len(tc.values) {
				t.Fatalf("tunnelMatches() = %v, want values %#x", got, tc.values)
			}

			for i, v := range tc.values {
				if got[i].dst != v {
					t.Errorf("match %d = %#x, want %#x", i, got[i].dst, v)
				}
			}
		})
	}
}
