// SPDX-FileCopyrightText: 2026 Balázs Toldi
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	pb "github.com/omec-project/upf-epc/pfcpiface/bess_pb"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

// The golden file pins what pfcpiface hands the BESS datapath and the control plane for
// a set of IPv4 sessions: every gRPC module command, byte for byte, the PFCP responses,
// and the end markers. It is the proof that a change to the rule model leaves IPv4 alone.
// Regenerate it only for a change that is meant to alter the datapath's input:
//
//	go test ./pfcpiface -run TestBESSWireOutputIPv4 -update-golden

var updateGolden = flag.Bool("update-golden", false, "rewrite the golden files in testdata")

const bessWireGoldenFile = "bess_wire_ipv4.golden"

// flowAnyToAssigned is the flow description an SMF gives a PDR by default.
const flowAnyToAssigned = "permit out ip from any to assigned"

// recordingModuleClient answers every module command and keeps it.
type recordingModuleClient struct {
	pb.BESSControlClient

	mu       sync.Mutex
	commands []string
}

func (c *recordingModuleClient) ModuleCommand(
	_ context.Context, req *pb.CommandRequest, _ ...grpc.CallOption,
) (*pb.CommandResponse, error) {
	line := fmt.Sprintf("%s %s %s", req.GetName(), req.GetCmd(), req.GetArg().GetTypeUrl())

	if req.GetArg() != nil {
		inner, err := req.GetArg().UnmarshalNew()
		if err != nil {
			return nil, err
		}

		b, err := proto.MarshalOptions{Deterministic: true}.Marshal(inner)
		if err != nil {
			return nil, err
		}

		line += " " + hex.EncodeToString(b)
	}

	c.mu.Lock()
	c.commands = append(c.commands, line)
	c.mu.Unlock()

	return &pb.CommandResponse{}, nil
}

// take returns the commands recorded since the last call, sorted: a batch programs its
// rules concurrently, so their order is not part of the output.
func (c *recordingModuleClient) take() []string {
	c.mu.Lock()
	defer c.mu.Unlock()

	out := c.commands
	c.commands = nil

	sort.Strings(out)

	return out
}

type goldenRecorder struct {
	t     *testing.T
	lines []string
}

func (g *goldenRecorder) section(name string, lines ...string) {
	g.lines = append(g.lines, "== "+name)
	g.lines = append(g.lines, lines...)
}

func (g *goldenRecorder) message(name string, m message.Message) {
	g.t.Helper()

	b := make([]byte, m.MarshalLen())
	err := m.MarshalTo(b)
	if err != nil {
		g.t.Fatalf("could not marshal the %s: %v", name, err)
	}

	g.section(name, hex.EncodeToString(b))
}

func (g *goldenRecorder) compare(file string) {
	g.t.Helper()

	got := strings.Join(g.lines, "\n") + "\n"
	path := filepath.Join("testdata", file)

	if *updateGolden {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			g.t.Fatal(err)
		}

		if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
			g.t.Fatal(err)
		}

		return
	}

	want, err := os.ReadFile(path)
	if err != nil {
		g.t.Fatalf("could not read the golden file (run with -update-golden to create it): %v", err)
	}

	if got == string(want) {
		return
	}

	gotLines, wantLines := strings.Split(got, "\n"), strings.Split(string(want), "\n")
	for i := 0; i < len(gotLines) || i < len(wantLines); i++ {
		var gl, wl string
		if i < len(gotLines) {
			gl = gotLines[i]
		}

		if i < len(wantLines) {
			wl = wantLines[i]
		}

		if gl != wl {
			g.t.Fatalf("the output differs from %s at line %d:\n got: %s\nwant: %s", path, i+1, gl, wl)
		}
	}
}

// goldenConn is a connection whose datapath is a real *bess talking to a recording
// client, so the test sees what the agent would send over gRPC.
func goldenConn(t *testing.T, pool *IPPool) (*PFCPConn, *recordingModuleClient, *bess) {
	t.Helper()

	client := &recordingModuleClient{}
	b := &bess{client: client, endMarkerChan: make(chan []byte, 16)}
	b.readQciQosMap(&Conf{})

	pConn := establishingConn(t, pool)
	pConn.upf.datapath = b
	pConn.upf.accessIP = net.ParseIP("10.10.3.1")
	pConn.upf.coreIP = net.ParseIP("10.10.6.1")
	pConn.upf.fteidGenerator = NewFTEIDGenerator()
	pConn.upf.enableEndMarker = true
	pConn.appPFDs = map[string]appPFD{
		"app-web": {appID: "app-web", flowDescs: []string{
			"permit out 6 from 192.0.2.10 80 to assigned",
			"permit in 6 from assigned to 192.0.2.10 80",
		}},
	}

	return pConn, client, b
}

func goldenPDR(id uint16, precedence uint32, farID uint32, pdi []*ie.IE, extra ...*ie.IE) *ie.IE {
	ies := []*ie.IE{
		ie.NewPDRID(id),
		ie.NewPrecedence(precedence),
		ie.NewPDI(pdi...),
		ie.NewFARID(farID),
	}

	return ie.NewCreatePDR(append(ies, extra...)...)
}

func takeEndMarkers(b *bess) []string {
	var out []string

	for {
		select {
		case m := <-b.endMarkerChan:
			out = append(out, hex.EncodeToString(m))
		default:
			return out
		}
	}
}

func TestBESSWireOutputIPv4(t *testing.T) {
	pool, err := NewIPPool("10.251.0.0/29")
	if err != nil {
		t.Fatal(err)
	}

	pConn, client, b := goldenConn(t, pool)
	g := &goldenRecorder{t: t}

	const ueIP = "10.250.0.5"

	// An establishment shaped like the SMF's: uplink PDRs sharing one chosen F-TEID,
	// downlink PDRs on the UE address, SDF filters with prefixes and ports, a PFD, a
	// CP-allocated F-TEID, and forwarding, buffering and QoS rules.
	sereq := message.NewSessionEstablishmentRequest(0, 0, 0, 1, 0,
		ie.NewNodeID("", "", testRemoteNodeID),
		ie.NewFSEID(0x1001, net.ParseIP("10.10.4.2"), nil),
		goldenPDR(1, 255, 1, []*ie.IE{
			ie.NewSourceInterface(ie.SrcInterfaceAccess),
			ie.NewFTEID(0x0d, 0, nil, nil, 1),
			ie.NewUEIPAddress(0x02, ueIP, "", 0, 0),
			ie.NewSDFFilter(flowAnyToAssigned, "", "", "", 0),
		}, ie.NewOuterHeaderRemoval(0, 0), ie.NewQERID(1)),
		goldenPDR(2, 100, 1, []*ie.IE{
			ie.NewSourceInterface(ie.SrcInterfaceAccess),
			ie.NewFTEID(0x0d, 0, nil, nil, 1),
			ie.NewUEIPAddress(0x02, ueIP, "", 0, 0),
			ie.NewSDFFilter("permit out 17 from 192.0.2.0/24 8000-8010 to assigned", "", "", "", 0),
		}, ie.NewOuterHeaderRemoval(0, 0), ie.NewQERID(1)),
		goldenPDR(3, 255, 2, []*ie.IE{
			ie.NewSourceInterface(ie.SrcInterfaceCore),
			ie.NewUEIPAddress(0x06, ueIP, "", 0, 0),
			ie.NewSDFFilter(flowAnyToAssigned, "", "", "", 0),
		}, ie.NewQERID(1)),
		goldenPDR(4, 90, 2, []*ie.IE{
			ie.NewSourceInterface(ie.SrcInterfaceCore),
			ie.NewUEIPAddress(0x06, ueIP, "", 0, 0),
			ie.NewSDFFilter("permit out 6 from 198.51.100.7 443 to assigned 1024-1030", "", "", "", 0),
		}),
		goldenPDR(5, 80, 1, []*ie.IE{
			ie.NewSourceInterface(ie.SrcInterfaceAccess),
			ie.NewFTEID(0x01, 0x1234, net.ParseIP("10.10.3.1"), nil, 0),
			ie.NewUEIPAddress(0x02, ueIP, "", 0, 0),
		}, ie.NewOuterHeaderRemoval(0, 0)),
		goldenPDR(6, 70, 2, []*ie.IE{
			ie.NewSourceInterface(ie.SrcInterfaceCore),
			ie.NewUEIPAddress(0x06, ueIP, "", 0, 0),
			ie.NewApplicationID("app-web"),
		}),
		goldenPDR(7, 60, 2, []*ie.IE{
			ie.NewSourceInterface(ie.SrcInterfaceCore),
			ie.NewUEIPAddress(0x06, ueIP, "", 0, 0),
			ie.NewSDFFilter("permit out ip from 203.0.113.77/26 to assigned", "", "", "", 0),
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
		ie.NewCreateFAR(
			ie.NewFARID(3),
			ie.NewApplyAction(ActionBuffer|ActionNotify),
		),
		ie.NewCreateQER(
			ie.NewQERID(1),
			ie.NewGateStatus(ie.GateStatusOpen, ie.GateStatusOpen),
			ie.NewMBR(200000, 100000),
			ie.NewQFI(9),
		),
	)

	rsp, err := pConn.handleSessionEstablishmentRequest(sereq)
	if err != nil {
		t.Fatalf("establishment refused: %v", err)
	}

	g.message("establishment response", rsp)
	g.section("establishment datapath", client.take()...)

	seres, ok := rsp.(*message.SessionEstablishmentResponse)
	if !ok {
		t.Fatalf("expected a Session Establishment Response, got %T", rsp)
	}

	assertAccepted(t, seres.Cause, "establishment")

	fseid, err := seres.UPFSEID.FSEID()
	if err != nil {
		t.Fatal(err)
	}

	localSEID := fseid.SEID

	// A handover: the downlink FAR moves to a new gNB with an end marker, a PDR is added
	// and one is removed.
	smreq := message.NewSessionModificationRequest(0, 0, localSEID, 2, 0,
		ie.NewUpdateFAR(
			ie.NewFARID(2),
			ie.NewApplyAction(ActionForward),
			ie.NewUpdateForwardingParameters(
				ie.NewDestinationInterface(ie.DstInterfaceAccess),
				ie.NewOuterHeaderCreation(0x0100, 0xabce, "10.10.3.201", "", 0, 0, 0),
				ie.NewPFCPSMReqFlags(0x02),
			),
		),
		goldenPDR(8, 50, 2, []*ie.IE{
			ie.NewSourceInterface(ie.SrcInterfaceCore),
			ie.NewUEIPAddress(0x06, ueIP, "", 0, 0),
			ie.NewSDFFilter("permit out 17 from 203.0.113.0/26 to assigned 5000", "", "", "", 0),
		}),
		ie.NewRemovePDR(ie.NewPDRID(5)),
	)

	rsp, err = pConn.handleSessionModificationRequest(smreq)
	if err != nil {
		t.Fatalf("modification refused: %v", err)
	}

	g.message("modification response", rsp)
	g.section("modification datapath", client.take()...)
	g.section("end markers", takeEndMarkers(b)...)

	// A session whose UE address the UPF chooses.
	sereq = message.NewSessionEstablishmentRequest(0, 0, 0, 3, 0,
		ie.NewNodeID("", "", testRemoteNodeID),
		ie.NewFSEID(0x1002, net.ParseIP("10.10.4.2"), nil),
		goldenPDR(1, 255, 1, []*ie.IE{
			ie.NewSourceInterface(ie.SrcInterfaceAccess),
			ie.NewFTEID(0x05, 0, nil, nil, 0),
			chooseUEAddress(),
			ie.NewSDFFilter(flowAnyToAssigned, "", "", "", 0),
		}, ie.NewOuterHeaderRemoval(0, 0)),
		goldenPDR(2, 255, 1, []*ie.IE{
			ie.NewSourceInterface(ie.SrcInterfaceCore),
			chooseUEAddress(),
		}),
		ie.NewCreateFAR(
			ie.NewFARID(1),
			ie.NewApplyAction(ActionForward),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore)),
		),
	)

	rsp, err = pConn.handleSessionEstablishmentRequest(sereq)
	if err != nil {
		t.Fatalf("allocating establishment refused: %v", err)
	}

	g.message("allocating establishment response", rsp)
	g.section("allocating establishment datapath", client.take()...)

	rsp, err = pConn.handleSessionDeletionRequest(
		message.NewSessionDeletionRequest(0, 0, localSEID, 4, 0))
	if err != nil {
		t.Fatalf("deletion refused: %v", err)
	}

	g.message("deletion response", rsp)
	g.section("deletion datapath", client.take()...)

	g.compare(bessWireGoldenFile)
}
