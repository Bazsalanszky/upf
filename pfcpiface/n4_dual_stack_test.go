// SPDX-FileCopyrightText: 2026 Balázs Toldi
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"context"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	reuse "github.com/libp2p/go-reuseport"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// These tests run N4 over real sockets: a PFCPNode listening the way NewPFCPNode does,
// on a free port instead of 8805, and a control plane built from go-pfcp messages.
// pfcpsim, which test/integration uses, cannot take this part: it listens on "udp4",
// joins addresses with "%s:%d" and sends an IPv4 Node ID and F-SEID.

const n4TestAccessIP = "198.51.100.1" // the N3 address, IPv4 whatever the N4 family

// listenN4Test listens on host with SO_REUSEPORT, as NewPFCPNode does, on a port no
// other socket holds. A reuseport bind to port 0 can be handed a port that another
// SO_REUSEPORT socket of the same user already has (Linux allows it), and the port's
// datagrams are then spread over both sockets, so a test peer's request can go
// unanswered. A plain bind is never given a port in use, so it picks the port.
func listenN4Test(t *testing.T, host string) net.PacketConn {
	t.Helper()

	var (
		lc  net.ListenConfig
		err error
	)

	for range 10 {
		var probe net.PacketConn

		probe, err = lc.ListenPacket(context.Background(), "udp", net.JoinHostPort(host, "0"))
		if err != nil {
			break
		}

		port := strconv.Itoa(probe.LocalAddr().(*net.UDPAddr).Port)
		probe.Close() //nolint:errcheck // only held to pick the port

		var conn net.PacketConn

		conn, err = reuse.ListenPacket("udp", net.JoinHostPort(host, port))
		if err == nil {
			return conn
		}
	}

	t.Fatalf("listen on %q: %v", host, err)

	return nil
}

// newN4TestNode starts a PFCP node listening on host (n4_addr) and serving new peers.
func newN4TestNode(t *testing.T, host string, id localNodeID) *PFCPNode {
	t.Helper()

	conn := listenN4Test(t, host)

	ctx, cancel := context.WithCancel(context.Background())

	node := &PFCPNode{
		ctx:        ctx,
		cancel:     cancel,
		PacketConn: conn,
		done:       make(chan struct{}),
		metrics:    noopMetrics{},
		upf: &upf{
			datapath:         &fakeDP{},
			accessIP:         net.ParseIP(n4TestAccessIP),
			nodeID:           id,
			readTimeout:      10 * time.Second,
			respTimeout:      500 * time.Millisecond,
			maxReqRetries:    1,
			fteidGenerator:   NewFTEIDGenerator(),
			reportNotifyChan: make(chan uint64, 1),
		},
	}

	go node.handleNewPeers()

	t.Cleanup(func() {
		cancel()

		if err := node.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close the node: %v", err)
		}

		node.pConns.Range(func(_, v any) bool {
			v.(*PFCPConn).Shutdown()
			return true
		})
		node.connWg.Wait()
	})

	return node
}

// n4Peer is a control plane at ip, talking to the node at the same family's address.
type n4Peer struct {
	t    *testing.T
	conn *net.UDPConn
	upf  *net.UDPAddr
	seq  uint32
}

func newN4Peer(t *testing.T, ip string, node *PFCPNode) *n4Peer {
	t.Helper()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(ip)})
	if err != nil {
		t.Fatalf("peer listen on %s: %v", ip, err)
	}

	t.Cleanup(func() { conn.Close() }) //nolint:errcheck // test cleanup

	port := node.LocalAddr().(*net.UDPAddr).Port

	return &n4Peer{t: t, conn: conn, upf: &net.UDPAddr{IP: net.ParseIP(ip), Port: port}}
}

func (p *n4Peer) nextSeq() uint32 {
	p.seq++
	return p.seq
}

func (p *n4Peer) send(msg message.Message) {
	p.t.Helper()

	b := make([]byte, msg.MarshalLen())
	if err := msg.MarshalTo(b); err != nil {
		p.t.Fatal(err)
	}

	if _, err := p.conn.WriteToUDP(b, p.upf); err != nil {
		p.t.Fatalf("send to %s: %v", p.upf, err)
	}
}

// receive reads the next message, and checks it came from the UPF's N4 address.
func (p *n4Peer) receive() (message.Message, *net.UDPAddr) {
	p.t.Helper()

	if err := p.conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		p.t.Fatal(err)
	}

	buf := make([]byte, 65507)

	n, from, err := p.conn.ReadFromUDP(buf)
	if err != nil {
		p.t.Fatalf("no message from the UPF: %v", err)
	}

	if !from.IP.Equal(p.upf.IP) {
		p.t.Errorf("message from %s, want the UPF's address %s", from, p.upf.IP)
	}

	msg, err := message.Parse(buf[:n])
	if err != nil {
		p.t.Fatalf("undecodable message from the UPF: %v", err)
	}

	return msg, from
}

func (p *n4Peer) request(msg message.Message) message.Message {
	p.t.Helper()
	p.send(msg)

	rsp, _ := p.receive()
	if rsp.Sequence() != msg.Sequence() {
		p.t.Fatalf("response sequence %d, want %d", rsp.Sequence(), msg.Sequence())
	}

	return rsp
}

func (p *n4Peer) associate(cpNodeID *ie.IE) *message.AssociationSetupResponse {
	p.t.Helper()

	rsp := p.request(message.NewAssociationSetupRequest(p.nextSeq(),
		cpNodeID, ie.NewRecoveryTimeStamp(time.Now())))

	asres, ok := rsp.(*message.AssociationSetupResponse)
	if !ok {
		p.t.Fatalf("got %s, want an Association Setup Response", rsp.MessageTypeName())
	}

	assertAccepted(p.t, asres.Cause, "association setup")

	return asres
}

func (p *n4Peer) heartbeat() {
	p.t.Helper()

	rsp := p.request(message.NewHeartbeatRequest(p.nextSeq(), ie.NewRecoveryTimeStamp(time.Now()), nil))

	hbres, ok := rsp.(*message.HeartbeatResponse)
	if !ok {
		p.t.Fatalf("got %s, want a Heartbeat Response", rsp.MessageTypeName())
	}

	if hbres.RecoveryTimeStamp == nil {
		p.t.Fatal("the Heartbeat Response has no Recovery Time Stamp")
	}
}

// establish sets up a session with an uplink PDR whose F-TEID the UPF chooses, as the
// SD-Core SMF does, and a CP F-SEID with the peer's own address.
func (p *n4Peer) establish(cpNodeID *ie.IE) *message.SessionEstablishmentResponse {
	p.t.Helper()

	local := p.conn.LocalAddr().(*net.UDPAddr).IP

	cpFSEID := ie.NewFSEID(0xC0FFEE, local, nil)
	if local.To4() == nil {
		cpFSEID = ie.NewFSEID(0xC0FFEE, nil, local)
	}

	rsp := p.request(message.NewSessionEstablishmentRequest(0, 0, 0, p.nextSeq(), 0,
		cpNodeID,
		cpFSEID,
		chooseUplinkPDR(1, 1, true, "permit out ip from any to assigned"),
		downlinkFAR(),
	))

	seres, ok := rsp.(*message.SessionEstablishmentResponse)
	if !ok {
		p.t.Fatalf("got %s, want a Session Establishment Response", rsp.MessageTypeName())
	}

	assertAccepted(p.t, seres.Cause, "session establishment")

	if seres.SEID() != 0xC0FFEE {
		p.t.Errorf("response SEID %#x, want the CP SEID", seres.SEID())
	}

	return seres
}

func hasIPv4Loopback() bool {
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return false
	}

	c.Close() //nolint:errcheck // probe only

	return true
}

func assertNodeID(t *testing.T, got *ie.IE, wantType uint8, want string) {
	t.Helper()

	if got == nil {
		t.Fatal("no Node ID")
	}

	if got.Payload[0] != wantType {
		t.Errorf("Node ID type %d, want %d", got.Payload[0], wantType)
	}

	if s, err := peerNodeID(got); err != nil || s != want {
		t.Errorf("Node ID %q (%v), want %q", s, err, want)
	}
}

// assertUPFSEID checks the UP F-SEID carries exactly the given address.
func assertUPFSEID(t *testing.T, got *ie.IE, want string) {
	t.Helper()

	if got == nil {
		t.Fatal("no UP F-SEID")
	}

	f, err := got.FSEID()
	if err != nil {
		t.Fatal(err)
	}

	wantIP := net.ParseIP(want)
	if v4 := wantIP.To4() != nil; f.HasIPv4() != v4 || f.HasIPv6() == v4 {
		t.Fatalf("UP F-SEID flags %#x for %s", f.Flags, want)
	}

	addr := f.IPv4Address
	if f.HasIPv6() {
		addr = f.IPv6Address
	}

	if !addr.Equal(wantIP) {
		t.Errorf("UP F-SEID address %v, want %v", addr, wantIP)
	}
}

// assertN3StaysIPv4 checks the F-TEID the UPF chose is the IPv4 N3 address, whatever
// the N4 family.
func assertN3StaysIPv4(t *testing.T, seres *message.SessionEstablishmentResponse) {
	t.Helper()

	if len(seres.CreatedPDR) != 1 {
		t.Fatalf("%d Created PDRs, want 1", len(seres.CreatedPDR))
	}

	fteid, err := seres.CreatedPDR[0].FTEID()
	if err != nil {
		t.Fatal(err)
	}

	if !fteid.HasIPv4() || fteid.HasIPv6() || !fteid.IPv4Address.Equal(net.ParseIP(n4TestAccessIP)) {
		t.Errorf("chosen F-TEID %+v, want IPv4 %s only", fteid, n4TestAccessIP)
	}
}

// TestN4OverIPv6 runs an association, a heartbeat and a session establishment with a
// control plane at ::1, against n4_addr loopbackV6. The UPF names itself with an IPv6 Node
// ID and puts its address in the IPv6 slot of the UP F-SEID; N3 stays IPv4.
//
// The control plane names itself with an FQDN in two spellings, so the establishment
// also checks that a peer's Node ID is matched after normalisation.
func TestN4OverIPv6(t *testing.T) {
	if !hasIPv6Loopback() {
		t.Skip("no IPv6 loopback here")
	}

	node := newN4TestNode(t, loopbackV6, localNodeID{})
	cp := newN4Peer(t, loopbackV6, node)

	asres := cp.associate(ie.NewNodeID("", "", "SMF.Example.org"))
	assertNodeID(t, asres.NodeID, nodeIDTypeIPv6, loopbackV6)

	if len(asres.UserPlaneIPResourceInformation) == 0 {
		t.Error("no UP IP Resource Information")
	}

	cp.heartbeat()

	seres := cp.establish(ie.NewNodeID("", "", testSMFFQDN))
	assertNodeID(t, seres.NodeID, nodeIDTypeIPv6, loopbackV6)
	assertUPFSEID(t, seres.UPFSEID, loopbackV6)
	assertN3StaysIPv4(t, seres)

	// The association is keyed the way an IPv6 peer is written, bracketed.
	if _, ok := node.pConns.Load(cp.conn.LocalAddr().String()); !ok {
		t.Errorf("no association keyed %s", cp.conn.LocalAddr())
	}
}

// TestN4DualStack: with n4_addr empty (or "::", or anyIPv4, which Go also opens as a
// dual-stack socket), one control plane at 127.0.0.1 and one at ::1 associate at the
// same time, and each is answered in its own family -- from its own family's address,
// with that family's Node ID and UP F-SEID. With a configured Node ID, each
// association advertises the configured address of its family, or the FQDN.
func TestN4DualStack(t *testing.T) {
	if !hasIPv6Loopback() || !hasIPv4Loopback() {
		t.Skip("needs both IPv4 and IPv6 loopback")
	}

	tests := []struct {
		name                 string
		host                 string
		id                   localNodeID
		wantType4, wantType6 uint8
		want4, want6         string
	}{
		{
			name: "n4_addr empty, Node ID from the socket", host: "",
			wantType4: nodeIDTypeIPv4, want4: loopbackV4, wantType6: nodeIDTypeIPv6, want6: loopbackV6,
		},
		{
			name: "n4_addr 0.0.0.0 is dual-stack too", host: anyIPv4,
			wantType4: nodeIDTypeIPv4, want4: loopbackV4, wantType6: nodeIDTypeIPv6, want6: loopbackV6,
		},
		{
			name: "hostname resolving to both families", host: "::",
			id:        localNodeID{addrs: addrs(testN4Addr6, "192.0.2.10")},
			wantType4: nodeIDTypeIPv4, want4: "192.0.2.10", wantType6: nodeIDTypeIPv6, want6: testN4Addr6,
		},
		{
			name: "node_id FQDN", host: "",
			id:        localNodeID{fixed: testUPFFQDN},
			wantType4: nodeIDTypeFQDN, want4: testUPFFQDN, wantType6: nodeIDTypeFQDN, want6: testUPFFQDN,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := newN4TestNode(t, tt.host, tt.id)
			cp4 := newN4Peer(t, loopbackV4, node)
			cp6 := newN4Peer(t, loopbackV6, node)

			as4 := cp4.associate(ie.NewNodeID(loopbackV4, "", ""))
			as6 := cp6.associate(ie.NewNodeID("", loopbackV6, ""))

			assertNodeID(t, as4.NodeID, tt.wantType4, tt.want4)
			assertNodeID(t, as6.NodeID, tt.wantType6, tt.want6)

			cp4.heartbeat()
			cp6.heartbeat()

			se4 := cp4.establish(ie.NewNodeID(loopbackV4, "", ""))
			se6 := cp6.establish(ie.NewNodeID("", loopbackV6, ""))

			assertNodeID(t, se4.NodeID, tt.wantType4, tt.want4)
			assertNodeID(t, se6.NodeID, tt.wantType6, tt.want6)
			assertUPFSEID(t, se4.UPFSEID, loopbackV4)
			assertUPFSEID(t, se6.UPFSEID, loopbackV6)
			assertN3StaysIPv4(t, se4)
			assertN3StaysIPv4(t, se6)

			// Two associations, keyed as handleNewPeers and tryConnectToN4Peers write
			// peers: IPv4 dotted (not IPv4-mapped), IPv6 bracketed.
			for _, cp := range []*n4Peer{cp4, cp6} {
				if _, ok := node.pConns.Load(cp.conn.LocalAddr().String()); !ok {
					t.Errorf("no association keyed %s", cp.conn.LocalAddr())
				}
			}
		})
	}
}

// TestN4SessionNodeIDMustMatchTheAssociation: normalising peer Node IDs must not make
// different peers match. A session for a Node ID other than the association's is still
// refused with "No established PFCP Association" over IPv6.
func TestN4SessionNodeIDMustMatchTheAssociation(t *testing.T) {
	if !hasIPv6Loopback() {
		t.Skip("no IPv6 loopback here")
	}

	node := newN4TestNode(t, loopbackV6, localNodeID{})
	cp := newN4Peer(t, loopbackV6, node)

	cp.associate(ie.NewNodeID("", "2001:db8::5", ""))

	rsp := cp.request(message.NewSessionEstablishmentRequest(0, 0, 0, cp.nextSeq(), 0,
		ie.NewNodeID("", "2001:db8::6", ""),
		ie.NewFSEID(0xC0FFEE, nil, net.ParseIP(loopbackV6)),
		chooseUplinkPDR(1, 1, true, "permit out ip from any to assigned"),
		downlinkFAR(),
	))

	seres, ok := rsp.(*message.SessionEstablishmentResponse)
	if !ok {
		t.Fatalf("got %s", rsp.MessageTypeName())
	}

	if c, err := seres.Cause.Cause(); err != nil || c != ie.CauseNoEstablishedPFCPAssociation {
		t.Errorf("cause %d (%v), want No established PFCP Association", c, err)
	}
}

// TestN4UPFInitiatedAssociationOverIPv6 covers the other direction, a cpiface.peers
// entry: the UPF sends the Association Setup Request from its IPv6 address, with an
// IPv6 Node ID.
//
// The peer refuses it. An accepted response makes sendAssociationRequest record the
// peer's Node ID while the connection's reader logs it (messages.go, HandlePFCPMsg),
// which is a data race of its own, in either address family; it is left for a separate
// change. The response's Node ID handling is TestAssociationSetupResponseNodeID.
func TestN4UPFInitiatedAssociationOverIPv6(t *testing.T) {
	if !hasIPv6Loopback() {
		t.Skip("no IPv6 loopback here")
	}

	node := newN4TestNode(t, loopbackV6, localNodeID{})
	cp := newN4Peer(t, loopbackV6, node)

	// What tryConnectToN4Peers does with the resolved peer, on the peer's own port
	// instead of 8805.
	pConn := node.NewPFCPConn(node.LocalAddr().String(), cp.conn.LocalAddr().String(), nil)
	if pConn == nil {
		t.Fatal("no connection to the peer")
	}

	done := make(chan struct{})

	go func() {
		defer close(done)
		pConn.sendAssociationRequest()
	}()

	msg, from := cp.receive()

	asreq, ok := msg.(*message.AssociationSetupRequest)
	if !ok {
		t.Fatalf("got %s, want an Association Setup Request", msg.MessageTypeName())
	}

	assertNodeID(t, asreq.NodeID, nodeIDTypeIPv6, loopbackV6)

	if from.String() != pConn.LocalAddr().String() {
		t.Errorf("request from %s, want the connection's address %s", from, pConn.LocalAddr())
	}

	cp.upf = from // answer the connection's own socket

	cp.send(message.NewAssociationSetupResponse(asreq.SequenceNumber,
		ie.NewNodeID("", "2001:db8::5", ""),
		ie.NewCause(ie.CauseRequestRejected),
		ie.NewRecoveryTimeStamp(time.Now()),
	))

	<-done
}

// TestAssociationSetupResponseNodeID: the peer's Node ID in an Association Setup
// Response is recorded in canonical form, whichever way the peer spelled it.
func TestAssociationSetupResponseNodeID(t *testing.T) {
	tests := []struct {
		nodeID *ie.IE
		want   string
	}{
		{nodeID: ie.NewNodeID("192.0.2.5", "", ""), want: "192.0.2.5"},
		{nodeID: ie.NewNodeID("", "2001:DB8:0:0::5", ""), want: "2001:db8::5"},
		{nodeID: ie.NewNodeID("", "", "SMF.example.org"), want: testSMFFQDN},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			pConn := &PFCPConn{Conn: teardownConn(t, nil).Conn}

			err := pConn.handleAssociationSetupResponse(message.NewAssociationSetupResponse(1,
				tt.nodeID, ie.NewCause(ie.CauseRequestAccepted), ie.NewRecoveryTimeStamp(time.Now())))
			if err != nil {
				t.Fatal(err)
			}

			if pConn.nodeID.remote != tt.want {
				t.Errorf("peer Node ID %q, want %q", pConn.nodeID.remote, tt.want)
			}
		})
	}

	// A short address used to be recorded as "<nil>"; now the association is refused.
	pConn := &PFCPConn{Conn: teardownConn(t, nil).Conn}

	err := pConn.handleAssociationSetupResponse(message.NewAssociationSetupResponse(1,
		ie.New(ie.NodeID, []byte{nodeIDTypeIPv6, 0x20, 0x01}),
		ie.NewCause(ie.CauseRequestAccepted), ie.NewRecoveryTimeStamp(time.Now())))
	if err == nil {
		t.Errorf("a truncated Node ID was accepted as %q", pConn.nodeID.remote)
	}
}
