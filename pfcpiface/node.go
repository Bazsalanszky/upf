// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Intel Corporation
// Copyright 2021 Open Networking Foundation
package pfcpiface

import (
	"context"
	"errors"
	"net"
	"sync"

	reuse "github.com/libp2p/go-reuseport"
	"github.com/omec-project/upf-epc/logger"
	"github.com/omec-project/upf-epc/pfcpiface/metrics"
)

// PFCPNode represents a PFCP endpoint of the UPF.
type PFCPNode struct {
	ctx    context.Context
	cancel context.CancelFunc
	// listening socket for new "PFCP connections"
	net.PacketConn
	// done is closed to signal shutdown complete
	done chan struct{}
	// WaitGroup to track active connections
	connWg sync.WaitGroup
	// map of existing connections
	pConns sync.Map
	// upf
	upf *upf
	// metrics for PFCP messages and sessions
	metrics metrics.InstrumentPFCP
}

// pfcpAddr joins host with the PFCP port. host is an IP literal, a name, or empty for
// every local address. An IPv6 literal comes out bracketed, as Listen and Dial expect.
func pfcpAddr(host string) string {
	return net.JoinHostPort(host, PFCPPort)
}

// NewPFCPNode create a new PFCPNode listening on local address.
func NewPFCPNode(upf *upf) *PFCPNode {
	conn, err := reuse.ListenPacket("udp", pfcpAddr(upf.n4addr))
	if err != nil {
		logger.PfcpLog.Fatalln("listen UDP failed", err)
	}

	metrics, err := metrics.NewPrometheusService()
	if err != nil {
		logger.PfcpLog.Fatalln("prom metrics service init failed", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &PFCPNode{
		ctx:        ctx,
		cancel:     cancel,
		PacketConn: conn,
		done:       make(chan struct{}),
		upf:        upf,
		metrics:    metrics,
	}
}

// resolveN4Peer returns the address of the PFCP endpoint of a configured N4 peer. A UDP
// dial sends nothing; it only resolves the peer and picks the route to it.
func resolveN4Peer(ctx context.Context, peer string) (*net.UDPAddr, error) {
	var d net.Dialer

	conn, err := d.DialContext(ctx, "udp", pfcpAddr(peer))
	if err != nil {
		return nil, err
	}

	remoteAddr := conn.RemoteAddr().(*net.UDPAddr)
	conn.Close()

	return remoteAddr, nil
}

func (node *PFCPNode) tryConnectToN4Peers(lAddrStr string) {
	for _, peer := range node.upf.peers {
		remoteAddr, err := resolveN4Peer(node.ctx, peer)
		if err != nil {
			logger.PfcpLog.Warnln("failed to establish PFCP connection to peer", peer, err)
			continue
		}

		n4DstIP := remoteAddr.IP

		logger.PfcpLog.Infof("Establishing PFCP Conn with CP node. SPGWC/SMF host: %s, CP node: %s", peer, n4DstIP.String())

		// remoteAddr.String() is the form handleNewPeers keys pConns by, and brackets an
		// IPv6 address.
		pfcpConn := node.NewPFCPConn(lAddrStr, remoteAddr.String(), nil)
		if pfcpConn != nil {
			go pfcpConn.sendAssociationRequest()
		}
	}
}

func (node *PFCPNode) handleNewPeers() {
	lAddrStr := node.LocalAddr().String()
	logger.PfcpLog.Infoln("listening for new PFCP connections on", lAddrStr)

	node.tryConnectToN4Peers(lAddrStr)

	for {
		buf := make([]byte, 1024)

		n, rAddr, err := node.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}

			continue
		}

		rAddrStr := rAddr.String()

		_, ok := node.pConns.Load(rAddrStr)
		if ok {
			logger.PfcpLog.Warnln("drop packet for existing PFCPconn received from", rAddrStr)
			continue
		}

		node.NewPFCPConn(lAddrStr, rAddrStr, buf[:n])
	}
}

// Serve listens for the first packet from a new PFCP peer and creates PFCPConn.
func (node *PFCPNode) Serve() {
	go node.handleNewPeers()

	shutdown := false

	for !shutdown {
		select {
		case fseid := <-node.upf.reportNotifyChan:
			// Offer the notification to every association until one recognises the
			// F-SEID. This used to stop at the first, whichever the map happened to
			// yield: if that association did not hold the session the notification was
			// dropped with a warning and no Session Report was sent, so an idle UE
			// stayed unreachable. More than one association is ordinary -- an SMF
			// talking to this element directly while an adapter is also associated is
			// enough -- and which one answered was a coin toss.
			reported := false

			node.pConns.Range(func(key, value any) bool {
				pConn := value.(*PFCPConn)
				reported = pConn.handleDigestReport(fseid)

				return !reported
			})

			if !reported {
				logger.PfcpLog.Warnln("no association holds a session for fseid, downlink data notification dropped:", fseid)
			}
		case <-node.ctx.Done():
			shutdown = true

			logger.PfcpLog.Infoln("shutting down PFCP node")

			err := node.Close()
			if err != nil {
				logger.PfcpLog.Errorln("error closing PFCPNode conn", err)
			}

			// Signal all connections to shutdown
			node.pConns.Range(func(key, value any) bool {
				pConn := value.(*PFCPConn)
				pConn.Shutdown()
				return true
			})

			// Wait for all connections to complete
			logger.PfcpLog.Infoln("waiting for PFCPConn completions")
			node.connWg.Wait()
			logger.PfcpLog.Infoln("done waiting for PFCPConn completions")

			node.upf.Exit()
		}
	}

	close(node.done)
}

func (node *PFCPNode) Stop() {
	node.cancel()

	if err := node.metrics.Stop(); err != nil {
		// TODO: propagate error upwards
		logger.PfcpLog.Errorf("failed to stop metrics: %v", err)
	}
}

// Done waits for Shutdown() to complete
func (node *PFCPNode) Done() {
	<-node.done
	logger.PfcpLog.Infoln("shutdown complete")
}
