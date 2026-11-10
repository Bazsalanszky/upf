// SPDX-FileCopyrightText: 2026 Balázs Toldi
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"testing"
	"time"
)

// TestNewPFCPConnDialFailure covers a PFCPConn whose connected socket cannot be
// created. NewPFCPConn used to log the dial error and carry on with a nil net.Conn,
// so the next line, which logs conn.LocalAddr(), panicked. The panic took down the
// whole agent: on the peer path at start-up, and on the listener path from the
// goroutine that accepts new peers.
//
// Each row fails inside reuse.Dial before any packet is sent, and none needs IPv6 on
// the host: Go rejects the address pair while it picks the socket family.
func TestNewPFCPConnDialFailure(t *testing.T) {
	tests := []struct {
		name  string
		lAddr string // "" means the test node's listening address, as handleNewPeers passes
		rAddr string
	}{
		{
			// n4_addr is an IPv4 address and cpiface.peers holds an IPv6 one.
			name:  "IPv4 local address, IPv6 peer",
			rAddr: "[::1]:" + PFCPPort,
		},
		{
			// n4_addr is an IPv6 address and cpiface.peers holds an IPv4 one.
			name:  "IPv6 local address, IPv4 peer",
			lAddr: "[::1]:0",
			rAddr: "127.0.0.1:" + PFCPPort,
		},
		{
			// An IPv6 host with ":8805" appended, as node.go builds peer addresses.
			name:  "IPv6 peer without brackets",
			rAddr: "::1:" + PFCPPort,
		},
		{
			name:  "local address without a port",
			lAddr: loopbackV4,
			rAddr: "127.0.0.1:" + PFCPPort,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			node := newTestPFCPNode(t, &upf{})

			lAddr := tc.lAddr
			if lAddr == "" {
				lAddr = node.LocalAddr().String()
			}

			var pConn *PFCPConn

			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("NewPFCPConn(%q, %q) panicked: %v", lAddr, tc.rAddr, r)
					}
				}()

				pConn = node.NewPFCPConn(lAddr, tc.rAddr, nil)
			}()

			if pConn != nil {
				t.Fatalf("NewPFCPConn(%q, %q) = %p, want nil", lAddr, tc.rAddr, pConn)
			}

			if _, ok := node.pConns.Load(tc.rAddr); ok {
				t.Errorf("pConns holds an entry for %q after the dial failed", tc.rAddr)
			}

			// No connection goroutine may have been registered, or shutdown would wait
			// for one that never runs.
			waited := make(chan struct{})

			go func() {
				node.connWg.Wait()
				close(waited)
			}()

			select {
			case <-waited:
			case <-time.After(time.Second):
				t.Error("connWg still counts a connection after the dial failed")
			}
		})
	}
}

// TestTryConnectToN4PeersSkipsAPeerOfTheOtherFamily covers the start-up path: the node
// listens on an IPv4 address and cpiface.peers holds an IPv6 one. Once peer addresses
// are joined with net.JoinHostPort, the peer resolves and NewPFCPConn is asked for a
// socket from an IPv4 address to an IPv6 one, which cannot be created. The peer must
// be skipped without a panic and without a connection being registered. Until then
// (the peer is dialled as "::1:8805"), or without IPv6 on the host, the resolve step
// before NewPFCPConn already skips the peer.
func TestTryConnectToN4PeersSkipsAPeerOfTheOtherFamily(t *testing.T) {
	node := newTestPFCPNode(t, &upf{peers: []string{loopbackV6}})

	node.tryConnectToN4Peers(node.LocalAddr().String())

	node.pConns.Range(func(key, _ any) bool {
		t.Errorf("pConns holds an entry for %v, want none", key)
		return true
	})
}
