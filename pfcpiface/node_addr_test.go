// SPDX-FileCopyrightText: 2026 Balázs Toldi
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"context"
	"net"
	"testing"
)

// The loopback addresses the N4 tests use. The repo's goconst settings count literals
// across the package's tests, so they are named once.
const (
	loopbackV4 = "127.0.0.1"
	loopbackV6 = "::1"
)

// TestPFCPAddr covers the N4 listen address (n4_addr) and the peer addresses
// (cpiface.peers). Joining with a bare ":" gave "2001:db8::1:8805" for an IPv6 host,
// which Listen and Dial refuse as having too many colons, so an IPv6 n4_addr stopped
// the agent at start-up and an IPv6 peer was never associated with.
func TestPFCPAddr(t *testing.T) {
	tests := []struct {
		host    string
		want    string
		literal bool // resolvable without DNS
		ipv6    bool
	}{
		{host: "", want: ":8805", literal: true},
		{host: "0.0.0.0", want: "0.0.0.0:8805", literal: true},
		{host: "10.0.0.1", want: "10.0.0.1:8805", literal: true},
		{host: "::", want: "[::]:8805", literal: true, ipv6: true},
		{host: loopbackV6, want: "[::1]:8805", literal: true, ipv6: true},
		{host: "2001:db8::1", want: "[2001:db8::1]:8805", literal: true, ipv6: true},
		{host: "smf.example.org", want: "smf.example.org:8805"},
	}

	for _, tt := range tests {
		got := pfcpAddr(tt.host)
		if got != tt.want {
			t.Errorf("pfcpAddr(%q) = %q, want %q", tt.host, got, tt.want)
			continue
		}

		host, port, err := net.SplitHostPort(got)
		if err != nil || host != tt.host || port != PFCPPort {
			t.Errorf("pfcpAddr(%q) = %q does not split back into the host and port: "+
				"host=%q port=%q err=%v", tt.host, got, host, port, err)
		}

		if !tt.literal {
			continue
		}

		if _, err = net.ResolveUDPAddr("udp", got); err != nil {
			t.Errorf("pfcpAddr(%q) = %q is not a UDP address: %v", tt.host, got, err)
		}

		// The concatenation this replaced, kept here as the reproduction: it is fine for
		// IPv4 and unparseable for IPv6.
		_, err = net.ResolveUDPAddr("udp", tt.host+":"+PFCPPort)
		if tt.ipv6 && err == nil {
			t.Errorf("%q+\":\"+PFCPPort unexpectedly parses", tt.host)
		}

		if !tt.ipv6 && err != nil {
			t.Errorf("%q+\":\"+PFCPPort no longer parses: %v", tt.host, err)
		}
	}
}

func hasIPv6Loopback() bool {
	var lc net.ListenConfig

	conn, err := lc.ListenPacket(context.Background(), "udp6", "[::1]:0")
	if err != nil {
		return false
	}

	conn.Close() //nolint:errcheck // probe only

	return true
}

// TestResolveN4Peer: the address a configured peer resolves to is the one the PFCP
// connection is dialled to and keyed by, so it has to come out in the form
// handleNewPeers sees from ReadFrom -- an IPv6 address bracketed.
func TestResolveN4Peer(t *testing.T) {
	tests := []struct {
		peer string
		want string
		v6   bool
	}{
		{peer: loopbackV4, want: "127.0.0.1:8805"},
		{peer: loopbackV6, want: "[::1]:8805", v6: true},
	}

	for _, tt := range tests {
		t.Run(tt.peer, func(t *testing.T) {
			if tt.v6 && !hasIPv6Loopback() {
				t.Skip("no IPv6 loopback here")
			}

			got, err := resolveN4Peer(context.Background(), tt.peer)
			if err != nil {
				t.Fatalf("resolveN4Peer(%q): %v", tt.peer, err)
			}

			if got.String() != tt.want {
				t.Errorf("resolveN4Peer(%q) = %q, want %q", tt.peer, got.String(), tt.want)
			}

			if !got.IP.Equal(net.ParseIP(tt.peer)) {
				t.Errorf("resolveN4Peer(%q) resolved to IP %v", tt.peer, got.IP)
			}
		})
	}
}
