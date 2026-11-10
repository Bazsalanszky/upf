// SPDX-FileCopyrightText: 2026 Balázs Toldi
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestLoadConfigN4Addresses: the N4 settings take IPv4 and IPv6 literals as they are
// usually written, and refuse the bracketed and host:port forms at load time. Those
// used to reach the listen, which exits the agent with "too many colons", or for
// node_id did not exist.
func TestLoadConfigN4Addresses(t *testing.T) {
	const (
		confN4Addr = "N4Addr"
		confNodeID = "AdvertisedNodeID"
	)

	tests := []struct {
		name    string
		n4Addr  string
		peers   []string
		nodeID  string
		wantErr string
	}{
		{name: "defaults"},
		{name: "IPv4", n4Addr: testN4Addr4, peers: []string{"10.0.0.2"}, nodeID: testN4Addr4},
		{name: "IPv6", n4Addr: testN4Addr6, peers: []string{"2001:db8::20"}, nodeID: testN4Addr6},
		{name: "dual-stack wildcard, mixed peers", n4Addr: "::", peers: []string{"10.0.0.2", "2001:db8::20"}},
		{name: "IPv4 wildcard", n4Addr: anyIPv4},
		{name: "link-local with a zone", n4Addr: testZonedAddr},
		{name: "host name", n4Addr: "upf-n4.example.org"},
		{name: "node_id FQDN", nodeID: testUPFFQDN},
		{name: "node_id FQDN with the root dot", nodeID: "upf.example.org."},
		{name: "node_id short name", nodeID: testHostname},
		{name: "bracketed n4_addr", n4Addr: "[2001:db8::10]", wantErr: confN4Addr},
		{name: "n4_addr with a port", n4Addr: "10.0.0.1:8805", wantErr: confN4Addr},
		{name: "bracketed IPv6 n4_addr with a port", n4Addr: "[2001:db8::10]:8805", wantErr: confN4Addr},
		{name: "bracketed peer", peers: []string{"[2001:db8::20]"}, wantErr: "Peers"},
		{name: "bracketed node_id", nodeID: "[2001:db8::10]", wantErr: confNodeID},
		{name: "node_id with a zone", nodeID: testZonedAddr, wantErr: confNodeID},
		{name: "node_id with an empty label", nodeID: "upf..example.org", wantErr: confNodeID},
		{name: "node_id with a port", nodeID: "upf.example.org:8805", wantErr: confNodeID},
		{name: "node_id label too long", nodeID: strings.Repeat("a", 64) + ".org", wantErr: confNodeID},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cp := map[string]any{"node_id": tt.nodeID}
			if tt.peers != nil {
				cp["peers"] = tt.peers
			}

			b, err := json.Marshal(map[string]any{"mode": "dpdk", "n4_addr": tt.n4Addr, "cpiface": cp})
			if err != nil {
				t.Fatal(err)
			}

			path := t.TempDir() + "/upf.jsonc"
			mustWriteStringToDisk(string(b), path)

			conf, err := LoadConfigFile(path)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %v, want one about %s", err, tt.wantErr)
				}

				return
			}

			if err != nil {
				t.Fatal(err)
			}

			if conf.N4Addr != tt.n4Addr || conf.CPIface.AdvertisedNodeID != tt.nodeID {
				t.Errorf("loaded n4_addr %q, node_id %q", conf.N4Addr, conf.CPIface.AdvertisedNodeID)
			}
		})
	}
}
