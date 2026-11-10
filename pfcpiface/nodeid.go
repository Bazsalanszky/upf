// SPDX-FileCopyrightText: 2026 Balázs Toldi
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"

	"github.com/omec-project/upf-epc/logger"
	"github.com/wmnsk/go-pfcp/ie"
)

// Node ID types, TS 29.244 clause 8.2.38, octet 5 bits 1 to 4.
const (
	nodeIDTypeIPv4 = 0
	nodeIDTypeIPv6 = 1
	nodeIDTypeFQDN = 2
)

var errNodeIDInvalid = errors.New("invalid Node ID")

// localNodeID is the configured part of the Node ID the UPF advertises on N4. The
// zero value means "none configured": each association then advertises the address of
// its own socket.
type localNodeID struct {
	// fixed, when set, is advertised on every association: an FQDN, or an address in
	// canonical form. It comes from node_id.
	fixed string
	// addrs are the addresses hostname resolved to. An association advertises the
	// first one of its own address family, and the first one when there is none.
	addrs []netip.Addr
}

// newLocalNodeID works out the UPF's Node ID from the cpiface settings.
//
//   - node_id is advertised as given: an IP literal as an IPv4 or IPv6 Node ID, anything
//     else as an FQDN Node ID. Nothing is resolved.
//   - Otherwise hostname, or with use_fqdn and no hostname the host's FQDN, is resolved
//     and the resulting addresses are advertised, one per association (see localNodeID).
//     This is what hostname has always done; it used to keep only the first address,
//     whichever family the resolver put first.
//   - Otherwise nothing is configured.
//
// lookupHost and hostname are net.DefaultResolver.LookupHost and fqdnHostname outside
// tests.
func newLocalNodeID(ctx context.Context, c CPIfaceInfo,
	lookupHost func(context.Context, string) ([]string, error), hostname func() (string, error),
) (localNodeID, error) {
	if c.AdvertisedNodeID != "" {
		if c.NodeID != "" || c.UseFQDN {
			logger.PfcpLog.Warnln("cpiface.node_id is set, so cpiface.hostname and cpiface.use_fqdn are ignored")
		}

		if a, err := netip.ParseAddr(c.AdvertisedNodeID); err == nil {
			return localNodeID{fixed: a.WithZone("").Unmap().String()}, nil
		}

		return localNodeID{fixed: strings.TrimSuffix(c.AdvertisedNodeID, ".")}, nil
	}

	name := c.NodeID

	if c.UseFQDN && name == "" {
		var err error

		name, err = hostname()
		if err != nil {
			return localNodeID{}, fmt.Errorf("unable to get hostname: %w", err)
		}
	}

	if name == "" {
		return localNodeID{}, nil
	}

	// TODO: Delete this once CI config is fixed
	// (fb45297 resolved hostname instead of advertising it as an FQDN until then.
	// node_id is the setting that advertises a name as it is.)
	hosts, err := lookupHost(ctx, name)
	if err != nil {
		return localNodeID{}, fmt.Errorf("unable to resolve hostname %s: %w", name, err)
	}

	var id localNodeID

	for _, h := range hosts {
		a, err := netip.ParseAddr(h)
		if err != nil {
			continue
		}

		id.addrs = append(id.addrs, a.WithZone("").Unmap())
	}

	if len(id.addrs) == 0 {
		return localNodeID{}, fmt.Errorf("hostname %s resolved to no address: %v", name, hosts)
	}

	return id, nil
}

// choose returns the Node ID to advertise on an association whose socket has the
// local address local: an FQDN, or an IP address in canonical text form.

func (n localNodeID) choose(local net.IP) string {
	if n.fixed != "" {
		return n.fixed
	}

	la, ok := netip.AddrFromSlice(local)
	la = la.Unmap()

	if len(n.addrs) == 0 {
		if !ok {
			return ""
		}

		return la.String()
	}

	if ok {
		for _, a := range n.addrs {
			if a.Is4() == la.Is4() {
				return a.String()
			}
		}

		logger.PfcpLog.Warnf("no configured Node ID address is of the family of the N4 "+
			"address %s; advertising %s", la, n.addrs[0])
	}

	return n.addrs[0].String()
}

// nodeIDIE encodes a Node ID as returned by choose: an IP literal as an IPv4 or IPv6
// Node ID, anything else as an FQDN. It is nil for an empty id.
func nodeIDIE(id string) *ie.IE {
	if id == "" {
		return nil
	}

	a, err := netip.ParseAddr(id)
	if err != nil {
		return ie.NewNodeID("", "", id)
	}

	if a.Unmap().Is4() {
		return ie.NewNodeID(a.Unmap().String(), "", "")
	}

	return ie.NewNodeID("", a.String(), "")
}

// peerNodeID decodes a peer's Node ID IE into the form associations are matched by.
//
// An address comes out in canonical text form (RFC 5952 for IPv6), the same string
// go-pfcp's NodeID() gives. An FQDN comes out in lower case without a trailing dot,
// because DNS names compare without regard to case (RFC 4343) and a sender that keeps
// the root label's zero octet otherwise names itself with a trailing dot.
//
// Unlike NodeID(), an address shorter than its type requires is an error, not the
// string "<nil>", which every other malformed Node ID would then have matched.
// Spare bits in the type octet are ignored, as TS 29.244 clause 8.1.1 requires.
func peerNodeID(i *ie.IE) (string, error) {
	if i == nil {
		return "", errNodeIDMissing
	}

	if i.Type != ie.NodeID {
		return "", &ie.InvalidTypeError{Type: i.Type}
	}

	p := i.Payload
	if len(p) < 2 {
		return "", io.ErrUnexpectedEOF
	}

	switch p[0] & 0x0f {
	case nodeIDTypeIPv4:
		if len(p) < 1+net.IPv4len {
			return "", fmt.Errorf("%w: IPv4 address of %d octets", errNodeIDInvalid, len(p)-1)
		}

		return netip.AddrFrom4([4]byte(p[1:5])).String(), nil
	case nodeIDTypeIPv6:
		if len(p) < 1+net.IPv6len {
			return "", fmt.Errorf("%w: IPv6 address of %d octets", errNodeIDInvalid, len(p)-1)
		}

		// Unmap, as net.IP.String() does, so the string is the one NodeID() gave.
		return netip.AddrFrom16([16]byte(p[1:17])).Unmap().String(), nil
	case nodeIDTypeFQDN:
		fqdn := decodeFQDN(p[1:])
		if fqdn == "" {
			return "", fmt.Errorf("%w: empty FQDN", errNodeIDInvalid)
		}

		return fqdn, nil
	default:
		return "", fmt.Errorf("%w: type %d", errNodeIDInvalid, p[0]&0x0f)
	}
}

// decodeFQDN decodes length-prefixed DNS labels (TS 29.244 clause 8.2.38, which refers
// to TS 23.003 clause 19.4.2), as go-pfcp does, and normalises the result: lower case,
// no empty labels, so no trailing dot.
func decodeFQDN(b []byte) string {
	var labels []string

	for offset := 0; offset < len(b); {
		l := int(b[offset])
		if offset+1+l > len(b) {
			break
		}

		if l > 0 {
			labels = append(labels, strings.ToLower(string(b[offset+1:offset+1+l])))
		}

		offset += 1 + l
	}

	return strings.Join(labels, ".")
}

// upFSEID builds the UP F-SEID (TS 29.244 clause 8.2.37) of a session established on
// an association whose socket has the local address local. The address goes in the
// slot of its family; an IPv4 address of a dual-stack socket comes as an IPv4-mapped
// IPv6 address, and goes in the IPv4 slot.
//
// Only that one address is given, even when the UPF also listens on the other family:
// sessions belong to the association they were established on, which is one socket
// connected to one peer address, so a request sent to the UPF's other address would
// arrive from a peer the UPF does not know.
func upFSEID(seid uint64, local net.IP) *ie.IE {
	if v4 := local.To4(); v4 != nil {
		return ie.NewFSEID(seid, v4, nil)
	}

	if v6 := local.To16(); v6 != nil {
		return ie.NewFSEID(seid, nil, v6)
	}

	return ie.NewFSEID(seid, nil, nil)
}
