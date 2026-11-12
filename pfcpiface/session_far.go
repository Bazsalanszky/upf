// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Intel Corporation

package pfcpiface

import (
	"encoding/binary"

	"github.com/omec-project/upf-epc/logger"
)

// CreateFAR appends far to existing list of FARs in the session.
func (s *PFCPSession) CreateFAR(f far) {
	s.fars = append(s.fars, f)
}

// Packet structure constants for GTP-U end marker
const (
	ethHeaderSize  = 14
	ipv4HeaderSize = 20
	udpHeaderSize  = 8
	gtpHeaderSize  = 8 // Minimum GTP-U header without optional fields
	endMarkerSize  = ethHeaderSize + ipv4HeaderSize + udpHeaderSize + gtpHeaderSize

	// Offsets within the packet
	ethTypeOffset    = 12
	ipOffset         = ethHeaderSize
	ipChecksumOffset = ipOffset + 10
	ipSrcOffset      = ipOffset + 12
	ipDstOffset      = ipOffset + 16
	udpOffset        = ipOffset + ipv4HeaderSize
	gtpOffset        = udpOffset + udpHeaderSize

	// Protocol constants
	gtpEndMarkerType = 254
)

// Placeholder MAC addresses for end marker packets.
// These are immutable values that will be replaced by the dataplane (BESS)
// with actual MAC addresses based on the routing/forwarding table.
// Note: Defined as variables (not constants) because Go doesn't support
// byte slice/array constants, but these should be treated as read-only.
var (
	endMarkerDstMAC = [6]byte{0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD} // Placeholder for next-hop MAC
	endMarkerSrcMAC = [6]byte{0xFF, 0xAA, 0xFA, 0xAA, 0xFF, 0xAA} // Placeholder for local interface MAC
)

// addEndMarker appends a GTP-U End Marker for the tunnel farItem forwards on, in an
// outer header of the tunnel's family.
func addEndMarker(farItem far, endMarkerList *[][]byte) {
	logger.PfcpLog.Infoln("adding end marker for farID:", farItem.farID)

	if farItem.tunnelIPDst.Is6() {
		addEndMarker6(farItem, endMarkerList)
		return
	}

	tunnelSrc, tunnelDst, err := farItem.ipv4Tunnel()
	if err != nil {
		logger.PfcpLog.Errorln("no end marker for the old tunnel:", err)
		return
	}

	packet := make([]byte, endMarkerSize)

	// Ethernet header - placeholder MAC addresses will be replaced by dataplane
	copy(packet[0:6], endMarkerDstMAC[:])
	copy(packet[6:12], endMarkerSrcMAC[:])
	binary.BigEndian.PutUint16(packet[ethTypeOffset:], 0x0800) // IPv4

	// IPv4 header
	packet[ipOffset] = 0x45                                                                     // Version 4, IHL 5
	packet[ipOffset+1] = 0                                                                      // DSCP/ECN
	binary.BigEndian.PutUint16(packet[ipOffset+2:], ipv4HeaderSize+udpHeaderSize+gtpHeaderSize) // Total length
	binary.BigEndian.PutUint16(packet[ipOffset+4:], 0)                                          // Identification
	binary.BigEndian.PutUint16(packet[ipOffset+6:], 0)                                          // Flags/Fragment offset
	packet[ipOffset+8] = 64                                                                     // TTL
	packet[ipOffset+9] = 17                                                                     // UDP protocol
	// Checksum at ipOffset+10 calculated below
	binary.BigEndian.PutUint32(packet[ipSrcOffset:], tunnelSrc)
	binary.BigEndian.PutUint32(packet[ipDstOffset:], tunnelDst)

	// Calculate and set IPv4 checksum
	binary.BigEndian.PutUint16(packet[ipChecksumOffset:], calculateIPv4Checksum(packet[ipOffset:ipOffset+ipv4HeaderSize]))

	// UDP header
	binary.BigEndian.PutUint16(packet[udpOffset:], tunnelGTPUPort)                // Source port
	binary.BigEndian.PutUint16(packet[udpOffset+2:], tunnelGTPUPort)              // Destination port
	binary.BigEndian.PutUint16(packet[udpOffset+4:], udpHeaderSize+gtpHeaderSize) // UDP length
	binary.BigEndian.PutUint16(packet[udpOffset+6:], 0)                           // Checksum (optional for IPv4)

	// GTP-U header (8 bytes - no optional fields for end marker)
	packet[gtpOffset] = 0x30                                             // Version 1, PT=1, no extension/sequence/N-PDU
	packet[gtpOffset+1] = gtpEndMarkerType                               // Message type: End Marker
	binary.BigEndian.PutUint16(packet[gtpOffset+2:], 0)                  // Message length: 0
	binary.BigEndian.PutUint32(packet[gtpOffset+4:], farItem.tunnelTEID) // TEID

	*endMarkerList = append(*endMarkerList, packet)
}

// IPv6 end marker layout: the fixed IPv6 header in place of the IPv4 one.
const (
	ipv6HeaderSize = 40
	endMarker6Size = ethHeaderSize + ipv6HeaderSize + udpHeaderSize + gtpHeaderSize
	ip6SrcOffset   = ipOffset + 8
	ip6DstOffset   = ipOffset + 24
	udp6Offset     = ipOffset + ipv6HeaderSize
	gtp6Offset     = udp6Offset + udpHeaderSize
)

// addEndMarker6 appends the End Marker of a tunnel to an IPv6 peer, sent from the
// address the FAR's tunnel leaves from. Over IPv6 the UDP checksum is not optional
// (RFC 8200 section 8.1), so it is filled in; the datapath does not recompute it.
func addEndMarker6(farItem far, endMarkerList *[][]byte) {
	if !farItem.tunnelIPSrc.Is6() {
		logger.PfcpLog.Errorln("no end marker for the old tunnel: no IPv6 source for", farItem.tunnelIPDst)
		return
	}

	packet := make([]byte, endMarker6Size)

	copy(packet[0:6], endMarkerDstMAC[:])
	copy(packet[6:12], endMarkerSrcMAC[:])
	binary.BigEndian.PutUint16(packet[ethTypeOffset:], 0x86DD) // IPv6

	// IPv6 header: version 6, traffic class and flow label 0
	packet[ipOffset] = 0x60
	binary.BigEndian.PutUint16(packet[ipOffset+4:], udpHeaderSize+gtpHeaderSize) // Payload length
	packet[ipOffset+6] = 17                                                      // Next header: UDP
	packet[ipOffset+7] = 64                                                      // Hop limit
	src, dst := farItem.tunnelIPSrc.As16(), farItem.tunnelIPDst.As16()
	copy(packet[ip6SrcOffset:], src[:])
	copy(packet[ip6DstOffset:], dst[:])

	binary.BigEndian.PutUint16(packet[udp6Offset:], tunnelGTPUPort)
	binary.BigEndian.PutUint16(packet[udp6Offset+2:], tunnelGTPUPort)
	binary.BigEndian.PutUint16(packet[udp6Offset+4:], udpHeaderSize+gtpHeaderSize)

	packet[gtp6Offset] = 0x30
	packet[gtp6Offset+1] = gtpEndMarkerType
	binary.BigEndian.PutUint32(packet[gtp6Offset+4:], farItem.tunnelTEID)

	binary.BigEndian.PutUint16(packet[udp6Offset+6:],
		udp6Checksum(src, dst, packet[udp6Offset:]))

	*endMarkerList = append(*endMarkerList, packet)
}

// udp6Checksum is the UDP checksum of datagram (its checksum field 0) between src and
// dst over IPv6 (RFC 8200 section 8.1); a sum of 0 is sent as 0xffff (RFC 768).
func udp6Checksum(src, dst [16]byte, datagram []byte) uint16 {
	var sum uint32

	add := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(b[i:]))
		}

		if len(b)%2 == 1 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}

	add(src[:])
	add(dst[:])
	sum += uint32(len(datagram)) + 17
	add(datagram)

	for sum>>16 != 0 {
		sum = (sum >> 16) + (sum & 0xffff)
	}

	if c := ^uint16(sum); c != 0 {
		return c
	}

	return 0xffff
}

// calculateIPv4Checksum calculates Internet Checksum for IPv4 header (RFC 1071).
// This function handles fixed 20-byte IPv4 headers (no options) by summing all 10 16-bit words directly.
func calculateIPv4Checksum(header []byte) uint16 {
	if len(header) < ipv4HeaderSize {
		logger.PfcpLog.Errorf("invalid IPv4 header length for checksum calculation: expected %d bytes, got %d bytes",
			ipv4HeaderSize, len(header))
		return 0
	}

	// Sum all 16-bit words (20 bytes = 10 words)
	var sum uint32
	for i := 0; i < ipv4HeaderSize; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i:]))
	}

	// Fold 32-bit sum to 16 bits
	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16
	return ^uint16(sum)
}

// UpdateFAR updates existing far in the session.
func (s *PFCPSession) UpdateFAR(f *far, endMarkerList *[][]byte) error {
	for idx, v := range s.fars {
		if v.farID == f.farID {
			if f.sendEndMarker {
				addEndMarker(v, endMarkerList)
			}

			s.fars[idx] = *f

			return nil
		}
	}

	return ErrNotFound("FAR")
}

// RemoveFAR removes far from existing list of FARs in the session.
func (s *PFCPSession) RemoveFAR(id uint32) (*far, error) {
	for idx, v := range s.fars {
		if v.farID == id {
			s.fars = append(s.fars[:idx], s.fars[idx+1:]...)
			return &v, nil
		}
	}

	return nil, ErrNotFound("FAR")
}
