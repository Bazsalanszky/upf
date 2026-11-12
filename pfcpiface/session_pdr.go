// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Intel Corporation

package pfcpiface

import (
	"net"

	"github.com/omec-project/upf-epc/logger"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

func addPdrInfo(msg *message.SessionEstablishmentResponse, pdrs []pdr) {
	logger.PfcpLog.Infoln("add PDRs with UPF alloc IPs to Establishment response")
	logger.PfcpLog.Infoln("PDRs:", pdrs)
	for _, pdr := range pdrs {
		logger.PfcpLog.Infoln("pdrID:", pdr.pdrID)
		if pdr.UPAllocateFteid {
			logger.PfcpLog.Infoln("adding PDR with tunnel TEID:", pdr.tunnelTEID)
			msg.CreatedPDR = append(msg.CreatedPDR,
				ie.NewCreatedPDR(
					ie.NewPDRID(uint16(pdr.pdrID)),
					createdFTEID(pdr),
				))
		}
		if pdr.allocIPFlag && (pdr.srcIface == core) {
			logger.PfcpLog.Debugln("pdrID:", pdr.pdrID)
			var flags uint8 = 0x02
			ueIP := pdr.ueAddress
			logger.PfcpLog.Debugln("ueIP:", ueIP.String())
			msg.CreatedPDR = append(msg.CreatedPDR,
				ie.NewCreatedPDR(
					ie.NewPDRID(uint16(pdr.pdrID)),
					ie.NewUEIPAddress(flags, ueIP.String(), "", 0, 0),
				))
		}
	}
}

// createdFTEID is the F-TEID the UP function chose for pdr, with the address of each
// family it chose: V4 (0x01), V6 (0x02) or both (TS 29.244 clause 8.2.3).
func createdFTEID(pdr pdr) *ie.IE {
	var flags uint8

	var v4, v6 net.IP

	if pdr.tunnelIPDst.IsValid() {
		flags |= 0x01
		v4 = ipFromAddr(pdr.tunnelIPDst.Addr())
	}

	if pdr.tunnelIPv6Dst.IsValid() {
		flags |= 0x02
		v6 = ipFromAddr(pdr.tunnelIPv6Dst.Addr())
	}

	return ie.NewFTEID(flags, pdr.tunnelTEID, v4, v6, 0)
}

// CreatePDR appends pdr to existing list of PDRs in the session.
func (s *PFCPSession) CreatePDR(p pdr) {
	s.pdrs = append(s.pdrs, p)
}

// UpdatePDR updates existing pdr in the session.
func (s *PFCPSession) UpdatePDR(p pdr) error {
	for idx, v := range s.pdrs {
		if v.pdrID == p.pdrID {
			s.pdrs[idx] = p
			return nil
		}
	}

	return ErrNotFound("PDR")
}

// RemovePDR removes pdr from existing list of PDRs in the session.
func (s *PFCPSession) RemovePDR(id uint32) (*pdr, error) {
	for idx, v := range s.pdrs {
		if v.pdrID == id {
			s.pdrs = append(s.pdrs[:idx], s.pdrs[idx+1:]...)
			return &v, nil
		}
	}

	return nil, ErrNotFound("PDR")
}
