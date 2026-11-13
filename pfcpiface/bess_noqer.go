// SPDX-FileCopyrightText: 2026 Balázs Toldi
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"context"
)

// ownQERIDFlag marks the qer_id of a PDR that has no QER. TS 29.244 clause 7.5.2.2 makes the
// QER ID of a Create PDR optional, and the SMF's router solicitation PDR (UP2CP) has none.
// BESS looks every PDR's packets up in appQERLookup on (src_iface, qer_id, fseid) and drops
// a miss (qerFailGate), so such a PDR forwarded nothing. Its rules now carry a qer_id of its
// own, ownQERIDFlag | PDR ID, which addPDR gives an unmetered appQERLookup entry. The flag is
// bit 31, which a dynamic QER ID (allocated by the CP) never has: it marks a predefined QER,
// which pfcpiface does not support. PDR IDs are 16 bits, so the ID is unique in the session.
const ownQERIDFlag uint32 = 1 << 31

// hasOwnQER reports whether the PDR gets a QER entry of its own: it has no QER, and it is a
// rule in the IPv6 table only (installsIPv4Rule). A PDR with an IPv4 rule keeps qer_id 0 and
// the datapath it has always had, so that IPv4 sessions are programmed byte for byte as
// before; the SMF gives every IPv4 PDR a QER.
func (p pdr) hasOwnQER() bool {
	return len(p.qerIDList) == 0 && !p.installsIPv4Rule()
}

// appQERID is the qer_id the PDR's rules carry: its first QER, its own (ownQERIDFlag), or 0.
func (p pdr) appQERID() uint32 {
	switch {
	case len(p.qerIDList) > 0:
		return p.qerIDList[0]
	case p.hasOwnQER():
		return ownQERIDFlag | p.pdrID
	default:
		return 0
	}
}

// ownQER is the unmetered QER of a PDR without one.
func (p pdr) ownQER() qer {
	return qer{
		qerID:    p.appQERID(),
		qosLevel: ApplicationQos,
		fseID:    p.fseID,
		fseidIP:  p.fseidIP,
	}
}

// writeOwnQER adds (or deletes) the unmetered appQERLookup entry of a PDR without a QER, on
// access and core as handleUplinkQER and handleDownlinkQER do for a QER. A PDR with a QER
// has nothing to write.
func (b *bess) writeOwnQER(ctx context.Context, p pdr, method upfMsgType) error {
	if !p.hasOwnQER() {
		return nil
	}

	q := p.ownQER()

	for _, srcIface := range []uint8{access, core} {
		var err error
		if method == upfMsgTypeDel {
			err = b.delApplicationQER(ctx, srcIface, q)
		} else {
			err = b.addApplicationQER(ctx, qerGateUnmeter, srcIface, 0, 0, 0, 0, 0, q)
		}

		if err != nil {
			return err
		}
	}

	return nil
}
