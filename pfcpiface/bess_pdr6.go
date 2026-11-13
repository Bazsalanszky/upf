// SPDX-FileCopyrightText: 2026 Balázs Toldi
// SPDX-License-Identifier: Apache-2.0

package pfcpiface

import (
	"context"
	"fmt"
	"math"
	"net/netip"

	"github.com/omec-project/upf-epc/logger"
	pb "github.com/omec-project/upf-epc/pfcpiface/bess_pb"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

// PdrLookup6 is the PDR table of IPv6 packets (conf/up4.bess): GtpuParser sends it a
// whole IPv6 packet, the inner one of a G-PDU or one from N6. Its fields, eight of at most
// eight bytes (WildcardMatch's limit), are
//
//	src_iface 1, teid 4, src_ip6_hi 8, src_ip6_lo 8, dst_ip6_hi 8, dst_ip6_lo 8,
//	l4_ports 4 (source port << 16 | destination port), ip_proto 1
//
// and its values are pdrLookup's (pdr_id, fseid, ctr_id, qer_id, far_id). There is no
// tunnel address field: the TEID, which the UPF allocates uniquely, identifies the tunnel
// whatever its outer family.
const PdrLookup6 = "pdrLookup6"

// wildcardKey is the values and masks of a WildcardMatch rule.
type wildcardKey struct {
	values, masks []*pb.FieldData
}

// ipv6PrefixFields is a prefix as two 64-bit values and masks, each value masked; the zero
// Prefix matches any address.
func ipv6PrefixFields(p netip.Prefix) (hi, lo, hiMask, loMask uint64) {
	if !p.IsValid() {
		return 0, 0, 0, 0
	}

	bits := p.Bits()
	if bits >= 64 {
		hiMask = math.MaxUint64
		loMask = math.MaxUint64 << uint(128-bits) // all zero at /64
	} else {
		hiMask = math.MaxUint64 << uint(64-bits) // all zero at /0
	}

	hi, lo = ipv6Halves(p.Addr())

	return hi & hiMask, lo & loMask, hiMask, loMask
}

// srcIfaceField is the PDR's src_iface value and mask. A CP-function PDR matches any
// interface (mask 0), and the value under a zero mask is zero.
func (p pdr) srcIfaceField() (value, mask uint64) {
	return uint64(p.srcIface & p.srcIfaceMask), uint64(p.srcIfaceMask)
}

// pdrLookup6Keys returns the PDR's rules in pdrLookup6 -- one per ternary rule of its port
// ranges -- or none when it has no IPv6 rule (hasIPv6Rule).
func (p pdr) pdrLookup6Keys() ([]wildcardKey, error) {
	if !p.hasIPv6Rule {
		return nil, nil
	}

	af := p.appFilter6
	for _, a := range []netip.Prefix{af.srcIP, af.dstIP} {
		if a.IsValid() && !a.Addr().Is6() {
			return nil, fmt.Errorf("PDR %d IPv6 rule: %v is not an IPv6 prefix", p.pdrID, a)
		}
	}

	portRules, err := CreatePortRangeCartesianProduct(af.srcPortRange, af.dstPortRange)
	if err != nil {
		return nil, err
	}

	iface, ifaceMask := p.srcIfaceField()
	srcHi, srcLo, srcHiMask, srcLoMask := ipv6PrefixFields(af.srcIP)
	dstHi, dstLo, dstHiMask, dstLoMask := ipv6PrefixFields(af.dstIP)

	keys := make([]wildcardKey, 0, len(portRules))
	for _, r := range portRules {
		keys = append(keys, wildcardKey{
			values: []*pb.FieldData{
				intEnc(iface),                /* src_iface */
				intEnc(uint64(p.tunnelTEID)), /* teid */
				intEnc(srcHi),                /* src_ip6_hi */
				intEnc(srcLo),                /* src_ip6_lo */
				intEnc(dstHi),                /* dst_ip6_hi */
				intEnc(dstLo),                /* dst_ip6_lo */
				intEnc(uint64(r.srcPort)<<16 | uint64(r.dstPort)), /* l4_ports */
				intEnc(uint64(af.proto)),                          /* ip_proto */
			},
			masks: []*pb.FieldData{
				intEnc(ifaceMask),                /* src_iface */
				intEnc(uint64(p.tunnelTEIDMask)), /* teid */
				intEnc(srcHiMask),                /* src_ip6_hi */
				intEnc(srcLoMask),                /* src_ip6_lo */
				intEnc(dstHiMask),                /* dst_ip6_hi */
				intEnc(dstLoMask),                /* dst_ip6_lo */
				intEnc(uint64(r.srcMask)<<16 | uint64(r.dstMask)), /* l4_ports */
				intEnc(uint64(af.protoMask)),                      /* ip_proto */
			},
		})
	}

	return keys, nil
}

// pdrValues is the PDR's values in pdrLookup and pdrLookup6.
func (p pdr) pdrValues() []*pb.FieldData {
	return []*pb.FieldData{
		intEnc(uint64(p.pdrID)),      /* pdr-id */
		intEnc(p.fseID),              /* fseid */
		intEnc(uint64(p.ctrID)),      /* ctr_id */
		intEnc(uint64(p.appQERID())), /* qer_id */
		intEnc(uint64(p.farID)),      /* far_id */
	}
}

// writePDR6 adds (or deletes) the PDR's rules in pdrLookup6, and reports whether every
// write was accepted. A pipeline without pdrLookup6 refuses them, and so the session.
func (b *bess) writePDR6(ctx context.Context, p pdr, method upfMsgType) bool {
	keys, err := p.pdrLookup6Keys()
	if err != nil {
		logger.BessLog.Errorln(err)
		return false
	}

	return b.writePDR6Keys(ctx, p, keys, method)
}

// writePDR6Keys writes the PDR's pdrLookup6 rules for the given keys (pdrLookup6Keys).
func (b *bess) writePDR6Keys(ctx context.Context, p pdr, keys []wildcardKey, method upfMsgType) bool {
	for _, k := range keys {
		var msg proto.Message

		if method == upfMsgTypeAdd {
			msg = &pb.WildcardMatchCommandAddArg{
				Gate:     uint64(p.needDecap),
				Priority: int64(math.MaxUint32 - p.precedence),
				Values:   k.values,
				Masks:    k.masks,
				Valuesv:  p.pdrValues(),
			}
		} else {
			msg = &pb.WildcardMatchCommandDeleteArg{Values: k.values, Masks: k.masks}
		}

		arg, err := anypb.New(msg)
		if err != nil {
			logger.BessLog.Errorln(errMarshalRule, msg, err)
			return false
		}

		if refused(b.processPDRTable(ctx, PdrLookup6, arg, method)) {
			return false
		}
	}

	return true
}
