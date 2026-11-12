/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2019 Intel Corporation
 */
/* for GTP parser */
#include "gtpu_parser.h"
/* for ethernet header  */
#include "utils/ether.h"
/* for ip header  */
#include "utils/ip.h"
/* for udp header */
#include "utils/udp.h"
/* for tcp header */
#include "utils/tcp.h"
/* for gtp header */
#include "utils/gtp.h"
/*----------------------------------------------------------------------------------*/
using bess::utils::Ethernet;
using bess::utils::Gtpv1;
using bess::utils::Ipv4;
using bess::utils::Ipv6;
using bess::utils::Tcp;
using bess::utils::Udp;

enum { DEFAULT_GATE = 0, FORWARD_GATE, FORWARD6_GATE };
/*----------------------------------------------------------------------------------*/
void GtpuParser::set_gtp_parsing_attrs(be32_t *sip, be32_t *dip, be16_t *sp,
                                       be16_t *dp, be32_t *teid, be32_t *tipd,
                                       uint8_t *protoid, bess::Packet *p) {
  /* set src_ip */
  set_attr<uint32_t>(this, src_ip_id, p, sip->raw_value());
  /* set dst_ip */
  set_attr<uint32_t>(this, dst_ip_id, p, dip->raw_value());
  /* set src_port_id */
  set_attr<uint16_t>(this, src_port_id, p, sp->raw_value());
  /* set dst_port_id */
  set_attr<uint16_t>(this, dst_port_id, p, dp->raw_value());
  /* set tied_id */
  set_attr<uint32_t>(this, teid_id, p, teid->raw_value());
  /* tunnel_ip4_dst_id  */
  set_attr<uint32_t>(this, tunnel_ip4_dst_id, p, tipd->raw_value());
  /* proto_id */
  set_attr<uint8_t>(this, proto_id, p, *protoid);
}
/*----------------------------------------------------------------------------------*/
/* Whether this is an IPv4 fragment other than the first: a non-zero offset. */
static inline bool is_later_fragment(const Ipv4 *iph) {
  return (iph->fragment_offset.value() & 0x1FFF) != 0;
}
/*----------------------------------------------------------------------------------*/
void GtpuParser::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  int cnt = batch->cnt();

  for (int i = 0; i < cnt; i++) {
    bess::Packet *p = batch->pkts()[i];
    const char *malformed = nullptr;
    gate_idx_t gate = Parse(p, &malformed);
    if (malformed) {
      drop_log_.Sample(ctx, name(), malformed, p);
    }
    EmitPacket(ctx, p, gate);
  }
}
/*----------------------------------------------------------------------------------*/
/* Sets the attributes pdrLookup matches on and returns FORWARD_GATE, or returns
 * DEFAULT_GATE for a packet that is not to be classified. Every read is checked
 * against the bytes the first segment holds before it is made. A packet that
 * claims more than it holds is reported through `malformed`; one that is
 * simply not an IPv4 G-PDU, such as an Error Indication or an IPv6 payload, is
 * dropped without being reported. The G-PDU may come in an IPv4 or an IPv6
 * outer header (see ParseIpv6()). */
gate_idx_t GtpuParser::Parse(bess::Packet *p, const char **malformed) {
  static const uint32_t _const_val = 0xFFFFFFFFu;
  const size_t len = p->head_len();
  char *head = p->head_data<char *>();

  if (len < sizeof(Ethernet)) {
    *malformed = "Ethernet header";
    return DEFAULT_GATE;
  }
  Ethernet *eth = reinterpret_cast<Ethernet *>(head);
  if (eth->ether_type == (be16_t)(Ethernet::kArp)) {
    /* ARP is forwarded as before, but with values that match no rule. It used
     * to be parsed as IPv4, which wrote nothing for most sender MACs, so it was
     * matched on whatever an earlier packet had left in the buffer -- often a
     * session's uplink rule, which sent it to decapsulation. */
    set_unmatchable_attrs(p);
    return FORWARD_GATE;
  }
  if (eth->ether_type == (be16_t)(Ethernet::kIpv6)) {
    return ParseIpv6(p, malformed);
  }
  if (eth->ether_type != (be16_t)(Ethernet::kIpv4)) {
    return DEFAULT_GATE;
  }

  const size_t ip_off = sizeof(Ethernet);
  if (len < ip_off + sizeof(Ipv4)) {
    *malformed = "outer IPv4 header";
    return DEFAULT_GATE;
  }
  Ipv4 *iph = reinterpret_cast<Ipv4 *>(head + ip_off);
  const size_t ihl = iph->header_length << 2;
  if (ihl < sizeof(Ipv4) || ip_off + ihl > len) {
    *malformed = "outer IPv4 header length";
    return DEFAULT_GATE;
  }
  const size_t l4_off = ip_off + ihl;

  /* A fragment after the first carries no transport header, so there are no
   * ports to read: it is classified on its addresses, as ICMP is. */
  if (is_later_fragment(iph)) {
    set_gtp_parsing_attrs(&iph->src, &iph->dst, (be16_t *)&_const_val,
                          (be16_t *)&_const_val, (be32_t *)&_const_val,
                          (be32_t *)&_const_val, &iph->protocol, p);
    return FORWARD_GATE;
  }

  switch (iph->protocol) {
    case Ipv4::kTcp: {
      if (l4_off + 2 * sizeof(be16_t) > len) {
        *malformed = "TCP ports";
        return DEFAULT_GATE;
      }
      Tcp *tcph = reinterpret_cast<Tcp *>(head + l4_off);
      set_gtp_parsing_attrs(&iph->src, &iph->dst, &tcph->src_port,
                            &tcph->dst_port, (be32_t *)&_const_val,
                            (be32_t *)&_const_val, &iph->protocol, p);
      break;
    }
    case Ipv4::kUdp: {
      if (l4_off + sizeof(Udp) > len) {
        *malformed = "UDP header";
        return DEFAULT_GATE;
      }
      Udp *udph = reinterpret_cast<Udp *>(head + l4_off);
      if (udph->dst_port == (be16_t)(UDP_PORT_GTPU)) {
        return ParseGtpu(p, iph->dst, l4_off + sizeof(Udp), malformed);
      }
      set_gtp_parsing_attrs(&iph->src, &iph->dst, &udph->src_port,
                            &udph->dst_port, (be32_t *)&_const_val,
                            (be32_t *)&_const_val, &iph->protocol, p);
      break;
    }
    case Ipv4::kIcmp:
      set_gtp_parsing_attrs(&iph->src, &iph->dst, (be16_t *)&_const_val,
                            (be16_t *)&_const_val, (be32_t *)&_const_val,
                            (be32_t *)&_const_val, &iph->protocol, p);
      break;
    case Ipv4::kEsp:
      set_gtp_parsing_attrs(&iph->src, &iph->dst, (be16_t *)&_const_val,
                            (be16_t *)&_const_val, (be32_t *)&_const_val,
                            (be32_t *)&_const_val, &iph->protocol, p);
      break;
    default:
      /* Classified on its own addresses, as ICMP is, rather than on values an
       * earlier packet left in the buffer. */
      set_gtp_parsing_attrs(&iph->src, &iph->dst, (be16_t *)&_const_val,
                            (be16_t *)&_const_val, (be32_t *)&_const_val,
                            (be32_t *)&_const_val, &iph->protocol, p);
      break;
  }

  return FORWARD_GATE;
}
/*----------------------------------------------------------------------------------*/
/* Attributes no PDR matches: no rule has an all-ones TEID or tunnel
 * destination on the access side, or an all-ones UE address on the core side.
 * Protocol 255 is reserved (IANA). */
void GtpuParser::set_unmatchable_attrs(bess::Packet *p) {
  static const uint32_t all_ones = 0xFFFFFFFFu;
  static uint8_t reserved_proto = 0xFF;
  set_gtp_parsing_attrs((be32_t *)&all_ones, (be32_t *)&all_ones,
                        (be16_t *)&all_ones, (be16_t *)&all_ones,
                        (be32_t *)&all_ones, (be32_t *)&all_ones,
                        &reserved_proto, p);
}
/*----------------------------------------------------------------------------------*/
/* An IPv6 packet: a G-PDU in an IPv6 outer header (N3/N9 over IPv6) is
 * classified on its inner packet, as one in an IPv4 outer header is. The UDP
 * header must follow the fixed header for that. Any other IPv6 packet -- IPv6
 * UE traffic on the core side, but also neighbour discovery, which no PDR
 * matches -- is classified on its own header for pdrLookup6
 * (ClassifyIpv6()).
 *
 * pdrLookup matches the tunnel destination in the 4-byte tunnel_ipv4_dst. For
 * an IPv6 outer header that is the low-order 32 bits of the destination
 * address: the access filters let in only packets for the UPF's own N3
 * addresses, so the field only has to tell those apart, and pfcpiface writes
 * an IPv6 F-TEID the same way. */
gate_idx_t GtpuParser::ParseIpv6(bess::Packet *p, const char **malformed) {
  const size_t len = p->head_len();
  char *head = p->head_data<char *>();

  const size_t ip_off = sizeof(Ethernet);
  if (len < ip_off + sizeof(Ipv6)) {
    *malformed = "outer IPv6 header";
    return DEFAULT_GATE;
  }
  Ipv6 *ip6h = reinterpret_cast<Ipv6 *>(head + ip_off);
  if (ip6h->version() != 6) {
    return DEFAULT_GATE;
  }
  static const uint32_t all_ones = 0xFFFFFFFFu;
  const size_t l4_off = ip_off + sizeof(Ipv6);
  if (ip6h->next_header != Ipv4::kUdp) {
    return ClassifyIpv6(p, ip_off, be32_t(all_ones), malformed);
  }
  if (l4_off + sizeof(Udp) > len) {
    *malformed = "UDP header";
    return DEFAULT_GATE;
  }
  Udp *udph = reinterpret_cast<Udp *>(head + l4_off);
  if (udph->dst_port != (be16_t)(UDP_PORT_GTPU)) {
    return ClassifyIpv6(p, ip_off, be32_t(all_ones), malformed);
  }
  return ParseGtpu(p, Ipv6TunnelKey(*ip6h), l4_off + sizeof(Udp), malformed);
}
/*----------------------------------------------------------------------------------*/
/* The GTP-U part of Parse(), from the GTP-U header at `gtp_off`, for a tunnel
 * whose destination pdrLookup knows as `tunnel_dst` (see ParseIpv6()). */
gate_idx_t GtpuParser::ParseGtpu(bess::Packet *p, be32_t tunnel_dst,
                                 size_t gtp_off, const char **malformed) {
  static const uint32_t _const_val = 0xFFFFFFFFu;
  const size_t len = p->head_len();
  char *head = p->head_data<char *>();

  Gtpv1 *gtph = reinterpret_cast<Gtpv1 *>(head + gtp_off);
  const size_t gtp_len = gtph->header_length(len - gtp_off);
  if (gtp_len == 0) {
    *malformed = "GTP-U header";
    return DEFAULT_GATE;
  }

  /* TS 29.281 5.1: version 1, and PT 1 for GTP (0 is GTP'). The spare bit is
   * deliberately not checked: the receiver shall not evaluate it (NOTE 0 of
   * Figure 5.1-1). */
  if (gtph->version != GTPU_VERSION || gtph->pt != GTP_PROTOCOL_TYPE_GTP) {
    *malformed = "GTP-U version or protocol type";
    return DEFAULT_GATE;
  }

  /* Only a G-PDU carries a packet to classify. Any other message on this path
   * (an Error Indication, an End Marker) reaches no PDR. */
  if (gtph->type != GTP_GPDU) {
    return DEFAULT_GATE;
  }

  const size_t inner_off = gtp_off + gtp_len;
  if (inner_off >= len) {
    *malformed = "inner IPv4 header";
    return DEFAULT_GATE;
  }
  Ipv4 *iph = reinterpret_cast<Ipv4 *>(head + inner_off);
  if (iph->version == 6) {
    /* An IPv6 UE packet: pdrLookup6, on the TEID. The tunnel destination is
     * not matched there: the TEID, which the UPF allocates uniquely, is. */
    return ClassifyIpv6(p, inner_off, (be32_t)gtph->teid.value(), malformed);
  }
  if (iph->version != 4) {
    return DEFAULT_GATE;
  }
  const size_t ihl = iph->header_length << 2;
  if (inner_off + sizeof(Ipv4) > len || ihl < sizeof(Ipv4) ||
      inner_off + ihl > len) {
    *malformed = "inner IPv4 header";
    return DEFAULT_GATE;
  }
  const size_t l4_off = inner_off + ihl;

  be32_t teid = (be32_t)gtph->teid.value();
  /* A fragment after the first carries no transport header (see Parse()). */
  const uint8_t proto = is_later_fragment(iph) ? 0 : iph->protocol;
  switch (proto) {
    case Ipv4::kTcp:
    case Ipv4::kUdp: {
      if (l4_off + 2 * sizeof(be16_t) > len) {
        *malformed = "inner ports";
        return DEFAULT_GATE;
      }
      /* TCP and UDP both start with the source and destination ports. */
      Udp *ports = reinterpret_cast<Udp *>(head + l4_off);
      set_gtp_parsing_attrs(&iph->src, &iph->dst, &ports->src_port,
                            &ports->dst_port, (be32_t *)&teid, &tunnel_dst,
                            &iph->protocol, p);
      break;
    }
    default:
      /* ESP, later fragments and the rest: no ports to classify on. */
      set_gtp_parsing_attrs(&iph->src, &iph->dst, (be16_t *)&_const_val,
                            (be16_t *)&_const_val, (be32_t *)&teid, &tunnel_dst,
                            &iph->protocol, p);
      break;
  }

  return FORWARD_GATE;
}
/*----------------------------------------------------------------------------------*/
/* The extension headers an IPv6 packet may carry before its upper-layer header
 * (RFC 8200 section 4) that are skipped to find it: Hop-by-Hop Options (an MLD
 * report has one), Routing and Destination Options. A Fragment header is
 * skipped too; a fragment other than the first has no ports. Anything else,
 * ESP included, is the upper layer as far as matching goes. */
static constexpr uint8_t kIpv6HopByHop = 0;
static constexpr uint8_t kIpv6Routing = 43;
static constexpr uint8_t kIpv6Fragment = 44;
static constexpr uint8_t kIpv6DestOpts = 60;
static constexpr int kMaxIpv6ExtHeaders = 4;
/*----------------------------------------------------------------------------------*/
/* Sets the attributes pdrLookup6 matches on for the IPv6 packet at `ip_off`
 * and returns FORWARD6_GATE: its addresses as two 8-byte halves each
 * (src_ip6_hi/lo, dst_ip6_hi/lo, network byte order, as pfcpiface writes
 * them), its transport ports as one 4-byte field (l4_ports: source port, then
 * destination port, as they open a TCP or UDP header; all ones without
 * ports), the upper-layer protocol (ip_proto), and the TEID (all ones for a
 * packet that came in no tunnel). pdrLookup6 has eight fields of at most
 * eight bytes, WildcardMatch's limit, which is why the ports share one. */
gate_idx_t GtpuParser::ClassifyIpv6(bess::Packet *p, size_t ip_off, be32_t teid,
                                    const char **malformed) {
  const size_t len = p->head_len();
  const uint8_t *head = p->head_data<const uint8_t *>();
  if (ip_off + sizeof(Ipv6) > len) {
    *malformed = "IPv6 header";
    return DEFAULT_GATE;
  }
  const Ipv6 *ip6h = reinterpret_cast<const Ipv6 *>(head + ip_off);
  if (ip6h->version() != 6) {
    return DEFAULT_GATE;
  }

  uint8_t proto = ip6h->next_header;
  size_t l4_off = ip_off + sizeof(Ipv6);
  bool later_fragment = false;
  for (int i = 0; i < kMaxIpv6ExtHeaders; i++) {
    if (proto == kIpv6HopByHop || proto == kIpv6Routing ||
        proto == kIpv6DestOpts) {
      if (l4_off + 2 > len) {
        *malformed = "IPv6 extension header";
        return DEFAULT_GATE;
      }
      proto = head[l4_off];
      l4_off += (static_cast<size_t>(head[l4_off + 1]) + 1) * 8;
    } else if (proto == kIpv6Fragment) {
      if (l4_off + 8 > len) {
        *malformed = "IPv6 fragment header";
        return DEFAULT_GATE;
      }
      proto = head[l4_off];
      const uint16_t offset = (head[l4_off + 2] << 8 | head[l4_off + 3]) & ~7u;
      later_fragment = later_fragment || offset != 0;
      l4_off += 8;
    } else {
      break;
    }
  }

  uint32_t ports = 0xFFFFFFFFu; /* raw: source port, destination port */
  if (!later_fragment && (proto == Ipv4::kTcp || proto == Ipv4::kUdp)) {
    if (l4_off + sizeof(ports) > len) {
      *malformed = "IPv6 transport ports";
      return DEFAULT_GATE;
    }
    memcpy(&ports, head + l4_off, sizeof(ports));
  }

  uint64_t half;
  memcpy(&half, ip6h->src, sizeof(half));
  set_attr<uint64_t>(this, src_ip6_hi_id, p, half);
  memcpy(&half, ip6h->src + 8, sizeof(half));
  set_attr<uint64_t>(this, src_ip6_lo_id, p, half);
  memcpy(&half, ip6h->dst, sizeof(half));
  set_attr<uint64_t>(this, dst_ip6_hi_id, p, half);
  memcpy(&half, ip6h->dst + 8, sizeof(half));
  set_attr<uint64_t>(this, dst_ip6_lo_id, p, half);
  set_attr<uint32_t>(this, l4_ports_id, p, ports);
  set_attr<uint32_t>(this, teid_id, p, teid.raw_value());
  set_attr<uint8_t>(this, proto_id, p, proto);
  return FORWARD6_GATE;
}
/*----------------------------------------------------------------------------------*/
CommandResponse GtpuParser::Init(const bess::pb::EmptyArg &) {
  using AccessMode = bess::metadata::Attribute::AccessMode;
  src_ip_id = AddMetadataAttr("src_ip", sizeof(uint32_t), AccessMode::kWrite);
  dst_ip_id = AddMetadataAttr("dst_ip", sizeof(uint32_t), AccessMode::kWrite);
  src_port_id =
      AddMetadataAttr("src_port", sizeof(uint16_t), AccessMode::kWrite);
  dst_port_id =
      AddMetadataAttr("dst_port", sizeof(uint16_t), AccessMode::kWrite);
  teid_id = AddMetadataAttr("teid", sizeof(uint32_t), AccessMode::kWrite);
  tunnel_ip4_dst_id =
      AddMetadataAttr("tunnel_ipv4_dst", sizeof(uint32_t), AccessMode::kWrite);
  proto_id = AddMetadataAttr("ip_proto", sizeof(uint8_t), AccessMode::kWrite);
  src_ip6_hi_id =
      AddMetadataAttr("src_ip6_hi", sizeof(uint64_t), AccessMode::kWrite);
  src_ip6_lo_id =
      AddMetadataAttr("src_ip6_lo", sizeof(uint64_t), AccessMode::kWrite);
  dst_ip6_hi_id =
      AddMetadataAttr("dst_ip6_hi", sizeof(uint64_t), AccessMode::kWrite);
  dst_ip6_lo_id =
      AddMetadataAttr("dst_ip6_lo", sizeof(uint64_t), AccessMode::kWrite);
  l4_ports_id =
      AddMetadataAttr("l4_ports", sizeof(uint32_t), AccessMode::kWrite);

  return CommandSuccess();
}
/*----------------------------------------------------------------------------------*/
ADD_MODULE(GtpuParser, "gtpu_parser", "parsing module for gtp traffic")
