/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2019 Intel Corporation
 */
/* for gtpu_encap decls */
#include "gtpu_encap.h"
/* for rte_zmalloc() */
#include <rte_malloc.h>
/* for IPVERSION */
#include <netinet/ip.h>
/* for be32_t */
#include "utils/endian.h"
/* for ToIpv4Address() */
#include "utils/ip.h"
/* for udp header */
#include "utils/udp.h"
/* for ethernet header */
#include "utils/ether.h"
/* for gtp header */
#include "utils/gtp.h"
/* for GetDesc() */
#include "utils/format.h"
#include <rte_jhash.h>
/*----------------------------------------------------------------------------------*/
using bess::utils::be16_t;
using bess::utils::be32_t;
using bess::utils::be64_t;
using bess::utils::Ethernet;
using bess::utils::Gtpv1;
using bess::utils::Gtpv1PDUSessExt;
using bess::utils::Gtpv1SeqPDUExt;
using bess::utils::Ipv4;
using bess::utils::Ipv6;
using bess::utils::ToIpv4Address;
using bess::utils::Udp;

enum { DEFAULT_GATE = 0, FORWARD_GATE };
/*----------------------------------------------------------------------------------*/
// Template for generating UDP packets without data
struct [[gnu::packed]] PacketTemplate {
  Ipv4 iph;
  Udp udph;
  Gtpv1 gtph;
  Gtpv1SeqPDUExt speh;
  Gtpv1PDUSessExt psch;

  PacketTemplate() {
    psch.qfi = 0;  // to fill in
    psch.spare2 = 0;
    psch.spare1 = 0;
    psch.pdu_type = 0;  // to fill in
    psch.hlen = psch.header_length();
    speh.ext = psch.type();
    speh.npdu = 0;
    speh.seqnum = (be16_t)0;
    gtph.version = GTPU_VERSION;
    gtph.pt = GTP_PROTOCOL_TYPE_GTP;
    gtph.spare = 0;
    gtph.ex = 0;  // conditionally set this
    gtph.seq = 0;
    gtph.pdn = 0;
    gtph.type = GTP_GPDU;
    gtph.length = (be16_t)0;  // to fill in
    gtph.teid = (be32_t)0;    // to fill in
    udph.src_port = (be16_t)UDP_PORT_GTPU;
    udph.dst_port = (be16_t)UDP_PORT_GTPU;
    udph.length = (be16_t)0;  // to fill in
    /* calculated by L4Checksum module in line */
    udph.checksum = 0;
    iph.version = IPVERSION;
    iph.header_length = (sizeof(Ipv4) >> 2);
    iph.type_of_service = 0;
    iph.length = (be16_t)0;  // to fill in
    iph.id = (be16_t)0;      // to fill in
    iph.fragment_offset = (be16_t)0;
    iph.ttl = 64;
    iph.protocol = IPPROTO_UDP;
    /* calculated by IPChecksum module in line */
    iph.checksum = 0;
    iph.src = (be32_t)0;  // to fill in
    iph.dst = (be32_t)0;  // to fill in
  }
};
static PacketTemplate outer_ip_template;
/*----------------------------------------------------------------------------------*/
// The same headers behind an IPv6 outer header (N3/N9 over IPv6).
struct [[gnu::packed]] PacketTemplate6 {
  Ipv6 ip6h;
  Udp udph;
  Gtpv1 gtph;
  Gtpv1SeqPDUExt speh;
  Gtpv1PDUSessExt psch;

  PacketTemplate6() {
    const PacketTemplate &v4 = outer_ip_template;
    udph = v4.udph;
    gtph = v4.gtph;
    speh = v4.speh;
    psch = v4.psch;
    ip6h.set_version_traffic_class(0);  // traffic class to fill in
    ip6h.payload_length = (be16_t)0;    // to fill in
    ip6h.next_header = IPPROTO_UDP;
    ip6h.hop_limit = 64;
    memset(ip6h.src, 0, sizeof(ip6h.src));  // to fill in
    memset(ip6h.dst, 0, sizeof(ip6h.dst));  // to fill in
  }
};
static PacketTemplate6 outer_ip6_template;
static_assert(sizeof(PacketTemplate6) ==
                  sizeof(PacketTemplate) + sizeof(Ipv6) - sizeof(Ipv4),
              "the two templates differ beyond the IP header");
/*----------------------------------------------------------------------------------*/
/* The DSCP and ECN bits of the packet carried, IPv4 or IPv6, which the outer
 * header copies; 0 for anything else. */
static inline uint8_t inner_traffic_class(const bess::Packet *p) {
  if (static_cast<size_t>(p->head_len()) < sizeof(Ethernet) + 2) {
    return 0;
  }
  const uint8_t *ip = p->head_data<const uint8_t *>() + sizeof(Ethernet);
  switch (ip[0] >> 4) {
    case 4:
      return ip[1];  // Type of Service
    case 6:
      return static_cast<uint8_t>((ip[0] << 4) | (ip[1] >> 4));
    default:
      return 0;
  }
}
/*----------------------------------------------------------------------------------*/
/* Fills in the outer IPv6 header for a tunnel to `dst_hi`:`dst_lo` from the
 * source this direction uses; false if there is none. */
bool GtpuEncap::FillIpv6(Ipv6 *ip6h, uint8_t action, uint64_t dst_hi,
                         uint64_t dst_lo, uint8_t traffic_class,
                         uint16_t payload_len) const {
  /* Downlink (action 0, farForwardD) leaves through the access interface,
   * uplink (1, farForwardU) through the core one. */
  const Ipv6Source &src = action == 0 ? access_ip6_ : core_ip6_;
  if (!src.set) {
    return false;
  }
  ip6h->set_version_traffic_class(traffic_class);
  ip6h->payload_length = be16_t(payload_len);
  memcpy(ip6h->src, src.addr, sizeof(ip6h->src));
  const be64_t hi(dst_hi), lo(dst_lo);
  memcpy(ip6h->dst, &hi, sizeof(hi));
  memcpy(ip6h->dst + 8, &lo, sizeof(lo));
  return true;
}
/*----------------------------------------------------------------------------------*/
void GtpuEncap::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  int cnt = batch->cnt();

  /* The outer header leaves DF clear, so the datagram may be fragmented on
   * the path, and RFC 6864 2.1 then asks for an ID unique for its source,
   * destination and protocol: fragments of two datagrams sharing an ID
   * reassemble into one corrupt packet. A counter cannot hold that for a
   * whole datagram lifetime at N3 rates -- 16 bits is 65536 packets, and
   * one counter serves every tunnel -- but it puts collisions that far
   * apart instead of in every pair of packets. Reserve a run of IDs for
   * this batch and give each packet the next one. */
  uint16_t ip_id = next_ip_id.fetch_add(cnt, std::memory_order_relaxed);

  /* Gate 1 is only usable with an IPv6 source (see Init()) */
  const bool outer6 = ctx->current_igate == kIpv6Gate;
  if (outer6 && tout_dip6_hi_attr < 0) {
    RunChooseModule(ctx, 0, batch);
    return;
  }

  for (int i = 0; i < cnt; i++) {
    bess::Packet *p = batch->pkts()[i];

    /* check attributes' values now */
    uint8_t at_pdu_type = 0;
    bess::metadata::mt_offset_t off = attr_offset(pdu_type_attr);
    at_pdu_type = get_attr_with_offset<uint8_t>(off, p);

    uint8_t at_qfi = 0;
    off = attr_offset(qfi_attr);
    at_qfi = get_attr_with_offset<uint8_t>(off, p);

    uint32_t at_tout_sip = 0;
    off = attr_offset(tout_sip_attr);
    at_tout_sip = get_attr_with_offset<uint32_t>(off, p);

    uint32_t at_tout_dip = 0;
    off = attr_offset(tout_dip_attr);
    at_tout_dip = get_attr_with_offset<uint32_t>(off, p);

    uint32_t at_tout_teid = 0;
    off = attr_offset(tout_teid);
    at_tout_teid = get_attr_with_offset<uint32_t>(off, p);

    uint16_t at_tout_uport = 0;
    off = attr_offset(tout_uport);
    at_tout_uport = get_attr_with_offset<uint16_t>(off, p);

    /* A tunnel to an IPv6 peer comes in on input gate 1 with the peer in
     * the tunnel_out_dst_ip6 attributes (farLookup6 in up4.bess); one to an
     * IPv4 peer comes in on gate 0, where those attributes are not set. */
    uint64_t at_tout_dip6_hi = 0;
    uint64_t at_tout_dip6_lo = 0;
    if (outer6) {
      off = attr_offset(tout_dip6_hi_attr);
      at_tout_dip6_hi = get_attr_with_offset<uint64_t>(off, p);
      off = attr_offset(tout_dip6_lo_attr);
      at_tout_dip6_lo = get_attr_with_offset<uint64_t>(off, p);
    }

    /* checking values now */
    DLOG(INFO) << "pdu type: " << static_cast<uint16_t>(at_pdu_type)
               << ", tunnel qfi: " << at_qfi
               << ", tunnel out sip: " << at_tout_sip
               << ", tunnel out dip: " << at_tout_dip
               << ", tunnel out dip6: " << std::hex << at_tout_dip6_hi << ":"
               << at_tout_dip6_lo << std::dec
               << ", tunnel out teid: " << at_tout_teid
               << ", tunnel out udp port: " << at_tout_uport;

    uint16_t pkt_len = p->total_len() - sizeof(Ethernet);
    Ethernet *eth = p->head_data<Ethernet *>();

    /* the DSCP and ECN bits of the packet carried */
    uint8_t type_of_service = inner_traffic_class(p);

    /* the outer IP header's size, and the whole header prepended */
    const size_t ip_size = outer6 ? sizeof(Ipv6) : sizeof(Ipv4);
    const int this_encap_size =
        outer6 ? encap_size + static_cast<int>(sizeof(Ipv6) - sizeof(Ipv4))
               : encap_size;

    /* pre-allocate space for encaped header(s) */
    char *new_p = static_cast<char *>(p->prepend(this_encap_size));
    if (new_p == NULL) {
      /* failed to prepend header space for encaped packet */
      EmitPacket(ctx, p, DEFAULT_GATE);
      DLOG(INFO) << "prepend() failed!";
      continue;
    }

    /* setting Ethernet header */
    memcpy(new_p, eth, sizeof(Ethernet));
    Ethernet *new_eth = reinterpret_cast<Ethernet *>(new_p);

    /* get pointers to header offsets */
    uint8_t *ip = reinterpret_cast<uint8_t *>(new_p + sizeof(Ethernet));
    Udp *udph = reinterpret_cast<Udp *>(ip + ip_size);
    Gtpv1 *gtph = reinterpret_cast<Gtpv1 *>(udph + 1);
    Gtpv1PDUSessExt *psch = reinterpret_cast<Gtpv1PDUSessExt *>(
        reinterpret_cast<uint8_t *>(udph) +
        (offsetof(PacketTemplate, psch) - offsetof(PacketTemplate, udph)));

    /* copying template content */
    if (outer6) {
      bess::utils::Copy(ip, &outer_ip6_template, this_encap_size);
    } else {
      bess::utils::Copy(ip, &outer_ip_template, this_encap_size);
    }

    /* setting gtp psc extension header*/
    if (add_psc) {
      gtph->ex = 1;
      psch->qfi = at_qfi;
      psch->pdu_type = at_pdu_type;
    }

    /* calculate lengths */
    uint16_t gtplen =
        pkt_len + this_encap_size - sizeof(Gtpv1) - sizeof(Udp) - ip_size;
    uint16_t udplen = gtplen + sizeof(Gtpv1) + sizeof(Udp);

    /* setting gtpu header */
    gtph->length = (be16_t)(gtplen);
    gtph->teid = (be32_t)(at_tout_teid);

    /* setting outer UDP header */
    udph->length = (be16_t)(udplen);
    udph->src_port = udph->dst_port = (be16_t)(at_tout_uport);

    /* setting outer IP header */
    if (outer6) {
      if (!FillIpv6(reinterpret_cast<Ipv6 *>(ip), at_pdu_type, at_tout_dip6_hi,
                    at_tout_dip6_lo, type_of_service, udplen)) {
        /* no IPv6 address to send from: undo, and drop it as a failure */
        p->adj(this_encap_size);
        EmitPacket(ctx, p, DEFAULT_GATE);
        continue;
      }
      new_eth->ether_type = be16_t(Ethernet::kIpv6);
    } else {
      Ipv4 *iph = reinterpret_cast<Ipv4 *>(ip);
      iph->length = (be16_t)(udplen + sizeof(Ipv4));
      iph->id = (be16_t)(ip_id++);
      iph->src = (be32_t)(at_tout_sip);
      iph->dst = (be32_t)(at_tout_dip);
      iph->type_of_service = type_of_service;
      new_eth->ether_type = be16_t(Ethernet::kIpv4);
    }

    EmitPacket(ctx, p, FORWARD_GATE);
  }
}
/*----------------------------------------------------------------------------------*/
static CommandResponse parse_ipv6_source(const std::string &str,
                                         const char *what, uint8_t addr[16],
                                         bool *set) {
  *set = false;
  if (str.empty()) {
    return CommandSuccess();
  }
  if (!bess::utils::ParseIpv6Address(str, addr)) {
    return CommandFailure(EINVAL, "invalid %s: %s", what, str.c_str());
  }
  *set = true;
  return CommandSuccess();
}
/*----------------------------------------------------------------------------------*/
CommandResponse GtpuEncap::Init(const bess::pb::GtpuEncapArg &arg) {
  add_psc = arg.add_psc();
  if (add_psc)
    encap_size = sizeof(outer_ip_template);
  else
    encap_size = sizeof(outer_ip_template) - sizeof(Gtpv1SeqPDUExt) -
                 sizeof(Gtpv1SeqPDUExt);

  CommandResponse err = parse_ipv6_source(arg.access_ip6(), "access_ip6",
                                          access_ip6_.addr, &access_ip6_.set);
  if (err.has_error()) {
    return err;
  }
  err = parse_ipv6_source(arg.core_ip6(), "core_ip6", core_ip6_.addr,
                          &core_ip6_.set);
  if (err.has_error()) {
    return err;
  }

  using AccessMode = bess::metadata::Attribute::AccessMode;
  pdu_type_attr = AddMetadataAttr("action", sizeof(uint8_t), AccessMode::kRead);
  DLOG(INFO) << "tout_sip_attr: " << tout_sip_attr;
  tout_sip_attr = AddMetadataAttr("tunnel_out_src_ip4addr", sizeof(uint32_t),
                                  AccessMode::kRead);
  DLOG(INFO) << "tout_sip_attr: " << tout_sip_attr;
  tout_dip_attr = AddMetadataAttr("tunnel_out_dst_ip4addr", sizeof(uint32_t),
                                  AccessMode::kRead);
  DLOG(INFO) << "tout_dip_attr: " << tout_dip_attr;
  tout_teid =
      AddMetadataAttr("tunnel_out_teid", sizeof(uint32_t), AccessMode::kRead);
  DLOG(INFO) << "tout_teid: " << tout_teid;
  tout_uport = AddMetadataAttr("tunnel_out_udp_port", sizeof(uint16_t),
                               AccessMode::kRead);
  DLOG(INFO) << "tout_uport: " << tout_uport;
  qfi_attr = AddMetadataAttr("qfi", sizeof(uint8_t), AccessMode::kRead);
  DLOG(INFO) << "qfi_attr: " << qfi_attr;

  /* The IPv6 peer is read only when this UPF has an IPv6 address to send
   * from, so an IPv4-only pipeline needs no module that writes it. */
  if (access_ip6_.set || core_ip6_.set) {
    tout_dip6_hi_attr = AddMetadataAttr("tunnel_out_dst_ip6_hi",
                                        sizeof(uint64_t), AccessMode::kRead);
    tout_dip6_lo_attr = AddMetadataAttr("tunnel_out_dst_ip6_lo",
                                        sizeof(uint64_t), AccessMode::kRead);
  }

  return CommandSuccess();
}
/*----------------------------------------------------------------------------------*/
ADD_MODULE(GtpuEncap, "gtpu_encap", "first version of gtpu encap module")
