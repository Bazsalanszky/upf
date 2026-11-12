/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2019 Intel Corporation
 */
#ifndef BESS_MODULES_GTPUPARSER_H_
#define BESS_MODULES_GTPUPARSER_H_
/*----------------------------------------------------------------------------------*/
#include <cstring>

#include "../module.h"
#include "gtpu_drop_log.h"
/* for the IPv4 and IPv6 headers */
#include "utils/ip.h"
/* for endian types */
#include "utils/endian.h"
using bess::utils::be16_t;
using bess::utils::be32_t;
/*----------------------------------------------------------------------------------*/
/* The value pdrLookup's tunnel_ipv4_dst holds for a G-PDU in an IPv6 outer
 * header: the low-order 32 bits of its destination address, in the byte
 * order an IPv4 destination has there. See GtpuParser::ParseIpv6(). */
static inline be32_t Ipv6TunnelKey(const bess::utils::Ipv6 &ip6h) {
  be32_t key;
  memcpy(&key, ip6h.dst + 12, sizeof(key));
  return key;
}
/*----------------------------------------------------------------------------------*/
/**
 * EPC Metadata
 */
typedef struct EpcMetadata {
  be16_t l4_sport;
  be16_t l4_dport;
  be16_t inner_l4_sport;
  be16_t inner_l4_dport;
  be32_t teid;
} EpcMetadata;
/*----------------------------------------------------------------------------------*/
class GtpuParser final : public Module {
 public:
  GtpuParser() { max_allowed_workers_ = Worker::kMaxWorkers; }

  /* Gates: (0) Default, (1) Forward an IPv4 packet (pdrLookup), (2) Forward an
   * IPv6 packet (pdrLookup6): an IPv6 UE packet, in a G-PDU or on its own. */
  static const gate_idx_t kNumOGates = 3;
  CommandResponse Init(const bess::pb::EmptyArg &);
  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

 private:
  gate_idx_t Parse(bess::Packet *p, const char **malformed);
  void set_unmatchable_attrs(bess::Packet *p);
  gate_idx_t ParseIpv6(bess::Packet *p, const char **malformed);
  gate_idx_t ParseGtpu(bess::Packet *p, be32_t tunnel_dst, size_t gtp_off,
                       const char **malformed);
  gate_idx_t ClassifyIpv6(bess::Packet *p, size_t ip_off, be32_t teid,
                          const char **malformed);
  GtpuDropLog drop_log_;
  /* set attributes */
  void set_gtp_parsing_attrs(be32_t *sip, be32_t *dip, be16_t *sp, be16_t *dp,
                             be32_t *teid, be32_t *tipd, uint8_t *protoid,
                             bess::Packet *p);
  int src_ip_id = -1;
  int dst_ip_id = -1;
  int src_port_id = -1;
  int dst_port_id = -1;
  int teid_id = -1;
  int tunnel_ip4_dst_id = -1;
  int proto_id = -1;
  /* The IPv6 attributes pdrLookup6 matches on (see ClassifyIpv6()). */
  int src_ip6_hi_id = -1;
  int src_ip6_lo_id = -1;
  int dst_ip6_hi_id = -1;
  int dst_ip6_lo_id = -1;
  int l4_ports_id = -1;
};
/*----------------------------------------------------------------------------------*/
#endif  // BESS_MODULES_GTPUPARSER_H_
