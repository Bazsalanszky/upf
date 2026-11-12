/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2019 Intel Corporation
 */
#ifndef BESS_MODULES_GTPUENCAP_H_
#define BESS_MODULES_GTPUENCAP_H_
/*----------------------------------------------------------------------------------*/
#include "../module.h"
#include "../pb/module_msg.pb.h"
#include "../utils/ip.h"
#include <atomic>
#include <rte_hash.h>
/*----------------------------------------------------------------------------------*/
class GtpuEncap final : public Module {
 public:
  GtpuEncap() { max_allowed_workers_ = Worker::kMaxWorkers; }

  /* Output gates: (0) Default, (1) Forward */
  static const gate_idx_t kNumOGates = 2;
  /* Input gates: (0) tunnel to an IPv4 peer, (1) tunnel to an IPv6 peer */
  static const gate_idx_t kNumIGates = 2;
  static const gate_idx_t kIpv6Gate = 1;

  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;
  CommandResponse Init(const bess::pb::GtpuEncapArg &arg);

 private:
  bool add_psc;
  int encap_size;
  int pdu_type_attr = -1;
  int qfi_attr = -1;
  int tout_sip_attr = -1;
  int tout_dip_attr = -1;
  int tout_teid = -1;
  int tout_uport = -1;
  /* The IPv6 peer, when the FAR has one (see Init()) */
  int tout_dip6_hi_attr = -1;
  int tout_dip6_lo_attr = -1;
  /* The UPF's own IPv6 addresses an IPv6 outer header is sent from */
  struct Ipv6Source {
    bool set = false;
    uint8_t addr[16] = {};
  };
  Ipv6Source access_ip6_;
  Ipv6Source core_ip6_;
  bool FillIpv6(bess::utils::Ipv6 *ip6h, uint8_t action, uint64_t dst_hi,
                uint64_t dst_lo, uint8_t traffic_class,
                uint16_t payload_len) const;
  /* ID of the next outer IPv4 header; see ProcessBatch() */
  std::atomic<uint16_t> next_ip_id{0};
};
/*----------------------------------------------------------------------------------*/
#endif  // BESS_MODULES_GTPUENCAP_H_
