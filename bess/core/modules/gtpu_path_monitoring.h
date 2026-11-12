/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2022 Intel Corporation
 */

#ifndef BESS_MODULES_GTPU_PATH_MONITORING_H_
#define BESS_MODULES_GTPU_PATH_MONITORING_H_

#include "../module.h"
#include "../pb/module_msg.pb.h"

#include <array>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

// A gNB's address: an IPv6 one, or an IPv4 one in its IPv4-mapped form
// (::ffff:a.b.c.d, RFC 4291 2.5.5.2), so that one table holds both.
struct GnbAddr {
  std::array<uint8_t, 16> bytes{};

  static GnbAddr FromIpv4(uint32_t host_order);
  static GnbAddr FromIpv6(const uint8_t *addr);
  bool is_ipv4() const;
  uint32_t ipv4() const;  // host order; meaningful when is_ipv4()
  std::string ToString() const;

  bool operator==(const GnbAddr &o) const { return bytes == o.bytes; }
};

struct GnbAddrHash {
  size_t operator()(const GnbAddr &a) const {
    uint64_t hi, lo;
    memcpy(&hi, a.bytes.data(), sizeof(hi));
    memcpy(&lo, a.bytes.data() + 8, sizeof(lo));
    return std::hash<uint64_t>()(hi ^ (lo * 0x9e3779b97f4a7c15ULL));
  }
};

// Updates sequence number by incrementing by 1
class GtpuPathMonitoring final : public Module {
 public:
  static const Commands cmds;

  GtpuPathMonitoring() : Module() { max_allowed_workers_ = 1; }

  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

  CommandResponse Init(const bess::pb::EmptyArg &arg);

  CommandResponse CommandAdd(
      const bess::pb::GtpuPathMonitoringCommandAddDeleteArg &arg);

  CommandResponse CommandDelete(
      const bess::pb::GtpuPathMonitoringCommandAddDeleteArg &arg);

  CommandResponse CommandClear(
      const bess::pb::GtpuPathMonitoringCommandClearArg &arg);

  CommandResponse CommandReadStats(
      const bess::pb::GtpuPathMonitoringCommandReadArg &arg);

 private:
  struct Values {
    uint32_t m_count{0};  // Count number of samples
    uint64_t m_min{std::numeric_limits<uint64_t>::max()};  // Minimum latency
    uint64_t m_mean{0};                                    // Average latency
    uint64_t m_max{0};                                     // Maximum latency
  };

  void Clear();
  // The gNB a command names, or false with *err set
  static bool GnbOf(const bess::pb::GtpuPathMonitoringCommandAddDeleteArg &arg,
                    GnbAddr *gnb, CommandResponse *err);
  void SendRequests(Context *ctx, bess::Packet *pkt, bool ipv6);
  void TakeResponse(const GnbAddr &src, uint16_t seq_number);

  // The commands are THREAD_SAFE, so they run on the control thread while a
  // worker runs ProcessBatch, and both read and change the tables below. Only
  // GTP-U echo messages reach this module, so a lock per batch is cheap.
  std::mutex mutex_;
  std::unordered_map<GnbAddr, std::unordered_map<uint16_t, uint64_t>,
                     GnbAddrHash>
      m_storedData;  // Store timestamp {dst_IP, {sequence_number, latency}}
  std::unordered_map<GnbAddr, Values, GnbAddrHash>
      m_latency;  // Store latency per dstIp
  std::unordered_map<GnbAddr, uint32_t, GnbAddrHash>
      m_dstIp;              // GTP Tunnel destination {gNB IP, counter}
  uint16_t m_seqNumber{0};  // gtpu echo sequence number
};

#endif  // BESS_MODULES_GTPU_PATH_MONITORING_H_
