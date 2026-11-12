/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2022 Intel Corporation
 */

#include "gtpu_path_monitoring.h"

#include "utils/endian.h" /* for be16_t */
#include "utils/endian.h" /* for be32_t */
#include "utils/ether.h"  /* for ethernet header */
#include "utils/gtp.h"    /* for gtp header */
#include "utils/ip.h"     /* for ToIpv4Address() */
#include "utils/udp.h"    /* for udp header */

#include <unordered_map>

using bess::utils::be16_t;
using bess::utils::be32_t;
using bess::utils::Ethernet;
using bess::utils::Gtpv1;
using bess::utils::Gtpv1SeqPDUExt;
using bess::utils::Ipv4;
using bess::utils::Ipv6;
using bess::utils::ToIpv4Address;
using bess::utils::Udp;

const Commands GtpuPathMonitoring::cmds = {
    {"add", "GtpuPathMonitoringCommandAddDeleteArg",
     MODULE_CMD_FUNC(&GtpuPathMonitoring::CommandAdd), Command::THREAD_SAFE},
    {"delete", "GtpuPathMonitoringCommandAddDeleteArg",
     MODULE_CMD_FUNC(&GtpuPathMonitoring::CommandDelete), Command::THREAD_SAFE},
    {"clear", "GtpuPathMonitoringCommandClearArg",
     MODULE_CMD_FUNC(&GtpuPathMonitoring::CommandClear), Command::THREAD_SAFE},
    {"read", "GtpuPathMonitoringCommandReadArg",
     MODULE_CMD_FUNC(&GtpuPathMonitoring::CommandReadStats),
     Command::THREAD_SAFE},
};

GnbAddr GnbAddr::FromIpv4(uint32_t host_order) {
  GnbAddr a;
  a.bytes[10] = 0xff;
  a.bytes[11] = 0xff;
  const be32_t be(host_order);
  memcpy(a.bytes.data() + 12, &be, sizeof(be));
  return a;
}

GnbAddr GnbAddr::FromIpv6(const uint8_t *addr) {
  GnbAddr a;
  memcpy(a.bytes.data(), addr, a.bytes.size());
  return a;
}

bool GnbAddr::is_ipv4() const {
  static const uint8_t kMapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
  return memcmp(bytes.data(), kMapped, sizeof(kMapped)) == 0;
}

uint32_t GnbAddr::ipv4() const {
  be32_t be;
  memcpy(&be, bytes.data() + 12, sizeof(be));
  return be.value();
}

std::string GnbAddr::ToString() const {
  if (is_ipv4()) {
    return ToIpv4Address(be32_t(ipv4()));
  }
  return bess::utils::ToIpv6Address(bytes.data());
}

/* Sends a copy of the request `pkt` to every gNB of its family, from the
 * template's source, and drops `pkt` itself. */
void GtpuPathMonitoring::SendRequests(Context *ctx, bess::Packet *pkt,
                                      bool ipv6) {
  for (auto it : m_dstIp) {
    if (it.first.is_ipv4() == ipv6) {
      continue;
    }
    bess::Packet *newPkt = bess::Packet::copy(pkt);
    if (!newPkt) {
      // The pool is empty: this gNB misses one request, and no timestamp
      // is kept for a request that was never sent.
      continue;
    }
    m_storedData[it.first][m_seqNumber] = tsc_to_ns(rdtsc());
    unsigned char *l3 = newPkt->head_data<unsigned char *>() + sizeof(Ethernet);
    if (ipv6) {
      memcpy(reinterpret_cast<Ipv6 *>(l3)->dst, it.first.bytes.data(),
             it.first.bytes.size());
    } else {
      reinterpret_cast<Ipv4 *>(l3)->dst = be32_t(it.first.ipv4());
    }
    EmitPacket(ctx, newPkt);
  }
  // Only the copies leave; the request they were made from is done with.
  DropPacket(ctx, pkt);
  m_seqNumber++;
}

void GtpuPathMonitoring::TakeResponse(const GnbAddr &src, uint16_t seqNumber) {
  auto it = m_storedData.find(src);
  if (it != m_storedData.end()) {
    auto itInn = it->second.find(seqNumber);
    if (itInn != it->second.end()) {
      Values values;
      uint64_t lat = (tsc_to_ns(rdtsc()) - itInn->second) / 2;
      auto itDst = m_latency.find(src);
      if (itDst != m_latency.end()) {
        Values valuesIn = itDst->second;
        values.m_count = valuesIn.m_count + 1;
        values.m_min = (lat < valuesIn.m_min) ? lat : valuesIn.m_min;
        if (lat > valuesIn.m_mean) {
          values.m_mean =
              valuesIn.m_mean + (lat - valuesIn.m_mean) / values.m_count;
        } else {
          values.m_mean =
              valuesIn.m_mean - (valuesIn.m_mean - lat) / values.m_count;
        }
        values.m_max = (lat > valuesIn.m_max) ? lat : valuesIn.m_max;
      } else {
        values.m_count = 1;
        values.m_min = lat;
        values.m_mean = lat;
        values.m_max = lat;
      }

      m_latency[src] = values;
      it->second.erase(itInn);

    } else {
      LOG(ERROR) << "Sequence number " << seqNumber << " not found in map";
    }
  } else {
    LOG(ERROR) << "gNB IP address not found in map";
  }

  LOG(INFO) << "type:" << +GTPU_ECHO_RESPONSE << ", srcIp:" << src.ToString()
            << ", seqNumber:" << seqNumber << ", latency:["
            << m_latency[src].m_min << ", " << m_latency[src].m_mean << ", "
            << m_latency[src].m_max << "]";
}

void GtpuPathMonitoring::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  const std::lock_guard<std::mutex> lock(mutex_);
  int cnt = batch->cnt();

  for (int i = 0; i < cnt; i++) {
    // we should drop-or-emit each packet
    bess::Packet *pkt = batch->pkts()[i];

    // If gNB IP vector is empty, drop packet. It is like disabling this feature
    if (m_dstIp.empty()) {
      DLOG(INFO) << "gNBs IP vector is empty, dropping packet";
      DropPacket(ctx, pkt);
      continue;
    }

    // An echo message comes in an IPv4 header, or an IPv6 one with UDP as
    // its next header (the access BPF filters let no other through).
    Ethernet *eth = pkt->head_data<Ethernet *>();
    const bool ipv6 = eth->ether_type == be16_t(Ethernet::Type::kIpv6);
    unsigned char *l3 = (unsigned char *)eth + sizeof(Ethernet);
    Udp *udp;
    if (ipv6) {
      udp = (Udp *)(l3 + sizeof(Ipv6));
    } else {
      udp = (Udp *)(l3 + (((Ipv4 *)l3)->header_length << 2));
    }
    Gtpv1 *gtph = (Gtpv1 *)((unsigned char *)udp + sizeof(Udp));
    Gtpv1SeqPDUExt *speh =
        (Gtpv1SeqPDUExt *)((unsigned char *)gtph + sizeof(Gtpv1));

    uint8_t gtpuType = gtph->type;

    if (gtpuType == GTPU_ECHO_REQUEST) {
      speh->seqnum = static_cast<be16_t>(m_seqNumber);
      SendRequests(ctx, pkt, ipv6);
    } else if (gtpuType == GTPU_ECHO_RESPONSE) {
      const GnbAddr src = ipv6 ? GnbAddr::FromIpv6(((Ipv6 *)l3)->src)
                               : GnbAddr::FromIpv4(((Ipv4 *)l3)->src.value());
      TakeResponse(src, speh->seqnum.value());
      DropPacket(ctx, pkt);
    } else {
      LOG(ERROR) << "Unexpected GTP Type (" << +gtpuType << ")";
      DropPacket(ctx, pkt);
    }
  }
}

CommandResponse GtpuPathMonitoring::CommandReadStats(
    const bess::pb::GtpuPathMonitoringCommandReadArg &arg) {
  const std::lock_guard<std::mutex> lock(mutex_);
  bess::pb::GtpuPathMonitoringCommandReadResponse resp;
  for (auto &element : m_latency) {
    bess::pb::GtpuPathMonitoringCommandReadResponse::Statistic stat;
    if (element.first.is_ipv4()) {
      stat.set_gnb_ip(element.first.ipv4());
    } else {
      stat.set_gnb_ip6(element.first.bytes.data(), element.first.bytes.size());
    }
    stat.set_count(element.second.m_count);
    stat.set_latency_min(element.second.m_min);
    stat.set_latency_mean(element.second.m_mean);
    stat.set_latency_max(element.second.m_max);
    *resp.add_statistics() = stat;

    if (arg.clear()) {
      element.second.m_count = 0;
      element.second.m_min = std::numeric_limits<uint64_t>::max();
      element.second.m_mean = 0;
      element.second.m_max = 0;
    }
  }

  return CommandSuccess(resp);
}

CommandResponse GtpuPathMonitoring::Init(const bess::pb::EmptyArg &) {
  GtpuPathMonitoring::Clear();

  return CommandSuccess();
}

bool GtpuPathMonitoring::GnbOf(
    const bess::pb::GtpuPathMonitoringCommandAddDeleteArg &arg, GnbAddr *gnb,
    CommandResponse *err) {
  const std::string &ip6 = arg.gnb_ip6();
  if (ip6.empty()) {
    *gnb = GnbAddr::FromIpv4(arg.gnb_ip());
    return true;
  }
  if (ip6.size() != gnb->bytes.size()) {
    *err =
        CommandFailure(EINVAL, "gnb_ip6 must be 16 bytes, not %zu", ip6.size());
    return false;
  }
  *gnb = GnbAddr::FromIpv6(reinterpret_cast<const uint8_t *>(ip6.data()));
  if (gnb->is_ipv4()) {
    // It would be taken for the IPv4 gNB it maps, and sent IPv4 requests.
    *err = CommandFailure(EINVAL, "gnb_ip6 is IPv4-mapped; use gnb_ip");
    return false;
  }
  return true;
}

CommandResponse GtpuPathMonitoring::CommandAdd(
    const bess::pb::GtpuPathMonitoringCommandAddDeleteArg &arg) {
  GnbAddr dst;
  CommandResponse err;
  if (!GnbOf(arg, &dst, &err)) {
    return err;
  }
  const std::lock_guard<std::mutex> lock(mutex_);
  auto it = m_dstIp.find(dst);
  if (it == m_dstIp.end()) {
    m_dstIp.emplace(dst, 1);
  } else {
    it->second++;
  }

  return CommandSuccess();
}

CommandResponse GtpuPathMonitoring::CommandDelete(
    const bess::pb::GtpuPathMonitoringCommandAddDeleteArg &arg) {
  GnbAddr dst;
  CommandResponse err;
  if (!GnbOf(arg, &dst, &err)) {
    return err;
  }
  const std::lock_guard<std::mutex> lock(mutex_);
  auto it = m_dstIp.find(dst);
  if (it == m_dstIp.end()) {
    LOG(ERROR) << "Address " << dst.ToString() << " is not known";
  } else {
    if (it->second == 1) {
      m_dstIp.erase(dst);
    } else {
      it->second--;
    }
  }

  return CommandSuccess();
}

CommandResponse GtpuPathMonitoring::CommandClear(
    const bess::pb::GtpuPathMonitoringCommandClearArg &) {
  GtpuPathMonitoring::Clear();

  return CommandSuccess();
}

void GtpuPathMonitoring::Clear() {
  // The tables are swapped out under the lock and freed once it is released:
  // the timestamps alone can hold 65536 entries per gNB, and the worker waits
  // on the lock with all the traffic it carries.
  decltype(m_storedData) storedData;
  decltype(m_latency) latency;
  decltype(m_dstIp) dstIp;
  const std::lock_guard<std::mutex> lock(mutex_);
  m_storedData.swap(storedData);
  m_latency.swap(latency);
  m_dstIp.swap(dstIp);
  m_seqNumber = 0;
}

ADD_MODULE(GtpuPathMonitoring, "gtpu_path_monitoring",
           "Gtpu path monitoring module")
