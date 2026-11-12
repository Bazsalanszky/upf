// SPDX-FileCopyrightText: 2026 Balázs Toldi
// SPDX-License-Identifier: Apache-2.0

#include "ip6_lookup.h"

#include <rte_errno.h>

#include <cstring>

#include "../utils/ether.h"
#include "../utils/format.h"
#include "../utils/ip.h"

static inline bool is_valid_gate(gate_idx_t gate) {
  return gate < MAX_GATES || gate == DROP_GATE;
}

const Commands IP6Lookup::cmds = {
    {"add", "IP6LookupCommandAddArg", MODULE_CMD_FUNC(&IP6Lookup::CommandAdd),
     Command::THREAD_UNSAFE},
    {"delete", "IP6LookupCommandDeleteArg",
     MODULE_CMD_FUNC(&IP6Lookup::CommandDelete), Command::THREAD_UNSAFE},
    {"clear", "EmptyArg", MODULE_CMD_FUNC(&IP6Lookup::CommandClear),
     Command::THREAD_UNSAFE}};

CommandResponse IP6Lookup::Init(const bess::pb::IP6LookupArg &arg) {
  struct rte_lpm6_config conf = {};
  conf.max_rules = arg.max_rules() ? arg.max_rules() : 1024;
  conf.number_tbl8s = arg.max_tbl8s() ? arg.max_tbl8s() : 1024;
  conf.flags = 0;

  lpm_ =
      rte_lpm6_create(name().c_str(), /* socket_id = */ rte_socket_id(), &conf);
  if (!lpm_) {
    return CommandFailure(rte_errno, "DPDK error: %s", rte_strerror(rte_errno));
  }
  return CommandSuccess();
}

void IP6Lookup::DeInit() {
  if (lpm_) {
    rte_lpm6_free(lpm_);
    lpm_ = nullptr;
  }
}

void IP6Lookup::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  using bess::utils::be16_t;
  using bess::utils::Ethernet;
  using bess::utils::Ipv6;

  const gate_idx_t default_gate = default_gate_;
  const int cnt = batch->cnt();

  for (int i = 0; i < cnt; i++) {
    bess::Packet *pkt = batch->pkts()[i];
    if (static_cast<size_t>(pkt->head_len()) <
        sizeof(Ethernet) + sizeof(Ipv6)) {
      EmitPacket(ctx, pkt, default_gate);
      continue;
    }
    const Ethernet *eth = pkt->head_data<const Ethernet *>();
    if (eth->ether_type != be16_t(Ethernet::kIpv6)) {
      EmitPacket(ctx, pkt, default_gate);
      continue;
    }
    const Ipv6 *ip6h = reinterpret_cast<const Ipv6 *>(eth + 1);
    struct rte_ipv6_addr dst;
    memcpy(&dst, ip6h->dst, sizeof(dst));
    uint32_t next_hop;
    if (rte_lpm6_lookup(lpm_, &dst, &next_hop) == 0) {
      EmitPacket(ctx, pkt, static_cast<gate_idx_t>(next_hop));
    } else {
      EmitPacket(ctx, pkt, default_gate);
    }
  }
}

CommandResponse IP6Lookup::ParsePrefix(const std::string &prefix,
                                       uint64_t prefix_len,
                                       struct rte_ipv6_addr *addr) {
  static_assert(sizeof(*addr) == 16, "rte_ipv6_addr is not 16 bytes");
  uint8_t bytes[16];
  if (prefix.empty()) {
    return CommandFailure(EINVAL, "prefix is missing");
  }
  if (!bess::utils::ParseIpv6Address(prefix, bytes)) {
    return CommandFailure(EINVAL, "Invalid IPv6 prefix: %s", prefix.c_str());
  }
  if (prefix_len > 128) {
    return CommandFailure(EINVAL, "Invalid prefix length: %" PRIu64,
                          prefix_len);
  }
  // No bits set past the prefix length, as IPLookup requires.
  for (unsigned bit = prefix_len; bit < 128; bit++) {
    if (bytes[bit / 8] & (0x80 >> (bit % 8))) {
      return CommandFailure(EINVAL, "Invalid IPv6 prefix %s/%" PRIu64,
                            prefix.c_str(), prefix_len);
    }
  }
  memcpy(addr, bytes, sizeof(bytes));
  return CommandSuccess();
}

CommandResponse IP6Lookup::CommandAdd(
    const bess::pb::IP6LookupCommandAddArg &arg) {
  const gate_idx_t gate = arg.gate();
  struct rte_ipv6_addr addr;
  CommandResponse err = ParsePrefix(arg.prefix(), arg.prefix_len(), &addr);
  if (err.has_error()) {
    return err;
  }
  if (!is_valid_gate(gate)) {
    return CommandFailure(EINVAL, "Invalid gate: %hu", gate);
  }

  if (arg.prefix_len() == 0) {
    default_gate_ = gate;
    return CommandSuccess();
  }
  int ret =
      rte_lpm6_add(lpm_, &addr, static_cast<uint8_t>(arg.prefix_len()), gate);
  if (ret) {
    return CommandFailure(-ret, "rte_lpm6_add() failed");
  }
  return CommandSuccess();
}

CommandResponse IP6Lookup::CommandDelete(
    const bess::pb::IP6LookupCommandDeleteArg &arg) {
  struct rte_ipv6_addr addr;
  CommandResponse err = ParsePrefix(arg.prefix(), arg.prefix_len(), &addr);
  if (err.has_error()) {
    return err;
  }

  if (arg.prefix_len() == 0) {
    default_gate_ = DROP_GATE;
    return CommandSuccess();
  }
  int ret =
      rte_lpm6_delete(lpm_, &addr, static_cast<uint8_t>(arg.prefix_len()));
  if (ret) {
    return CommandFailure(-ret, "rte_lpm6_delete() failed");
  }
  return CommandSuccess();
}

CommandResponse IP6Lookup::CommandClear(const bess::pb::EmptyArg &) {
  rte_lpm6_delete_all(lpm_);
  default_gate_ = DROP_GATE;
  return CommandSuccess();
}

ADD_MODULE(IP6Lookup, "ip6_lookup",
           "performs Longest Prefix Match on IPv6 packets")
