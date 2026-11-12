// SPDX-FileCopyrightText: 2026 Balázs Toldi
// SPDX-License-Identifier: Apache-2.0

#ifndef BESS_MODULES_IP6LOOKUP_H_
#define BESS_MODULES_IP6LOOKUP_H_

#include <rte_config.h>
#include <rte_lpm6.h>

#include "../module.h"
#include "../pb/module_msg.pb.h"

// IP6Lookup is IPLookup for IPv6: a longest prefix match on the destination
// address of an IPv6 packet, to an output gate. A packet that is not IPv6, or
// matches no route, goes to the default gate (the /0 route, or a drop).
class IP6Lookup final : public Module {
 public:
  static const gate_idx_t kNumOGates = MAX_GATES;

  static const Commands cmds;

  IP6Lookup() : Module(), lpm_(), default_gate_(DROP_GATE) {
    max_allowed_workers_ = Worker::kMaxWorkers;
  }

  CommandResponse Init(const bess::pb::IP6LookupArg &arg);

  void DeInit() override;

  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

  CommandResponse CommandAdd(const bess::pb::IP6LookupCommandAddArg &arg);
  CommandResponse CommandDelete(const bess::pb::IP6LookupCommandDeleteArg &arg);
  CommandResponse CommandClear(const bess::pb::EmptyArg &arg);

 private:
  // Parses `prefix`/`prefix_len` into `addr`; an error response if the prefix
  // is not an IPv6 network address of that length.
  CommandResponse ParsePrefix(const std::string &prefix, uint64_t prefix_len,
                              struct rte_ipv6_addr *addr);

  struct rte_lpm6 *lpm_;
  gate_idx_t default_gate_;
};

#endif  // BESS_MODULES_IP6LOOKUP_H_
