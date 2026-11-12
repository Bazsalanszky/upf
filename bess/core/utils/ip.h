// Copyright (c) 2016-2017, Nefeli Networks, Inc.
// All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// * Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// * Neither the names of the copyright holders nor the names of their
// contributors may be used to endorse or promote products derived from this
// software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

#ifndef BESS_UTILS_IP_H_
#define BESS_UTILS_IP_H_

#include <string>

#include "endian.h"

namespace bess {
namespace utils {

// return false if string -> be32_t conversion failed (*addr is unmodified)
bool ParseIpv4Address(const std::string &str, be32_t *addr);

// be32 -> string
std::string ToIpv4Address(be32_t addr);

// An IPv4 header definition loosely based on the BSD version.
struct [[gnu::packed]] Ipv4 {
  enum Flag : uint16_t {
    kMF = 1 << 13,  // More fragments
    kDF = 1 << 14,  // Do not fragment
  };

  enum Proto : uint8_t {
    kIcmp = 1,
    kIgmp = 2,
    kIpIp = 4,  // IPv4-in-IPv4
    kTcp = 6,
    kUdp = 17,
    kIpv6 = 41,  // IPv6-in-IPv4
    kGre = 47,
    kEsp = 50,  // IPsec ESP (Encapsulating Security Payload)
    kAh = 51,   // IPsec AH (Authentication Header)
    kSctp = 132,
    kUdpLite = 136,
    kMpls = 137,  // MPLS-in-IPv4
    kRaw = 255,
  };

#if __BYTE_ORDER == __LITTLE_ENDIAN
  uint8_t header_length : 4;  // Header length.
  uint8_t version : 4;        // Version.
#elif __BYTE_ORDER == __BIG_ENDIAN
  uint8_t version : 4;        // Version.
  uint8_t header_length : 4;  // Header length.
#else
#error __BYTE_ORDER must be defined.
#endif
  uint8_t type_of_service;  // Type of service.
  be16_t length;            // Length.
  be16_t id;                // ID.
  be16_t fragment_offset;   // Fragment offset.
  uint8_t ttl;              // Time to live.
  uint8_t protocol;         // Protocol.
  uint16_t checksum;        // Checksum.
  be32_t src;               // Source address.
  be32_t dst;               // Destination address.
};

static_assert(std::is_pod<Ipv4>::value, "not a POD type");
static_assert(sizeof(Ipv4) == 20, "struct Ipv4 is incorrect");

// The fixed IPv6 header (RFC 8200 section 3). Extension headers, if any,
// follow it; next_header then names the first of them.
struct [[gnu::packed]] Ipv6 {
  // Version (4 bits), Traffic Class (8 bits) and Flow Label (20 bits).
  be32_t vtc_flow;
  be16_t payload_length;  // Length of everything after this header.
  uint8_t next_header;    // Same values as Ipv4::Proto.
  uint8_t hop_limit;
  uint8_t src[16];
  uint8_t dst[16];

  uint8_t version() const { return vtc_flow.value() >> 28; }
  uint8_t traffic_class() const { return (vtc_flow.value() >> 20) & 0xFF; }
  // Version 6, the given Traffic Class and Flow Label 0.
  void set_version_traffic_class(uint8_t tc) {
    vtc_flow = be32_t((6u << 28) | (static_cast<uint32_t>(tc) << 20));
  }
};

static_assert(std::is_pod<Ipv6>::value, "not a POD type");
static_assert(sizeof(Ipv6) == 40, "struct Ipv6 is incorrect");

// return false if string -> 16 network-order bytes conversion failed
// (*addr is unmodified)
bool ParseIpv6Address(const std::string &str, uint8_t addr[16]);

// 16 network-order bytes -> string
std::string ToIpv6Address(const uint8_t addr[16]);

struct Ipv4Prefix {
  // Implicit default constructor is not allowed
  Ipv4Prefix() = delete;

  // Construct Ipv4Prefix from a string like "192.168.0.1/24"
  explicit Ipv4Prefix(const std::string &prefix);

  // Returns true if ip is within the range of Ipv4Prefix
  bool Match(const be32_t &ip) const { return (addr & mask) == (ip & mask); }

  // Returns the prefix length
  uint32_t prefix_length() const {
    uint32_t mask_val = mask.value();
    if (mask_val == 0) {
      return 0;
    } else {
      return 32 - __builtin_ctz(mask_val);
    }
  }

  be32_t addr;
  be32_t mask;
};

}  // namespace utils
}  // namespace bess

#endif  // BESS_UTILS_IP_ADDRESS_H_
