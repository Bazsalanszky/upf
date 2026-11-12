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

#include "checksum.h"

#include <cstdint>

#include <gtest/gtest.h>
#include <rte_config.h>
#include <rte_ip.h>

#include "random.h"

using namespace bess::utils;

namespace {

Random rd;
const int kTestLoopCount = 1000000;

// Tests generic checksum
TEST(ChecksumTest, GenericChecksum) {
  uint32_t buf[40] = {
      0x45000032, 0x00010000, 0x40060000, 0x0c22384e, 0xac0c3763, 0x45000032,
      0x00010000, 0x40060000, 0x0c22384e, 0xac0c3763, 0x45000032, 0x00010000,
      0x40060000, 0x0c22384e, 0xac0c3763, 0x45000032, 0x00010000, 0x40060000,
      0x0c22384e, 0xac0c3763, 0x45000032, 0x00010000, 0x40060000, 0x0c22384e,
      0xac0c3763, 0x45000032, 0x00010000, 0x40060000, 0x0c22384e, 0xac0c3763,
      0x45000032, 0x00010000, 0x40060000, 0x0c22384e, 0xac0c3763, 0x45000032,
      0x00010000, 0x40060000, 0x0c22384e, 0xac0c3763};

  // choose byte size 159, 160 to enter the all loops in the test functions
  uint16_t cksum_bess = CalculateGenericChecksum(buf, 160);
  uint16_t cksum_dpdk = ~rte_raw_cksum(buf, 160);  // take the complement
  EXPECT_EQ(cksum_dpdk, cksum_bess);

  EXPECT_TRUE(VerifyGenericChecksum(buf, 160, cksum_bess));
  EXPECT_TRUE(VerifyGenericChecksum(buf, 160, cksum_dpdk));

  cksum_bess = CalculateGenericChecksum(buf, 159);
  cksum_dpdk = ~rte_raw_cksum(buf, 159);  // take the complement
  EXPECT_EQ(cksum_dpdk, cksum_bess);

  EXPECT_TRUE(VerifyGenericChecksum(buf, 159, cksum_bess));
  EXPECT_TRUE(VerifyGenericChecksum(buf, 159, cksum_dpdk));

  for (int i = 0; i < kTestLoopCount; i++) {
    for (int j = 0; j < 40; j++) {
      buf[j] = rd.Get();
    }

    cksum_bess = CalculateGenericChecksum(buf, 160);
    cksum_dpdk = ~rte_raw_cksum(buf, 160);  // take the complement
    EXPECT_EQ(cksum_dpdk, cksum_bess);
  }
}

// Tests IP checksum
TEST(ChecksumTest, Ipv4NoOptChecksum) {
  char buf[1514] = {0};  // ipv4 header w/o options

  bess::utils::Ipv4 *ip = reinterpret_cast<bess::utils::Ipv4 *>(buf);

  ip->version = 4;
  ip->header_length = 5;
  ip->type_of_service = 0;
  ip->length = be16_t(20);
  ip->fragment_offset = be16_t(0);
  ip->ttl = 10;
  ip->protocol = 0x06;  // tcp
  ip->src = be32_t(0x12345678);
  ip->dst = be32_t(0x12347890);

  uint16_t cksum_dpdk =
      rte_ipv4_cksum(reinterpret_cast<const rte_ipv4_hdr *>(ip));
  uint16_t cksum_bess = CalculateIpv4NoOptChecksum(*ip);
  EXPECT_EQ(cksum_dpdk, cksum_bess);

  // bess excludes to checksum fields to calculate ip checksum
  ip->checksum = 0x7823;
  cksum_bess = CalculateIpv4NoOptChecksum(*ip);
  EXPECT_EQ(cksum_dpdk, cksum_bess);

  ip->checksum = cksum_bess;
  EXPECT_TRUE(VerifyIpv4NoOptChecksum(*ip));

  ip->checksum = 0x0000;  // for dpdk

  for (int i = 0; i < kTestLoopCount; i++) {
    ip->src = be32_t(rd.Get());
    ip->dst = be32_t(rd.Get());

    cksum_dpdk = rte_ipv4_cksum(reinterpret_cast<const rte_ipv4_hdr *>(ip));
    cksum_bess = CalculateIpv4NoOptChecksum(*ip);

    if (cksum_dpdk == 0xffff) {
      // While the value of IP/TCP checksum field must not be -0 (0xffff),
      // but DPDK often (incorrectly) gives that value. (RFC 768, 1071, 1624)
      EXPECT_EQ(0, cksum_bess);
    } else {
      EXPECT_EQ(cksum_dpdk, cksum_bess);
    }
  }
}

// Tests IP checksum
TEST(ChecksumTest, Ipv4Checksum) {
  char buf[1514] = {0};  // ipv4 header w/o options
  uint32_t *buf32 = reinterpret_cast<uint32_t *>(buf);
  bess::utils::Ipv4 *ip = reinterpret_cast<bess::utils::Ipv4 *>(buf);

  ip->version = 4;
  ip->header_length = 5;
  ip->type_of_service = 0;
  ip->length = be16_t(20);
  ip->fragment_offset = be16_t(0);
  ip->ttl = 10;
  ip->protocol = 0x06;  // tcp
  ip->src = be32_t(0x12345678);
  ip->dst = be32_t(0x12347890);

  // DPDK doesn't support IP checksum with options
  uint16_t cksum_dpdk =
      ~rte_raw_cksum(buf, ip->header_length << 2);  // takes the complement
  uint16_t cksum_bess = CalculateIpv4Checksum(*ip);
  EXPECT_EQ(cksum_dpdk, cksum_bess);

  // bess excludes to checksum fields to calculate ip checksum
  ip->checksum = 0x7823;
  cksum_bess = CalculateIpv4Checksum(*ip);
  EXPECT_EQ(cksum_dpdk, cksum_bess);

  ip->checksum = cksum_bess;
  EXPECT_TRUE(VerifyIpv4Checksum(*ip));

  // Should not crash with incorrect IP headers
  ip->header_length = 4;
  EXPECT_EQ(0, CalculateIpv4Checksum(*ip));
  EXPECT_FALSE(VerifyIpv4Checksum(*ip));

  ip->checksum = 0x0000;  // for dpdk

  for (int i = 0; i < kTestLoopCount; i++) {
    size_t ip_opts_len = rd.Get() % 10;  // Maximum IP option length is 10 << 2
    ip->header_length = 5 + ip_opts_len;
    ip->src = be32_t(rd.Get());
    ip->dst = be32_t(rd.Get());

    for (size_t j = 0; j < ip_opts_len; j++) {
      buf32[5 + j] = rd.Get();
    }

    // DPDK doesn't support IP checksum with options
    cksum_dpdk =
        ~rte_raw_cksum(buf, ip->header_length << 2);  // takes the complement
    cksum_bess = CalculateIpv4Checksum(*ip);

    if (cksum_dpdk == 0xffff) {
      // While the value of IP/TCP checksum field must not be -0 (0xffff),
      // but DPDK often (incorrectly) gives that value. (RFC 768, 1071, 1624)
      EXPECT_EQ(0, cksum_bess);
    } else {
      EXPECT_EQ(cksum_dpdk, cksum_bess);
    }
  }
}

// Tests UDP checksum
TEST(ChecksumTest, UdpChecksum) {
  char buf[1514] = {0};  // ipv4 header + udp header + payload

  bess::utils::Ipv4 *ip = reinterpret_cast<bess::utils::Ipv4 *>(buf);
  bess::utils::Udp *udp = reinterpret_cast<bess::utils::Udp *>(ip + 1);

  ip->version = 4;
  ip->header_length = 5;
  ip->type_of_service = 0;
  ip->length = be16_t(28);
  ip->fragment_offset = be16_t(0);
  ip->ttl = 10;
  ip->protocol = bess::utils::Ipv4::Proto::kUdp;
  ip->src = be32_t(0x12345678);
  ip->dst = be32_t(0x12347890);

  udp->src_port = be16_t(0x0024);
  udp->dst_port = be16_t(0x2097);
  udp->length = be16_t(8);

  uint16_t cksum_dpdk =
      rte_ipv4_udptcp_cksum(reinterpret_cast<const rte_ipv4_hdr *>(ip), udp);
  uint16_t cksum_bess = CalculateIpv4UdpChecksum(*ip, *udp);
  EXPECT_EQ(cksum_dpdk, cksum_bess);

  // bess excludes the checksum field to calculate udp checksum
  udp->checksum = 0x0987;
  cksum_bess = CalculateIpv4UdpChecksum(*ip, *udp);
  EXPECT_EQ(cksum_dpdk, cksum_bess);

  udp->checksum = cksum_bess;
  EXPECT_TRUE(VerifyIpv4UdpChecksum(*ip, *udp));

  // Empty checksum is always considered correct for UDP
  udp->checksum = 0;
  EXPECT_TRUE(VerifyIpv4UdpChecksum(*ip, *udp));

  // Return 0 upon invalid header?
  udp->length = be16_t(7);
  EXPECT_EQ(0, CalculateIpv4UdpChecksum(*ip, *udp));

  udp->length = be16_t(8);

  for (int i = 0; i < kTestLoopCount; i++) {
    ip->src = be32_t(rd.Get());
    ip->dst = be32_t(rd.Get());
    udp->src_port = be16_t(rd.Get() >> 16);
    udp->dst_port = be16_t(rd.Get() >> 16);

    ip->checksum = 0x0000;   // for dpdk
    udp->checksum = 0x0000;  // for dpdk

    cksum_dpdk = rte_ipv4_cksum(reinterpret_cast<const rte_ipv4_hdr *>(ip));
    cksum_bess = CalculateIpv4NoOptChecksum(*ip);

    if (cksum_dpdk == 0xffff) {
      // While the value of IP/TCP checksum field must not be -0 (0xffff),
      // but DPDK often (incorrectly) gives that value. (RFC 768, 1071, 1624)
      EXPECT_EQ(0, cksum_bess);
    } else {
      EXPECT_EQ(cksum_dpdk, cksum_bess);
    }

    ip->checksum = cksum_bess;

    cksum_dpdk =
        rte_ipv4_udptcp_cksum(reinterpret_cast<const rte_ipv4_hdr *>(ip), udp);
    cksum_bess = CalculateIpv4UdpChecksum(*ip, *udp);

    EXPECT_EQ(cksum_dpdk, cksum_bess);

    // The result of UDP checksum must not be zero
    EXPECT_NE(0, cksum_bess);
  }
}

// UDP and TCP over IPv6 against DPDK's rte_ipv6_udptcp_cksum
TEST(ChecksumTest, Ipv6UdpTcpChecksum) {
  alignas(8) char buf[1514] = {0};  // ipv6 header + l4 header + payload

  bess::utils::Ipv6 *ip = reinterpret_cast<bess::utils::Ipv6 *>(buf);
  bess::utils::Udp *udp = reinterpret_cast<bess::utils::Udp *>(ip + 1);
  bess::utils::Tcp *tcp = reinterpret_cast<bess::utils::Tcp *>(ip + 1);
  char *l4 = reinterpret_cast<char *>(ip + 1);

  for (int i = 0; i < 10000; i++) {
    // Odd and even lengths, so the last byte's padding is exercised.
    uint32_t payload = rd.Get() % 1400;
    for (size_t j = 0; j < 16; j += 4) {
      uint32_t s = rd.Get(), d = rd.Get();
      memcpy(ip->src + j, &s, 4);
      memcpy(ip->dst + j, &d, 4);
    }
    for (uint32_t j = 0; j < payload + 20; j++) {
      l4[j] = static_cast<char>(rd.Get());
    }
    ip->set_version_traffic_class(0);
    ip->hop_limit = 64;

    // UDP
    uint32_t udp_len = sizeof(*udp) + payload;
    ip->next_header = bess::utils::Ipv4::Proto::kUdp;
    ip->payload_length = be16_t(udp_len);
    udp->length = be16_t(udp_len);
    udp->checksum = 0;
    uint16_t cksum_dpdk =
        rte_ipv6_udptcp_cksum(reinterpret_cast<const rte_ipv6_hdr *>(ip), udp);
    // The field's value is left out of the sum.
    udp->checksum = static_cast<uint16_t>(rd.Get());
    uint16_t cksum_bess = CalculateIpv6UdpChecksum(*ip, *udp, udp_len);
    EXPECT_EQ(cksum_dpdk, cksum_bess);
    EXPECT_NE(0, cksum_bess);
    udp->checksum = cksum_bess;
    EXPECT_TRUE(VerifyIpv6UdpChecksum(*ip, *udp, udp_len));
    udp->checksum ^= 0x0100;
    EXPECT_FALSE(VerifyIpv6UdpChecksum(*ip, *udp, udp_len));
    // A zero UDP checksum is accepted (RFC 6935/6936 tunnels).
    udp->checksum = 0;
    EXPECT_TRUE(VerifyIpv6UdpChecksum(*ip, *udp, udp_len));

    // TCP
    uint32_t tcp_len = sizeof(*tcp) + payload;
    ip->next_header = bess::utils::Ipv4::Proto::kTcp;
    ip->payload_length = be16_t(tcp_len);
    tcp->checksum = 0;
    cksum_dpdk =
        rte_ipv6_udptcp_cksum(reinterpret_cast<const rte_ipv6_hdr *>(ip), tcp);
    tcp->checksum = static_cast<uint16_t>(rd.Get());
    cksum_bess = CalculateIpv6TcpChecksum(*ip, *tcp, tcp_len);
    EXPECT_EQ(cksum_dpdk, cksum_bess);
    tcp->checksum = cksum_bess;
    EXPECT_TRUE(VerifyIpv6TcpChecksum(*ip, *tcp, tcp_len));
    tcp->checksum ^= 0x0001;
    EXPECT_FALSE(VerifyIpv6TcpChecksum(*ip, *tcp, tcp_len));
  }
}

// Tests TCP checksum
TEST(ChecksumTest, TcpChecksum) {
  char buf[1514] = {0};  // ipv4 header + tcp header + payload

  bess::utils::Ipv4 *ip = reinterpret_cast<bess::utils::Ipv4 *>(buf);
  bess::utils::Tcp *tcp = reinterpret_cast<bess::utils::Tcp *>(ip + 1);

  ip->version = 4;
  ip->header_length = 5;
  ip->type_of_service = 0;
  ip->length = be16_t(40);
  ip->fragment_offset = be16_t(0);
  ip->ttl = 10;
  ip->protocol = bess::utils::Ipv4::Proto::kTcp;
  ip->src = be32_t(0x12345678);
  ip->dst = be32_t(0x12347890);

  tcp->src_port = be16_t(0x0024);
  tcp->dst_port = be16_t(0x2097);
  tcp->seq_num = be32_t(0x67546354);
  tcp->ack_num = be32_t(0x98461732);

  uint16_t cksum_dpdk =
      rte_ipv4_udptcp_cksum(reinterpret_cast<const rte_ipv4_hdr *>(ip), tcp);
  uint16_t cksum_bess = CalculateIpv4TcpChecksum(*ip, *tcp);
  EXPECT_EQ(cksum_dpdk, cksum_bess);

  // bess excludes the checksum field to calculate tcp checksum
  tcp->checksum = 0x0987;
  cksum_bess = CalculateIpv4TcpChecksum(*ip, *tcp);
  EXPECT_EQ(cksum_dpdk, cksum_bess);

  tcp->checksum = cksum_bess;
  EXPECT_TRUE(VerifyIpv4TcpChecksum(*ip, *tcp));

  // Should not crash with incorrect IP headers
  ip->length = be16_t(39);
  EXPECT_EQ(0, CalculateIpv4TcpChecksum(*ip, *tcp));
  EXPECT_FALSE(VerifyIpv4TcpChecksum(*ip, *tcp));

  ip->length = be16_t(40);

  for (int i = 0; i < kTestLoopCount; i++) {
    ip->src = be32_t(rd.Get());
    ip->dst = be32_t(rd.Get());
    tcp->src_port = be16_t(rd.Get() >> 16);
    tcp->dst_port = be16_t(rd.Get() >> 16);
    tcp->seq_num = be32_t(rd.Get());
    tcp->ack_num = be32_t(rd.Get());

    ip->checksum = 0x0000;   // for dpdk
    tcp->checksum = 0x0000;  // for dpdk

    cksum_dpdk = rte_ipv4_cksum(reinterpret_cast<const rte_ipv4_hdr *>(ip));
    cksum_bess = CalculateIpv4NoOptChecksum(*ip);

    if (cksum_dpdk == 0xffff) {
      // While the value of IP/TCP checksum field must not be -0 (0xffff),
      // but DPDK often (incorrectly) gives that value. (RFC 768, 1071, 1624)
      EXPECT_EQ(0, cksum_bess);
    } else {
      EXPECT_EQ(cksum_dpdk, cksum_bess);
    }

    ip->checksum = cksum_bess;

    cksum_dpdk =
        rte_ipv4_udptcp_cksum(reinterpret_cast<const rte_ipv4_hdr *>(ip), tcp);
    cksum_bess = CalculateIpv4TcpChecksum(*ip, *tcp);

    if (cksum_dpdk == 0xffff) {
      // While the value of IP/TCP checksum field must not be -0 (0xffff),
      // but DPDK often (incorrectly) gives that value. (RFC 768, 1071, 1624)
      EXPECT_EQ(0, cksum_bess);
    } else {
      EXPECT_EQ(cksum_dpdk, cksum_bess);
    }
  }
}

// Tests incremental checksum update for unsigned 16-bit integer
TEST(ChecksumTest, IncrementalUpdateChecksum16) {
  uint16_t old16 = 0x4500;
  uint16_t new16 = 0x1234;
  uint16_t buf[5] = {old16, 0x0001, 0x4006, 0x0c22, 0xac0c};
  uint16_t cksum_old = CalculateGenericChecksum(buf, 10);

  buf[0] = new16;
  uint16_t cksum_new = CalculateGenericChecksum(buf, 10);
  uint16_t cksum_update = UpdateChecksum16(cksum_old, old16, new16);

  EXPECT_EQ(cksum_new, cksum_update);

  for (int i = 0; i < kTestLoopCount; i++) {
    for (int j = 0; j < 5; j++)
      buf[j] = rd.Get() >> 16;

    cksum_old = CalculateGenericChecksum(buf, 10);

    old16 = buf[0];
    new16 = buf[0] = rd.Get() >> 16;
    cksum_new = CalculateGenericChecksum(buf, 10);
    cksum_update = UpdateChecksum16(cksum_old, old16, new16);
    EXPECT_EQ(cksum_new, cksum_update);
  }
}

// Tests incremental checksum update for unsigned 32-bit integer
TEST(ChecksumTest, IncrementalUpdateChecksum32) {
  uint32_t old32 = 0x45000032;
  uint32_t new32 = 0x12341234;
  uint32_t buf[5] = {0x45000032, 0x00010000, 0x40060000, 0x0c22384e,
                     0xac0c3763};

  uint16_t cksum_old = CalculateGenericChecksum(buf, 20);

  buf[0] = new32;
  uint16_t cksum_new = CalculateGenericChecksum(buf, 20);
  uint16_t cksum_update = UpdateChecksum32(cksum_old, old32, new32);

  EXPECT_EQ(cksum_new, cksum_update);

  for (int i = 0; i < kTestLoopCount; i++) {
    for (int j = 0; j < 5; j++) {
      buf[j] = rd.Get();
    }

    cksum_old = CalculateGenericChecksum(buf, 20);

    old32 = buf[0];
    new32 = buf[0] = rd.Get();
    cksum_new = CalculateGenericChecksum(buf, 20);
    cksum_update = UpdateChecksum32(cksum_old, old32, new32);
    EXPECT_EQ(cksum_new, cksum_update);
  }
}

// Tests incremental checksum update with source IP/port update
TEST(ChecksumTest, IncrementalUpdateSrcIpPort) {
  char buf[1514] = {0};

  bess::utils::Ipv4 *ip = reinterpret_cast<bess::utils::Ipv4 *>(buf);

  bess::utils::Tcp *tcp = reinterpret_cast<bess::utils::Tcp *>(ip + 1);

  ip->version = 4;
  ip->header_length = 5;
  ip->type_of_service = 0;
  ip->length = be16_t(40);
  ip->fragment_offset = be16_t(0);
  ip->ttl = 10;
  ip->protocol = 0x06;  // tcp
  ip->src = be32_t(0x12345678);
  ip->dst = be32_t(0x12347890);

  tcp->src_port = be16_t(0x0024);
  tcp->dst_port = be16_t(0x2097);
  tcp->seq_num = be32_t(0x67546354);
  tcp->ack_num = be32_t(0x98461732);

  ip->checksum = CalculateIpv4NoOptChecksum(*ip);
  tcp->checksum = CalculateIpv4TcpChecksum(*ip, *tcp);
  EXPECT_TRUE(VerifyIpv4NoOptChecksum(*ip));
  EXPECT_TRUE(VerifyIpv4TcpChecksum(*ip, *tcp));

  for (int i = 0; i < kTestLoopCount; i++) {
    be32_t src_ip_old = ip->src;
    be16_t src_port_old = tcp->src_port;
    uint16_t ip_cksum_old = ip->checksum;
    uint16_t tcp_cksum_old = tcp->checksum;

    for (int j = 0; j < 5; j++) {
      ip->src = be32_t(rd.Get());
      tcp->src_port = be16_t(rd.Get() >> 16);
    }

    ip->checksum = UpdateChecksum32(ip_cksum_old, src_ip_old.raw_value(),
                                    ip->src.raw_value());
    EXPECT_TRUE(VerifyIpv4NoOptChecksum(*ip));

    tcp->checksum = UpdateChecksum32(tcp_cksum_old, src_ip_old.raw_value(),
                                     ip->src.raw_value());
    tcp->checksum = UpdateChecksum16(tcp->checksum, src_port_old.raw_value(),
                                     tcp->src_port.raw_value());
    EXPECT_TRUE(VerifyIpv4TcpChecksum(*ip, *tcp));
  }
}
}  // namespace
