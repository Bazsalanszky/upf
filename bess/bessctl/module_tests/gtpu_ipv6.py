# SPDX-FileCopyrightText: 2026 Balázs Toldi
# SPDX-License-Identifier: Apache-2.0

# GTP-U with an IPv6 outer header (N3/N9 over IPv6) carrying IPv4 UE packets:
# GtpuParser, GtpuDecap, GtpuEncap, L4Checksum, GtpuEcho, GtpuPathMonitoring
# and IP6Lookup.

import socket
import struct

from test_utils import *

N3_6 = "2001:db8:630::1"
CORE_6 = "2001:db8:660::2"
GNB_6 = "2001:db8:630::10"
N3 = "10.200.0.3"
UE = "10.250.0.1"
DN = "10.0.0.9"
TEID = 0x01020304
QFI = 9

ETH = scapy.Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
ETH4 = scapy.Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02", type=0x0800)
ETH_LEN = 14

INNER_TCP = bytes(scapy.IP(src=UE, dst=DN, tos=0xB8) / scapy.TCP(sport=40000, dport=80) / (b"x" * 20))
INNER_UDP = bytes(scapy.IP(src=UE, dst=DN) / scapy.UDP(sport=40001, dport=53) / (b"y" * 12))

OPTS_PSC = b"\x00\x00\x00\x85"  # seq, N-PDU, next type: PDU Session Container
PSC_END = b"\x01\x10\x09\x00"  # one unit, UL, QFI 9, next type: none


def gtpu(flags, mtype, body, teid=TEID):
    return bytes([flags, mtype]) + struct.pack("!HI", len(body), teid) + body


def n3v6(gtp_bytes, dst=N3_6, src=GNB_6):
    return bytes(ETH / scapy.IPv6(src=src, dst=dst) / scapy.UDP(sport=2152, dport=2152) / scapy.Raw(gtp_bytes))


def n3v4(gtp_bytes):
    return bytes(ETH / scapy.IP(src="10.200.0.201", dst=N3) / scapy.UDP(sport=2152, dport=2152) / scapy.Raw(gtp_bytes))


def ip4(addr):
    return socket.inet_aton(addr)


def low32(addr6):
    return socket.inet_pton(socket.AF_INET6, addr6)[12:]


GPDU6_PSC_TCP = n3v6(gtpu(0x34, 0xFF, OPTS_PSC + PSC_END + INNER_TCP))
GPDU6_UDP = n3v6(gtpu(0x30, 0xFF, INNER_UDP))

# The attributes GtpuParser writes (see gtpu_decap.py).
ATTRS = [
    ("src_ip", 4),
    ("dst_ip", 4),
    ("src_port", 2),
    ("dst_port", 2),
    ("teid", 4),
    ("tunnel_ipv4_dst", 4),
    ("ip_proto", 1),
]


def attr(name, size, wire):
    """An attribute GtpuEncap reads as a native-order integer and writes
    big-endian (see gtpu_encap.py)."""
    return {"name": name, "size": size, "value_int": int.from_bytes(wire, "little")}


def tunnel_attrs(action=0, dst4="0.0.0.0", dst6=None, src4=N3):
    a6 = socket.inet_pton(socket.AF_INET6, dst6) if dst6 else bytes(16)
    return [
        {"name": "action", "size": 1, "value_int": action},
        {"name": "qfi", "size": 1, "value_int": QFI},
        attr("tunnel_out_src_ip4addr", 4, ip4(src4)),
        attr("tunnel_out_dst_ip4addr", 4, ip4(dst4)),
        attr("tunnel_out_teid", 4, struct.pack("!I", TEID)),
        attr("tunnel_out_udp_port", 2, struct.pack("!H", 2152)),
        attr("tunnel_out_dst_ip6_hi", 8, a6[:8]),
        attr("tunnel_out_dst_ip6_lo", 8, a6[8:]),
    ]


class GtpuIpv6Test(BessModuleTestCase):
    # ---------------------------------------------------------------- parser
    def parse(self, pkts):
        parser = GtpuParser()
        encap = GenericEncap(fields=[{"size": s, "attribute": a} for a, s in ATTRS])
        self.bess.connect_modules(parser.name, encap.name, 1, 0)
        return self.run_pipeline(parser, encap, 0, pkts, [0], proto=bytes)[0]

    def test_parser_classifies_a_gpdu_in_an_ipv6_outer_header(self):
        for name, pkt, sport, dport, proto in (
            ("psc_tcp", GPDU6_PSC_TCP, 40000, 80, 6),
            ("plain_udp", GPDU6_UDP, 40001, 53, 17),
        ):
            with self.subTest(case=name):
                out = self.parse([pkt])
                self.assertEqual(len(out), 1, "the G-PDU was not classified")
                self.assertEqual(
                    out[0][:21],
                    ip4(UE) + ip4(DN) + struct.pack("!HH", sport, dport)
                    + struct.pack("!I", TEID) + low32(N3_6) + bytes([proto]),
                )

    def test_parser_tunnel_key_is_the_low_32_bits_of_the_destination(self):
        other = "2001:db8:630::a0a:301"  # low 32 bits read as 10.10.3.1
        out = self.parse([n3v6(gtpu(0x30, 0xFF, INNER_UDP), dst=other)])
        self.assertEqual(out[0][16:20], ip4("10.10.3.1"))

    def test_parser_classifies_no_other_ipv6_packet_as_ipv4(self):
        # Gate 1 is pdrLookup, for IPv4 UE packets. An IPv6 packet that is not a G-PDU
        # with an IPv4 packet inside goes to gate 2 (pdrLookup6, gtpu_ue_ipv6.py) when
        # it is a whole IPv6 packet, and to gate 0 when it is cut or carries no packet.
        to_pdr_lookup6 = {
            "neighbour_solicitation": bytes(
                ETH / scapy.IPv6(src="fe80::1", dst="ff02::1:ff00:1") / scapy.ICMPv6ND_NS(tgt=N3_6)
            ),
            "udp_other_port": bytes(ETH / scapy.IPv6(src=GNB_6, dst=N3_6) / scapy.UDP(sport=5000, dport=53) / b"q"),
            # An extension header before UDP: classified on its own, not decapsulated.
            "hop_by_hop": bytes(
                ETH / scapy.IPv6(src=GNB_6, dst=N3_6) / scapy.IPv6ExtHdrHopByHop()
                / scapy.UDP(sport=2152, dport=2152) / scapy.Raw(gtpu(0x30, 0xFF, INNER_UDP))
            ),
            "ipv6_ue_packet": bytes(ETH / scapy.IPv6(src="2001:db8:500::1", dst="2001:db8::9") / scapy.UDP()),
            "inner_ipv6": n3v6(gtpu(0x30, 0xFF, bytes(scapy.IPv6(src="fd00::1", dst="fd00::2") / scapy.UDP()))),
        }
        to_default = {
            "outer_ipv6_cut": GPDU6_UDP[: ETH_LEN + 30],
            "udp_cut": GPDU6_UDP[: ETH_LEN + 40 + 4],
            "end_marker": n3v6(gtpu(0x30, 254, b"")),
        }
        for gate, cases in ((2, to_pdr_lookup6), (0, to_default)):
            for name, pkt in cases.items():
                with self.subTest(case=name):
                    parser = GtpuParser()
                    out = self.run_module(parser, 0, [pkt], [0, 1, 2])
                    self.assertEqual(len(out[1]), 0, f"{name} was classified as IPv4")
                    self.assertEqual(len(out[gate]), 1, f"{name} did not leave on gate {gate}")
                    self.assertBessAlive()

    # ---------------------------------------------------------------- decap
    def test_decap_strips_an_ipv6_outer_header_and_fixes_the_ethertype(self):
        decap = GtpuDecap()
        for name, pkt, inner in (("psc_tcp", GPDU6_PSC_TCP, INNER_TCP), ("plain_udp", GPDU6_UDP, INNER_UDP)):
            with self.subTest(case=name):
                out = self.run_module(decap, 0, [pkt], [0], proto=bytes)
                self.assertEqual(len(out[0]), 1)
                frame = out[0][0]
                self.assertEqual(frame[:12], pkt[:12], "the MAC addresses changed")
                self.assertEqual(frame[12:14], b"\x08\x00", "an IPv4 packet is labelled with the outer EtherType")
                self.assertEqual(frame[14:], inner)

    def test_decap_of_an_ipv4_outer_header_is_unchanged(self):
        decap = GtpuDecap()
        pkt = n3v4(gtpu(0x30, 0xFF, INNER_UDP))
        out = self.run_module(decap, 0, [pkt], [0], proto=bytes)
        self.assertEqual(out[0], [pkt[:14] + INNER_UDP])

    def test_decap_drops_a_cut_ipv6_outer_header(self):
        decap = GtpuDecap()
        for cut in (ETH_LEN + 20, ETH_LEN + 40 + 4, ETH_LEN + 40 + 8 + 4):
            with self.subTest(cut=cut):
                out = self.run_module(decap, 0, [GPDU6_UDP[:cut]], [0])
                self.assertEqual(len(out[0]), 0)
                self.assertBessAlive()

    # ---------------------------------------------------------------- encap
    def encap(self, pkts, attrs, add_psc=True, **kwargs):
        tunnel = SetMetadata(attrs=attrs)
        encap = GtpuEncap(add_psc=add_psc, **kwargs)
        self.bess.connect_modules(tunnel.name, encap.name, 0, 0)
        return self.run_pipeline(tunnel, encap, 0, pkts, [0, 1], proto=bytes)

    def test_encap_builds_an_ipv6_outer_header_for_an_ipv6_peer(self):
        downlink = bytes(ETH4) + INNER_TCP
        for add_psc, flags, ext_len in ((True, 0x34, 8), (False, 0x30, 0)):
            with self.subTest(add_psc=add_psc):
                out = self.encap([downlink], tunnel_attrs(dst6=GNB_6), add_psc=add_psc,
                                 access_ip6=N3_6, core_ip6=CORE_6)
                self.assertEqual(len(out[1]), 1, "the packet was not encapsulated")
                frame = out[1][0]
                self.assertEqual(frame[:12], downlink[:12])
                self.assertEqual(frame[12:14], b"\x86\xdd")
                outer = scapy.IPv6(frame[ETH_LEN:])
                self.assertEqual(outer.version, 6)
                self.assertEqual(outer.tc, 0xB8, "the DSCP/ECN of the packet carried was not copied")
                self.assertEqual(outer.fl, 0)
                self.assertEqual(outer.nh, 17)
                self.assertEqual(outer.hlim, 64)
                self.assertEqual((outer.src, outer.dst), (N3_6, GNB_6))
                self.assertEqual(outer.plen, len(frame) - ETH_LEN - 40)
                udp = frame[ETH_LEN + 40 : ETH_LEN + 48]
                self.assertEqual(struct.unpack("!HHH", udp[:6]), (2152, 2152, len(frame) - ETH_LEN - 40))
                gtp = frame[ETH_LEN + 48 :]
                ghdr, mtype, length, teid = struct.unpack("!BBHI", gtp[:8])
                self.assertEqual((ghdr, mtype, teid), (flags, 0xFF, TEID))
                self.assertEqual(length, ext_len + len(INNER_TCP))
                self.assertEqual(gtp[-len(INNER_TCP) :], INNER_TCP)
                if add_psc:
                    self.assertEqual(gtp[8:16], b"\x00\x00\x00\x85\x01\x00\x09\x00")

    def test_encap_sends_uplink_from_the_core_address(self):
        out = self.encap([bytes(ETH4) + INNER_UDP], tunnel_attrs(action=1, dst6=GNB_6),
                         access_ip6=N3_6, core_ip6=CORE_6)
        self.assertEqual(scapy.IPv6(out[1][0][ETH_LEN:]).src, CORE_6)

    def test_encap_without_a_source_for_the_direction_fails_the_packet(self):
        out = self.encap([bytes(ETH4) + INNER_UDP], tunnel_attrs(action=1, dst6=GNB_6), access_ip6=N3_6)
        self.assertEqual(len(out[1]), 0)
        self.assertEqual(len(out[0]), 1, "the packet did not leave by the failure gate")

    def test_encap_without_an_ipv6_source_is_the_ipv4_encapsulator(self):
        # An instance without IPv6 sources -- the pipeline's gtpuEncap --
        # ignores IPv6 tunnel attributes, whatever they hold, and builds the
        # IPv4 outer header it always has.
        downlink = bytes(ETH4) + INNER_UDP
        plain = self.encap([downlink], tunnel_attrs(dst4="10.200.0.201")[:6])[1][0]
        with_v6_attrs = self.encap([downlink], tunnel_attrs(dst4="10.200.0.201", dst6=GNB_6))[1][0]
        ip_id = slice(ETH_LEN + 4, ETH_LEN + 6)
        self.assertEqual(
            plain[: ip_id.start] + plain[ip_id.stop :], with_v6_attrs[: ip_id.start] + with_v6_attrs[ip_id.stop :]
        )
        self.assertEqual(plain[12:14], b"\x08\x00")
        self.assertEqual(scapy.IP(plain[ETH_LEN:]).dst, "10.200.0.201")

    def test_encap_refuses_an_invalid_ipv6_source(self):
        with self.assertRaises(bess.Error):
            GtpuEncap(add_psc=True, access_ip6="10.0.0.1")

    # ---------------------------------------------------------------- L4Checksum
    def test_l4_checksum_over_ipv6(self):
        frame = bytes(ETH / scapy.IPv6(src=N3_6, dst=GNB_6) / scapy.UDP(sport=2152, dport=2152, chksum=0)
                      / scapy.Raw(gtpu(0x30, 0xFF, INNER_TCP)))
        out = self.run_module(L4Checksum(), 0, [frame], [0], proto=bytes)
        got = struct.unpack("!H", out[0][0][ETH_LEN + 46 : ETH_LEN + 48])[0]
        want = scapy.IPv6(bytes(scapy.IPv6(src=N3_6, dst=GNB_6) / scapy.UDP(sport=2152, dport=2152)
                                / scapy.Raw(gtpu(0x30, 0xFF, INNER_TCP))))[scapy.UDP].chksum
        self.assertEqual(got, want)

        verify = L4Checksum(verify=True)
        good = out[0][0]
        bad = bytearray(good)
        bad[-1] ^= 0xFF
        res = self.run_module(verify, 0, [good, bytes(bad)], [0, 1], proto=bytes)
        self.assertEqual(res[0], [good])
        self.assertEqual(res[1], [bytes(bad)])

    # ---------------------------------------------------------------- GtpuEcho
    def test_echo_request_over_ipv6_is_answered(self):
        req = bytes(ETH / scapy.IPv6(src=GNB_6, dst=N3_6) / scapy.UDP(sport=2152, dport=2152)
                    / scapy.Raw(gtpu(0x32, 1, b"\x00\x07\x00\x00", teid=0)))
        echo = GtpuEcho(s1u_sgw_ip=0, ipv6=True)
        out = self.run_module(echo, 0, [req], [0, 1], proto=bytes)
        self.assertEqual(len(out[1]), 1, "the echo request was not answered")
        rsp = out[1][0]
        ip6 = scapy.IPv6(rsp[ETH_LEN:])
        self.assertEqual((ip6.src, ip6.dst), (N3_6, GNB_6))
        gtp = rsp[ETH_LEN + 48 :]
        self.assertEqual(gtp[1], 2, "not an Echo Response")
        self.assertEqual(struct.unpack("!H", gtp[2:4])[0], 4 + 2)
        self.assertEqual(gtp[8:12], b"\x00\x07\x00\x00", "the sequence number changed")
        self.assertEqual(gtp[12:14], b"\x0e\x00", "no Recovery IE")
        self.assertEqual(ip6.plen, 8 + 8 + 6)
        self.assertEqual(struct.unpack("!H", rsp[ETH_LEN + 44 : ETH_LEN + 46])[0], 8 + 8 + 6)

    def test_echo_still_needs_an_address(self):
        with self.assertRaises(bess.Error):
            GtpuEcho(s1u_sgw_ip=0)

    # ---------------------------------------------------------------- GtpuPathMonitoring
    def test_path_monitoring_over_ipv6(self):
        gnb4 = "10.200.0.201"
        gpm = GtpuPathMonitoring()
        gpm.add(gnb_ip=int.from_bytes(ip4(gnb4), "big"))
        gpm.add(gnb_ip6=socket.inet_pton(socket.AF_INET6, GNB_6))

        def echo(mtype, l3, seq=0):
            body = struct.pack("!HBB", seq, 0, 0)
            return bytes(ETH / l3 / scapy.UDP(sport=2152, dport=2152) / scapy.Raw(gtpu(0x32, mtype, body, teid=0)))

        req6 = echo(1, scapy.IPv6(src=N3_6, dst="::"))
        req4 = echo(1, scapy.IP(src=N3, dst="0.0.0.0"))
        # A request template of each family goes to the gNBs of that family.
        out = self.run_module(gpm, 0, [req6], [0], proto=bytes)
        self.assertEqual([scapy.IPv6(p[ETH_LEN:]).dst for p in out[0]], [GNB_6])
        out = self.run_module(gpm, 0, [req4], [0], proto=bytes)
        self.assertEqual([scapy.IP(p[ETH_LEN:]).dst for p in out[0]], [gnb4])

        # Request 0 went to the IPv6 gNB, request 1 to the IPv4 one.
        self.run_module(gpm, 0, [echo(2, scapy.IPv6(src=GNB_6, dst=N3_6), seq=0),
                                 echo(2, scapy.IP(src=gnb4, dst=N3), seq=1)], [0])
        stats = {(s.gnb_ip, bytes(s.gnb_ip6)): s.count for s in gpm.read(clear=False).statistics}
        self.assertEqual(stats, {(0, socket.inet_pton(socket.AF_INET6, GNB_6)): 1,
                                 (int.from_bytes(ip4(gnb4), "big"), b""): 1})

        gpm.delete(gnb_ip6=socket.inet_pton(socket.AF_INET6, GNB_6))
        out = self.run_module(gpm, 0, [req6], [0], proto=bytes)
        self.assertEqual(len(out[0]), 0, "the deleted IPv6 gNB was still sent a request")

        with self.assertRaises(bess.Error):
            gpm.add(gnb_ip6=b"\x20\x01")
        with self.assertRaises(bess.Error):
            gpm.add(gnb_ip6=socket.inet_pton(socket.AF_INET6, "::ffff:10.0.0.1"))

    # ---------------------------------------------------------------- IP6Lookup
    def test_ip6_lookup_routes_by_longest_prefix(self):
        lookup = IP6Lookup()
        lookup.add(prefix="2001:db8::", prefix_len=32, gate=1)
        lookup.add(prefix="2001:db8:630::", prefix_len=64, gate=2)
        lookup.add(prefix="2001:db8:630::10", prefix_len=128, gate=3)
        lookup.add(prefix="::", prefix_len=0, gate=4)

        def to(dst):
            return bytes(ETH / scapy.IPv6(src=N3_6, dst=dst) / scapy.UDP())

        pkts = {1: to("2001:db8:1::1"), 2: to("2001:db8:630::11"), 3: to(GNB_6), 4: to("2001:4860::1")}
        v4 = bytes(ETH4 / scapy.IP(src=N3, dst="10.0.0.1") / scapy.UDP())
        out = self.run_module(lookup, 0, list(pkts.values()) + [v4], [1, 2, 3, 4], proto=bytes)
        for gate, pkt in pkts.items():
            self.assertIn(pkt, out[gate], f"not routed to gate {gate}")
        self.assertIn(v4, out[4], "an IPv4 packet did not take the default gate")

        lookup.delete(prefix="2001:db8:630::10", prefix_len=128)
        out = self.run_module(lookup, 0, [pkts[3]], [2, 3], proto=bytes)
        self.assertEqual(out[2], [pkts[3]], "the /64 did not take over from the deleted /128")

        with self.assertRaises(bess.Error):
            lookup.add(prefix="2001:db8:630::1", prefix_len=64, gate=1)  # host bits set
        with self.assertRaises(bess.Error):
            lookup.add(prefix="10.0.0.0", prefix_len=8, gate=1)

        lookup.clear()
        out = self.run_module(lookup, 0, [pkts[1]], [1])
        self.assertEqual(len(out[1]), 0, "a route survived clear()")


suite = unittest.TestLoader().loadTestsFromTestCase(GtpuIpv6Test)
results = unittest.TextTestRunner(verbosity=2).run(suite)

if results.failures or results.errors:
    sys.exit(1)
