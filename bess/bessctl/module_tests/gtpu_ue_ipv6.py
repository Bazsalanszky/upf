# SPDX-FileCopyrightText: 2026 Balázs Toldi
# SPDX-License-Identifier: Apache-2.0

# IPv6 UE packets (stage 3 of the IPv6 port): GtpuParser's gate 2 and the
# attributes it writes for pdrLookup6, a pdrLookup6 laid out as up4.bess lays
# it out with rules encoded as pfcpiface encodes them, and GtpuDecap/GtpuEncap
# around an inner IPv6 packet.

import socket
import struct

from test_utils import *

N3 = "10.200.0.3"
N3_6 = "2001:db8:630::1"
GNB = "10.200.0.201"
GNB_6 = "2001:db8:630::10"
UE6 = "2001:db8:500:1:c0de:1:2:3"
UE6_PREFIX = "2001:db8:500:1::"
DN6 = "2606:4700:4700::1111"
TEID = 0x01020304
ACCESS, CORE = 1, 2

ETH = scapy.Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
ETH_LEN = 14


def a6(addr):
    return socket.inet_pton(socket.AF_INET6, addr)


def gtpu(body, teid=TEID, mtype=0xFF):
    return bytes([0x30, mtype]) + struct.pack("!HI", len(body), teid) + body


def over_v4(inner, teid=TEID):
    return bytes(ETH / scapy.IP(src=GNB, dst=N3) / scapy.UDP(sport=2152, dport=2152) / scapy.Raw(gtpu(inner, teid)))


def over_v6(inner, teid=TEID):
    return bytes(ETH / scapy.IPv6(src=GNB_6, dst=N3_6) / scapy.UDP(sport=2152, dport=2152) / scapy.Raw(gtpu(inner, teid)))


UL_UDP = bytes(scapy.IPv6(src=UE6, dst=DN6, tc=0xB8) / scapy.UDP(sport=40001, dport=53) / (b"y" * 12))
UL_TCP = bytes(scapy.IPv6(src=UE6, dst=DN6) / scapy.TCP(sport=40000, dport=443) / (b"x" * 20))
# A router solicitation from the UE's link-local address to all-routers.
RS = bytes(scapy.IPv6(src="fe80::c0de:1:2:3", dst="ff02::2", hlim=255) / scapy.ICMPv6ND_RS())
# An MLD report: a Hop-by-Hop header (Router Alert) before ICMPv6.
MLD = bytes(
    scapy.IPv6(src="fe80::c0de:1:2:3", dst="ff02::16")
    / scapy.IPv6ExtHdrHopByHop(options=[scapy.RouterAlert()])
    / scapy.ICMPv6MLReport2()
)
# The second fragment of a UDP datagram: no ports.
FRAG2 = bytes(scapy.IPv6(src=UE6, dst=DN6) / scapy.IPv6ExtHdrFragment(offset=100, nh=17, id=7) / (b"z" * 16))
DL_TCP = bytes(ETH / scapy.IPv6(src=DN6, dst=UE6) / scapy.TCP(sport=443, dport=40000) / (b"w" * 10))

# The attributes GtpuParser writes for pdrLookup6, in the order GenericEncap
# puts them in front of the packet.
ATTRS6 = [
    ("src_ip6_hi", 8),
    ("src_ip6_lo", 8),
    ("dst_ip6_hi", 8),
    ("dst_ip6_lo", 8),
    ("l4_ports", 4),
    ("teid", 4),
    ("ip_proto", 1),
]
ALL_ONES_PORTS = b"\xff\xff\xff\xff"
ALL_ONES_TEID = b"\xff\xff\xff\xff"


def attrs6(src, dst, ports, teid, proto):
    return a6(src) + a6(dst) + ports + teid + bytes([proto])


# pdrLookup6 as up4.bess declares it.
PDR6_FIELDS = [
    {"attr_name": "src_iface", "num_bytes": 1},
    {"attr_name": "teid", "num_bytes": 4},
    {"attr_name": "src_ip6_hi", "num_bytes": 8},
    {"attr_name": "src_ip6_lo", "num_bytes": 8},
    {"attr_name": "dst_ip6_hi", "num_bytes": 8},
    {"attr_name": "dst_ip6_lo", "num_bytes": 8},
    {"attr_name": "l4_ports", "num_bytes": 4},
    {"attr_name": "ip_proto", "num_bytes": 1},
]


def halves(addr):
    b = a6(addr)
    return int.from_bytes(b[:8], "big"), int.from_bytes(b[8:], "big")


def ints(*values):
    return [{"value_int": v} for v in values]


def rule(iface=0, teid=0, src=None, src_len=0, dst=None, dst_len=0, sport=None, dport=None, proto=None):
    """A pdrLookup6 rule as pfcpiface writes it: values and masks as integers,
    the addresses as big-endian halves, the ports as source<<16 | destination."""

    def prefix(addr, length):
        if addr is None:
            return (0, 0), (0, 0)
        mask = ((1 << 128) - 1) ^ ((1 << (128 - length)) - 1)
        m_hi, m_lo = mask >> 64, mask & ((1 << 64) - 1)
        hi, lo = halves(addr)
        return (hi & m_hi, lo & m_lo), (m_hi, m_lo)

    (s_hi, s_lo), (sm_hi, sm_lo) = prefix(src, src_len)
    (d_hi, d_lo), (dm_hi, dm_lo) = prefix(dst, dst_len)
    ports = ((sport or 0) << 16) | (dport or 0)
    ports_mask = (0xFFFF0000 if sport is not None else 0) | (0xFFFF if dport is not None else 0)
    values = ints(iface, teid, s_hi, s_lo, d_hi, d_lo, ports, proto or 0)
    masks = ints(
        0xFF if iface else 0,
        0xFFFFFFFF if teid else 0,
        sm_hi, sm_lo, dm_hi, dm_lo, ports_mask,
        0xFF if proto is not None else 0,
    )
    return values, masks


class GtpuUeIpv6Test(BessModuleTestCase):
    # ---------------------------------------------------------------- parser
    def parse6(self, pkts):
        parser = GtpuParser()
        encap = GenericEncap(fields=[{"size": s, "attribute": a} for a, s in ATTRS6])
        self.bess.connect_modules(parser.name, encap.name, 2, 0)
        return self.run_pipeline(parser, encap, 0, pkts, [0], proto=bytes)[0]

    def test_parser_classifies_an_ipv6_ue_packet_in_a_gpdu(self):
        teid = struct.pack("!I", TEID)
        cases = (
            ("udp, IPv4 outer", over_v4(UL_UDP), attrs6(UE6, DN6, struct.pack("!HH", 40001, 53), teid, 17)),
            ("udp, IPv6 outer", over_v6(UL_UDP), attrs6(UE6, DN6, struct.pack("!HH", 40001, 53), teid, 17)),
            ("tcp", over_v4(UL_TCP), attrs6(UE6, DN6, struct.pack("!HH", 40000, 443), teid, 6)),
            ("router solicitation", over_v4(RS), attrs6("fe80::c0de:1:2:3", "ff02::2", ALL_ONES_PORTS, teid, 58)),
            ("hop-by-hop, then ICMPv6", over_v6(MLD), attrs6("fe80::c0de:1:2:3", "ff02::16", ALL_ONES_PORTS, teid, 58)),
            ("later fragment: no ports", over_v4(FRAG2), attrs6(UE6, DN6, ALL_ONES_PORTS, teid, 17)),
        )
        for name, pkt, want in cases:
            with self.subTest(case=name):
                out = self.parse6([pkt])
                self.assertEqual(len(out), 1, f"{name} did not leave on gate 2")
                self.assertEqual(out[0][: len(want)], want)

    def test_parser_classifies_an_ipv6_packet_from_the_data_network(self):
        out = self.parse6([DL_TCP])
        self.assertEqual(len(out), 1)
        want = attrs6(DN6, UE6, struct.pack("!HH", 443, 40000), ALL_ONES_TEID, 6)
        self.assertEqual(out[0][: len(want)], want)

    def test_parser_drops_a_cut_inner_ipv6_packet(self):
        for name, pkt in (
            ("fixed header cut", over_v4(UL_UDP[:30])),
            ("ports cut", over_v4(UL_UDP[:42])),
            ("extension header cut", over_v4(MLD[:41])),
        ):
            with self.subTest(case=name):
                out = self.run_module(GtpuParser(), 0, [pkt], [0, 1, 2])
                self.assertEqual((len(out[0]), len(out[1]), len(out[2])), (1, 0, 0), name)
                self.assertBessAlive()

    def test_ipv4_ue_packets_still_take_gate_1(self):
        inner = bytes(scapy.IP(src="10.250.0.1", dst="10.0.0.9") / scapy.UDP(sport=1, dport=2))
        for pkt in (over_v4(inner), over_v6(inner), bytes(ETH / scapy.IP(src="10.0.0.9", dst="10.250.0.1") / scapy.UDP())):
            out = self.run_module(GtpuParser(), 0, [pkt], [0, 1, 2])
            self.assertEqual((len(out[0]), len(out[1]), len(out[2])), (0, 1, 0))

    # ---------------------------------------------------------------- pdrLookup6
    def lookup(self, iface, pkts, rules):
        meta = SetMetadata(attrs=[{"name": "src_iface", "size": 1, "value_int": iface}])
        parser = GtpuParser()
        pdr6 = WildcardMatch(fields=PDR6_FIELDS, values=[{"attr_name": "pdr_id", "num_bytes": 4}])
        for gate, priority, (values, masks) in rules:
            pdr6.add(gate=gate, priority=priority, values=values, masks=masks, valuesv=ints(gate))
        pdr6.set_default_gate(gate=9)
        self.bess.connect_modules(meta.name, parser.name, 0, 0)
        self.bess.connect_modules(parser.name, pdr6.name, 2, 0)
        return self.run_pipeline(meta, pdr6, 0, pkts, [1, 2, 3, 4, 9], proto=bytes)

    def test_pdr_lookup6_matches_as_pfcpiface_writes_the_rules(self):
        rules = [
            # UP2CP: the session's TEID, ICMPv6 to ff02::2, precedence 0.
            (3, 0xFFFFFFFF, rule(iface=ACCESS, teid=TEID, dst="ff02::2", dst_len=128, proto=58)),
            # The uplink PDR: the TEID and the UE's /64 as the source.
            (1, 0xFFFFFF00, rule(iface=ACCESS, teid=TEID, src=UE6_PREFIX, src_len=64)),
            # A downlink PCC rule: TCP from port 443 to the UE's /64.
            (4, 0xFFFFFFF0, rule(iface=CORE, src=DN6, src_len=128, dst=UE6_PREFIX, dst_len=64, sport=443, proto=6)),
            # The downlink PDR: the UE's /64 as the destination.
            (2, 0xFFFFFF00, rule(iface=CORE, dst=UE6_PREFIX, dst_len=64)),
        ]
        other_ue = bytes(scapy.IPv6(src="2001:db8:500:2::1", dst=DN6) / scapy.UDP())
        privacy = bytes(scapy.IPv6(src="2001:db8:500:1:dead:beef:0:1", dst=DN6) / scapy.UDP())
        ul = self.lookup(ACCESS, [over_v4(UL_UDP), over_v4(RS), over_v6(privacy), over_v4(other_ue),
                                  over_v4(UL_UDP, teid=TEID + 1)], rules)
        self.assertEqual(len(ul[1]), 2, "the uplink PDR (any address in the /64)")
        self.assertEqual(len(ul[3]), 1, "the router solicitation")
        self.assertEqual(len(ul[9]), 2, "another UE's prefix, another TEID")

        dl_other = bytes(ETH / scapy.IPv6(src=DN6, dst=UE6) / scapy.TCP(sport=80, dport=40000))
        dl = self.lookup(CORE, [DL_TCP, dl_other, bytes(ETH / scapy.IPv6(src=DN6, dst="2001:db8:500:2::1") / scapy.UDP())], rules)
        self.assertEqual(len(dl[4]), 1, "the PCC rule (port 443)")
        self.assertEqual(len(dl[2]), 1, "the default downlink PDR")
        self.assertEqual(len(dl[9]), 1, "another UE")

    # ---------------------------------------------------------------- decap / encap
    def test_decap_of_an_inner_ipv6_packet_is_labelled_ipv6(self):
        for name, pkt in (("IPv4 outer", over_v4(UL_UDP)), ("IPv6 outer", over_v6(UL_UDP))):
            with self.subTest(case=name):
                out = self.run_module(GtpuDecap(), 0, [pkt], [0], proto=bytes)
                self.assertEqual(out[0], [pkt[:12] + b"\x86\xdd" + UL_UDP])

    def test_encap_of_an_ipv6_packet_in_an_ipv4_outer_header(self):
        downlink = bytes(scapy.Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02", type=0x86DD)) + UL_UDP
        tunnel = SetMetadata(attrs=[
            {"name": "action", "size": 1, "value_int": 0},
            {"name": "qfi", "size": 1, "value_int": 9},
            {"name": "tunnel_out_src_ip4addr", "size": 4, "value_int": int.from_bytes(socket.inet_aton(N3), "little")},
            {"name": "tunnel_out_dst_ip4addr", "size": 4, "value_int": int.from_bytes(socket.inet_aton(GNB), "little")},
            {"name": "tunnel_out_teid", "size": 4, "value_int": int.from_bytes(struct.pack("!I", TEID), "little")},
            {"name": "tunnel_out_udp_port", "size": 2, "value_int": int.from_bytes(struct.pack("!H", 2152), "little")},
        ])
        encap = GtpuEncap(add_psc=False)
        self.bess.connect_modules(tunnel.name, encap.name, 0, 0)
        out = self.run_pipeline(tunnel, encap, 0, [downlink], [0, 1], proto=bytes)
        self.assertEqual(len(out[1]), 1)
        frame = out[1][0]
        self.assertEqual(frame[12:14], b"\x08\x00", "the outer header is IPv4")
        outer = scapy.IP(frame[ETH_LEN:])
        self.assertEqual((outer.src, outer.dst, outer.tos), (N3, GNB, 0xB8))
        self.assertEqual(frame[-len(UL_UDP):], UL_UDP)


suite = unittest.TestLoader().loadTestsFromTestCase(GtpuUeIpv6Test)
results = unittest.TextTestRunner(verbosity=2).run(suite)

if results.failures or results.errors:
    sys.exit(1)
