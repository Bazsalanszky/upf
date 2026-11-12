#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2019 Intel Corporation

import ipaddress
import os
import socket
import struct
import sys
from socket import AF_INET, AF_INET6

import iptools
import psutil
from jsoncomment import JsonComment
from pyroute2 import NDB


def exit(code, msg):
    print(msg)
    sys.exit(code)


def getpid(process_name):
    for proc in psutil.process_iter(attrs=["pid", "name"]):
        if process_name == proc.info["name"]:
            return proc.info["pid"]


def getpythonpid(process_name):
    for proc in psutil.process_iter(attrs=["pid", "cmdline"]):
        if len(proc.info["cmdline"]) < 2:
            continue
        if (
            process_name in proc.info["cmdline"][1]
            and "python" in proc.info["cmdline"][0]
        ):
            return proc.info["pid"]
    return


def get_json_conf(path, dump):
    try:
        with open(path, "r") as f:
            jsonc_data = f.read()
        jc = JsonComment()
        conf = jc.loads(jsonc_data)
        if dump:
            print(jc.dumps(conf, indent=4, sort_keys=True))
        return conf
    except (OSError, ValueError) as e:
        print("An unexpected error occurred:", str(e))
        return None


def get_env(varname, default=None):
    try:
        var = os.environ[varname]
        return var
    except KeyError:
        if default is not None:
            return f"{default}"
        else:
            exit(1, f"Empty env var {varname}")


def ips_by_interface(name: str) -> list[str]:
    ndb = NDB()
    interfaces = ndb.interfaces
    if iface_record := interfaces.get(name):
        for address in iface_record.ipaddr:
            if address["family"] == AF_INET:
                return [address["local"]]
    return []


def ip6s_by_interface(name: str) -> list[str]:
    """The global IPv6 addresses of interface `name`: an N3/N9 tunnel is
    never sent from a link-local one."""
    ndb = NDB()
    out = []
    if iface_record := ndb.interfaces.get(name):
        for address in iface_record.ipaddr:
            if address["family"] != AF_INET6:
                continue
            if global_ipv6(address["address"]):
                out.append(address["address"])
    return out


def global_ipv6(addr) -> bool:
    try:
        ip = ipaddress.IPv6Address(addr)
    except ValueError:
        return False
    return not (
        ip.is_link_local
        or ip.is_multicast
        or ip.is_loopback
        or ip.is_unspecified
        or ip.ipv4_mapped is not None
    )


def tunnel_ipv6(conf: dict, ifname: str) -> str | None:
    """The IPv6 address GTP-U on this interface is sent from and received
    on: the interface's "ipv6" key in upf.jsonc, else its first global IPv6
    address, else none. "transport_family": "ipv4" turns it off."""
    if conf.get("transport_family", "") == "ipv4":
        return None
    if explicit := conf.get("ipv6"):
        if not global_ipv6(explicit):
            raise ValueError(
                f"{ifname}: ipv6 {explicit!r} is not a global IPv6 address"
            )
        return str(ipaddress.IPv6Address(explicit))
    addrs = ip6s_by_interface(ifname)
    return addrs[0] if addrs else None


def atoh(ip):
    return socket.inet_aton(ip)


def alias_by_interface(name: str) -> str | None:
    ndb = NDB()
    if iface_record := ndb.interfaces.get(name):
        return iface_record["ifalias"]


def mac_by_interface(name: str) -> str | None:
    ndb = NDB()
    if iface_record := ndb.interfaces.get(name):
        return iface_record["address"]


def mac2hex(mac):
    return int(mac.replace(":", ""), 16)


def peer_by_interface(name: str) -> str:
    ndb = NDB()
    try:
        peer_idx = ndb.interfaces[name]["link"]
        peer_name = ndb.interfaces[peer_idx]["ifname"]
    except KeyError:
        raise LookupError(f"veth interface {name} does not exist") from None
    else:
        return peer_name


def aton(ip):
    return socket.inet_aton(ip)


def validate_cidr(cidr):
    return iptools.ipv4.validate_cidr(cidr)


def cidr2mask(cidr):
    _, prefix = cidr.split("/")
    return format(0xFFFFFFFF << (32 - int(prefix)), "08x")


def cidr2block(cidr):
    return iptools.ipv4.cidr2block(cidr)


def ip2hex(ip):
    return iptools.ipv4.ip2hex(ip)


def cidr2netmask(cidr):
    network, net_bits = cidr.split("/")
    host_bits = 32 - int(net_bits)
    netmask = socket.inet_ntoa(struct.pack("!I", (1 << 32) - (1 << host_bits)))
    return network, netmask


def ip2long(ip):
    return iptools.ipv4.ip2long(ip)


def get_process_affinity():
    return psutil.Process().cpu_affinity()


def set_process_affinity(pid, cpus):
    try:
        psutil.Process(pid).cpu_affinity(cpus)
    except OSError as e:
        # 22 = Invalid argument; PID has PF_NO_SETAFFINITY set
        if e.errno == 22:
            print(f"Failed to set affinity on process {pid} {psutil.Process(pid).name}")
        else:
            raise


def set_process_affinity_all(cpus):
    for pid in psutil.pids():
        for thread in psutil.Process(pid).threads():
            set_process_affinity(thread.id, cpus)
