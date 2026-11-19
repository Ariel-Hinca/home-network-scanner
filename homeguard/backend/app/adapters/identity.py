"""Names for devices that already answered a scan.

Only those addresses are asked. The lookup is a reverse DNS query, then a
NetBIOS name query, plus the company name on the network card from the local
ARP table. Nothing here adds ports or leaves the addresses already found.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

from app.adapters.nmap.parser import DiscoveredHost

_ARP_LINE = re.compile(
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"(?P<mac>[0-9A-Fa-f]{2}(?:[-:][0-9A-Fa-f]{2}){5})"
)
_VENDORS: dict[str, dict[str, str]] = {}


def identify_hosts(hosts: list[DiscoveredHost], nmap_bin: str) -> list[DiscoveredHost]:
    if not hosts:
        return hosts
    pending = [host.ip for host in hosts if _private_ipv4(host.ip) and not host.hostname]
    names = _lookup_names(pending)
    return apply_identity(hosts, arp=read_arp_table(), vendors=load_vendors(nmap_bin), names=names)


def apply_identity(
    hosts: list[DiscoveredHost],
    *,
    arp: dict[str, str],
    vendors: dict[str, str],
    names: dict[str, str],
) -> list[DiscoveredHost]:
    named: list[DiscoveredHost] = []
    for host in hosts:
        mac = host.mac or arp.get(host.ip, "")
        vendor = host.vendor or vendor_for(mac, vendors)
        hostname = host.hostname or _clean_name(names.get(host.ip, ""))
        named.append(replace(host, hostname=hostname, mac=mac, vendor=vendor))
    return named


def parse_arp_table(text: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for match in _ARP_LINE.finditer(text):
        ip = match.group("ip")
        mac = _format_mac(match.group("mac"))
        if _private_ipv4(ip) and mac:
            found[ip] = mac
    return found


def read_arp_table() -> dict[str, str]:
    try:
        completed = subprocess.run(
            ["arp", "-a"],
            capture_output=True,
            text=True,
            timeout=3,
            shell=False,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {}
    return parse_arp_table(completed.stdout or "")


def load_vendors(nmap_bin: str) -> dict[str, str]:
    path = Path(nmap_bin).resolve().parent / "nmap-mac-prefixes"
    if not path.is_file():
        return {}
    cached = _VENDORS.get(str(path))
    if cached is not None:
        return cached
    vendors = _read_vendor_file(path)
    _VENDORS[str(path)] = vendors
    return vendors


def vendor_for(mac: str, vendors: dict[str, str]) -> str:
    hex_mac = "".join(character for character in mac if character.isalnum()).upper()
    if len(hex_mac) != 12:
        return ""
    for size in range(len(hex_mac), 5, -1):
        vendor = vendors.get(hex_mac[:size])
        if vendor:
            return vendor
    return ""


def device_kind(ip: str, cidr: str, open_ports: set[int]) -> str:
    if _is_gateway(ip, cidr):
        return "router"
    if 554 in open_ports:
        return "camera"
    if open_ports & {9100, 515, 631}:
        return "printer"
    if 8009 in open_ports:
        return "tv"
    if open_ports & {3389, 5357, 445, 139}:
        return "computer"
    if open_ports & {62078, 548}:
        return "apple"
    return ""


def parse_netbios_hostname(payload: bytes) -> str:
    if len(payload) < 12 or payload[2] & 0x80 == 0:
        return ""
    offset = _skip_name(payload, 12)
    offset += 4
    offset = _skip_name(payload, offset)
    if offset + 10 > len(payload):
        return ""
    record_type = int.from_bytes(payload[offset : offset + 2], "big")
    offset += 8
    length = int.from_bytes(payload[offset : offset + 2], "big")
    offset += 2
    if record_type != 0x21 or length < 1 or offset + length > len(payload):
        return ""
    count = payload[offset]
    offset += 1
    fallback = ""
    for _ in range(count):
        if offset + 18 > len(payload):
            break
        raw_name = payload[offset : offset + 15]
        suffix = payload[offset + 15]
        flags = int.from_bytes(payload[offset + 16 : offset + 18], "big")
        offset += 18
        if flags & 0x8000:
            continue
        name = raw_name.decode("ascii", errors="ignore").strip(" \x00")
        if not name or name == "*":
            continue
        if suffix == 0x00:
            return name[:255]
        if suffix == 0x20 and not fallback:
            fallback = name[:255]
    return fallback


def _lookup_names(ips: list[str]) -> dict[str, str]:
    if not ips:
        return {}
    workers = min(8, len(ips))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        found = pool.map(_lookup_name, ips)
    return {ip: name for ip, name in zip(ips, found, strict=True) if name}


def _lookup_name(ip: str) -> str:
    if not _private_ipv4(ip):
        return ""
    dns_name = _reverse_dns(ip)
    if dns_name:
        return dns_name
    return _netbios_name(ip)


def _reverse_dns(ip: str) -> str:
    result: list[str] = []

    def resolve() -> None:
        try:
            name, _, _ = socket.gethostbyaddr(ip)
        except OSError:
            return
        cleaned = _clean_name(name)
        if cleaned and cleaned != ip:
            result.append(cleaned)

    thread = threading.Thread(target=resolve, daemon=True)
    thread.start()
    thread.join(1.0)
    return result[0] if result else ""


def _netbios_name(ip: str) -> str:
    query = _netbios_query()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.4)
    try:
        sock.sendto(query, (ip, 137))
        payload, _ = sock.recvfrom(1024)
    except OSError:
        return ""
    finally:
        sock.close()
    return parse_netbios_hostname(payload)


def _netbios_query() -> bytes:
    name = b"*" + (b"\x00" * 15)
    encoded = bytearray()
    for byte in name:
        encoded.append((byte >> 4) + 0x41)
        encoded.append((byte & 0x0F) + 0x41)
    question = bytes([len(encoded)]) + bytes(encoded) + b"\x00" + b"\x00\x21\x00\x01"
    return b"\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" + question


def _skip_name(payload: bytes, offset: int) -> int:
    while offset < len(payload):
        length = payload[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:
            return offset + 2
        offset += 1 + length
        if offset > len(payload):
            return len(payload)
    return offset


def _read_vendor_file(path: Path) -> dict[str, str]:
    vendors: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return {}
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        prefix, _, vendor = stripped.partition(" ")
        prefix = prefix.strip().upper()
        vendor = vendor.strip()
        if vendor and 6 <= len(prefix) <= 12 and all(character in "0123456789ABCDEF" for character in prefix):
            vendors[prefix] = vendor[:255]
    return vendors


def _format_mac(value: str) -> str:
    hex_chars = "".join(character for character in value if character.isalnum()).upper()
    if len(hex_chars) != 12 or any(character not in "0123456789ABCDEF" for character in hex_chars):
        return ""
    if hex_chars in {"000000000000", "FFFFFFFFFFFF"}:
        return ""
    return ":".join(hex_chars[index : index + 2] for index in range(0, 12, 2))


def _clean_name(value: str) -> str:
    name = value.strip().rstrip(".")
    if not name or "in-addr.arpa" in name.lower():
        return ""
    return name[:255]


def _private_ipv4(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return isinstance(address, ipaddress.IPv4Address) and address.is_private


def _is_gateway(ip: str, cidr: str) -> bool:
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if not isinstance(network, ipaddress.IPv4Network) or network.prefixlen > 30:
        return False
    return address == network.network_address + 1
