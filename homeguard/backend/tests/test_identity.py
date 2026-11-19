from pathlib import Path

from app.adapters.identity import (
    apply_identity,
    device_kind,
    load_vendors,
    parse_arp_table,
    parse_netbios_hostname,
    vendor_for,
)
from app.adapters.nmap.parser import DiscoveredHost


def test_arp_table_keeps_private_addresses() -> None:
    text = """
    Interface: 192.168.1.10 --- 0xc
      192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic
      192.168.1.255         ff-ff-ff-ff-ff-ff     static
      8.8.8.8               11-22-33-44-55-66     dynamic
    """
    assert parse_arp_table(text) == {"192.168.1.1": "AA:BB:CC:DD:EE:FF"}


def test_apply_identity_fills_a_missing_name_and_keeps_a_known_one() -> None:
    hosts = [
        DiscoveredHost(ip="192.168.1.20", hostname=""),
        DiscoveredHost(ip="192.168.1.30", hostname="laptop.home"),
    ]
    named = apply_identity(
        hosts,
        arp={"192.168.1.20": "AA:BB:CC:00:00:01"},
        vendors={"AABBCC": "Petkit"},
        names={"192.168.1.20": "feeder.home", "192.168.1.30": "other.home"},
    )
    assert (named[0].hostname, named[0].vendor, named[0].mac) == (
        "feeder.home",
        "Petkit",
        "AA:BB:CC:00:00:01",
    )
    assert named[1].hostname == "laptop.home"


def test_vendor_file_matches_the_company_prefix(tmp_path: Path) -> None:
    binary = tmp_path / "nmap.exe"
    binary.write_text("", encoding="utf-8")
    (tmp_path / "nmap-mac-prefixes").write_text(
        "# comment\nAABBCC Example Cameras\nAABBCC00 More Specific\n",
        encoding="utf-8",
    )
    vendors = load_vendors(str(binary))
    assert vendor_for("AA:BB:CC:00:11:22", vendors) == "More Specific"
    assert vendor_for("AA:BB:CC:10:11:22", vendors) == "Example Cameras"


def test_device_kind_uses_the_gateway_and_distinctive_ports() -> None:
    assert device_kind("192.168.1.1", "192.168.1.0/24", {80, 443}) == "router"
    assert device_kind("192.168.1.50", "192.168.1.0/24", {554, 80}) == "camera"
    assert device_kind("192.168.1.40", "192.168.1.0/24", {9100}) == "printer"
    assert device_kind("192.168.1.41", "192.168.1.0/24", {8009}) == "tv"
    assert device_kind("192.168.1.42", "192.168.1.0/24", {445}) == "computer"
    assert device_kind("192.168.1.43", "192.168.1.0/24", {62078}) == "apple"
    assert device_kind("192.168.1.44", "192.168.1.0/24", {80}) == ""


def test_netbios_hostname_reads_the_computer_name() -> None:
    encoded = bytes([32]) + b"CK" + (b"AA" * 15) + b"\x00"
    question = encoded + b"\x00\x21\x00\x01"
    header = b"\x00\x01\x84\x00\x00\x01\x00\x01\x00\x00\x00\x00"
    answer_name = b"\xc0\x0c"
    rdata = bytes([1]) + b"LAPTOP".ljust(15) + bytes([0x00, 0x00, 0x00])
    meta = b"\x00\x21\x00\x01" + b"\x00\x00\x00\x00" + len(rdata).to_bytes(2, "big")
    payload = header + question + answer_name + meta + rdata
    assert parse_netbios_hostname(payload) == "LAPTOP"
