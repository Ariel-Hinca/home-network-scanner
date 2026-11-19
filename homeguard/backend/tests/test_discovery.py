from pathlib import Path

from app.adapters.nmap.parser import parse_discovery_xml, parse_port_scan_xml
from app.adapters.nmap.runner import COMMON_TCP_PORTS, build_discovery_args, build_port_scan_args
from app.domain.policy import ScopeRejected, assert_scan_size


def test_discovery_args_stay_fixed() -> None:
    args = build_discovery_args("nmap", "192.168.1.0/24", Path("out.xml"))
    assert args[0] == "nmap"
    assert args[-1] == "192.168.1.0/24"
    assert "-sT" in args
    assert "--open" in args
    assert "--script" not in args
    joined = " ".join(args)
    assert "&" not in joined
    assert "|" not in joined


def test_port_scan_args_are_fixed() -> None:
    args = build_port_scan_args("nmap", ["192.168.1.20", "192.168.1.21"], Path("ports.xml"))
    assert args[0] == "nmap"
    assert args[-2:] == ["192.168.1.20", "192.168.1.21"]
    assert "-sT" in args
    assert "--script" not in args
    assert COMMON_TCP_PORTS in args
    assert len(COMMON_TCP_PORTS.split(",")) == 100


def test_port_parser_keeps_open_closed_and_filtered(tmp_path: Path) -> None:
    xml_path = tmp_path / "ports.xml"
    xml_path.write_text(
        """<?xml version="1.0"?>
        <nmaprun>
          <host>
            <status state="up"/>
            <address addr="192.168.1.20" addrtype="ipv4"/>
            <ports>
              <port protocol="tcp" portid="80"><state state="open"/></port>
              <port protocol="tcp" portid="23"><state state="closed"/></port>
              <port protocol="tcp" portid="445"><state state="filtered"/></port>
            </ports>
          </host>
        </nmaprun>
        """,
        encoding="utf-8",
    )
    found = parse_port_scan_xml(xml_path)
    assert found[0].ip == "192.168.1.20"
    assert [(port.port, port.state) for port in found[0].ports] == [(80, "open"), (23, "closed"), (445, "filtered")]


def test_parser_keeps_hosts_with_an_open_port(tmp_path: Path) -> None:
    xml_path = tmp_path / "sample.xml"
    xml_path.write_text(
        """<?xml version="1.0"?>
        <nmaprun>
          <host>
            <status state="up"/>
            <address addr="192.168.1.5" addrtype="ipv4"/>
            <hostnames><hostname name="printer.home"/></hostnames>
            <ports><port protocol="tcp" portid="9100"><state state="open"/></port></ports>
          </host>
          <host>
            <status state="up"/>
            <address addr="192.168.1.6" addrtype="ipv4"/>
            <ports><port protocol="tcp" portid="80"><state state="closed"/></port></ports>
          </host>
        </nmaprun>
        """,
        encoding="utf-8",
    )
    found = parse_discovery_xml(xml_path)
    assert [(host.ip, host.hostname) for host in found] == [("192.168.1.5", "printer.home")]


def test_scan_size_rejects_a_16() -> None:
    try:
        assert_scan_size(16)
    except ScopeRejected as exc:
        assert exc.code == "scan_scope_too_large"
    else:
        raise AssertionError("a /16 was accepted for discovery")


def test_scan_size_accepts_a_24() -> None:
    assert_scan_size(24)
    assert_scan_size(32)
