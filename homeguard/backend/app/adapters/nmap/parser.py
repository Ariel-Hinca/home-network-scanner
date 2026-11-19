"""Read a discovery XML file into the devices that answered."""

from dataclasses import dataclass
from pathlib import Path
import xml.etree.ElementTree as ET


@dataclass(frozen=True)
class ObservedPort:
    port: int
    protocol: str
    state: str


@dataclass(frozen=True)
class DiscoveredHost:
    ip: str
    hostname: str
    ports: tuple[ObservedPort, ...] = ()


def parse_discovery_xml(path: Path) -> list[DiscoveredHost]:
    if not path.is_file():
        return []
    try:
        root = _root(path)
    except ValueError:
        if not path.is_file():
            return []
        raise

    found: list[DiscoveredHost] = []
    seen: set[str] = set()
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        if not _has_open_port(host):
            continue
        ip = _ipv4(host)
        if ip is None or ip in seen:
            continue
        seen.add(ip)
        found.append(DiscoveredHost(ip=ip, hostname=_hostname(host)))
    return found


def parse_port_scan_xml(path: Path) -> list[DiscoveredHost]:
    root = _root(path)
    found: list[DiscoveredHost] = []
    seen: set[str] = set()
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        ip = _ipv4(host)
        if ip is None or ip in seen:
            continue
        seen.add(ip)
        found.append(DiscoveredHost(ip=ip, hostname=_hostname(host), ports=tuple(_ports(host))))
    return found


def _root(path: Path) -> ET.Element:
    if not path.is_file():
        raise ValueError("Nmap did not write a result file.")
    try:
        return ET.parse(path).getroot()
    except ET.ParseError as exc:
        raise ValueError("Nmap did not write a readable result file.") from exc


def _ports(host: ET.Element) -> list[ObservedPort]:
    ports: list[ObservedPort] = []
    for port in host.findall("./ports/port"):
        protocol = port.get("protocol") or ""
        if protocol != "tcp":
            continue
        raw_port = port.get("portid")
        state = port.find("state")
        port_state = state.get("state") if state is not None else None
        if raw_port is None or port_state not in {"open", "closed", "filtered"}:
            continue
        ports.append(ObservedPort(port=int(raw_port), protocol="tcp", state=port_state))
    return ports


def _has_open_port(host: ET.Element) -> bool:
    for port in host.findall("./ports/port"):
        state = port.find("state")
        if state is not None and state.get("state") == "open":
            return True
    return False


def _ipv4(host: ET.Element) -> str | None:
    for address in host.findall("address"):
        if address.get("addrtype") == "ipv4" and address.get("addr"):
            return address.get("addr")
    return None


def _hostname(host: ET.Element) -> str:
    for hostname in host.findall("./hostnames/hostname"):
        name = (hostname.get("name") or "").strip()
        if name:
            return name[:255]
    return ""
