"""Run one discovery scan with a fixed Nmap argument list.

The caller supplies the binary, the already-checked CIDR, and the XML path.
Nothing in the request can add flags.
"""

from __future__ import annotations

import ipaddress
import shutil
import subprocess
import threading
from collections.abc import Callable
from pathlib import Path

# Ports that common home devices answer on. This is how phase 1 notices a
# device. It is not a full port scan.
DISCOVERY_PORTS = "22,53,80,139,443,445,515,631,3000,5000,5357,8000,8080,8443,9100,62078"
# A fixed defensive list. Requests cannot add or replace these ports.
COMMON_TCP_PORTS = (
    "20,21,22,23,25,26,53,69,80,81,110,111,113,123,135,139,143,161,179,199,"
    "389,443,445,465,514,515,543,544,548,554,587,593,631,636,646,873,990,993,995,"
    "1025,1026,1027,1028,1029,1080,1110,1433,1434,1521,1720,1723,1755,1900,2000,2001,"
    "2049,2121,2222,2375,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5061,"
    "5101,5190,5357,5432,5631,5666,5800,5900,6000,6001,6646,7070,8000,8008,8009,8080,"
    "8081,8443,8888,9100,9999,10000,32768,49152,49153,49154,49155,49156,49157"
)

_WINDOWS_CANDIDATES = (
    Path(r"C:\Program Files (x86)\Nmap\nmap.exe"),
    Path(r"C:\Program Files\Nmap\nmap.exe"),
)


class NmapFailed(Exception):
    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


def find_nmap(configured_path: str = "") -> str | None:
    raw = configured_path.strip()
    if raw:
        candidate = Path(raw)
        if candidate.is_file():
            return str(candidate)
        return None
    found = shutil.which("nmap")
    if found:
        return found
    for candidate in _WINDOWS_CANDIDATES:
        if candidate.is_file():
            return str(candidate)
    return None


def build_discovery_args(nmap_bin: str, cidr: str, xml_path: Path) -> list[str]:
    return [
        nmap_bin,
        "-sT",
        "-Pn",
        "-n",
        "-T3",
        "--max-retries",
        "1",
        "--host-timeout",
        "10s",
        "-p",
        DISCOVERY_PORTS,
        "--open",
        "-oX",
        str(xml_path),
        cidr,
    ]


def build_port_scan_args(nmap_bin: str, ips: list[str], xml_path: Path) -> list[str]:
    targets = [_require_ipv4(ip) for ip in ips]
    if not targets:
        raise NmapFailed("There are no devices to check.")
    return [
        nmap_bin,
        "-sT",
        "-Pn",
        "-n",
        "-T3",
        "--max-retries",
        "1",
        "--host-timeout",
        "15s",
        "-p",
        COMMON_TCP_PORTS,
        "-oX",
        str(xml_path),
        *targets,
    ]


def run_port_scan(
    nmap_bin: str,
    ips: list[str],
    xml_path: Path,
    cancel_event: threading.Event,
    timeout_seconds: int,
) -> str:
    return _run(
        build_port_scan_args(nmap_bin, ips, xml_path),
        xml_path,
        cancel_event,
        timeout_seconds,
    )


def _require_ipv4(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise NmapFailed("A saved device address was not a valid IPv4 address.") from exc
    if not isinstance(address, ipaddress.IPv4Address):
        raise NmapFailed("Only IPv4 devices can be checked in this phase.")
    return str(address)


def run_discovery(
    nmap_bin: str,
    cidr: str,
    xml_path: Path,
    cancel_event: threading.Event,
    timeout_seconds: int,
    on_process: Callable[[subprocess.Popen[bytes]], None] | None = None,
) -> str:
    """Return 'completed' or 'cancelled'. Raise NmapFailed when Nmap errors."""

    return _run(
        build_discovery_args(nmap_bin, cidr, xml_path),
        xml_path,
        cancel_event,
        timeout_seconds,
        on_process,
    )


def _run(
    args: list[str],
    xml_path: Path,
    cancel_event: threading.Event,
    timeout_seconds: int,
    on_process: Callable[[subprocess.Popen[bytes]], None] | None = None,
) -> str:
    xml_path.parent.mkdir(parents=True, exist_ok=True)
    process = subprocess.Popen(
        args,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        shell=False,
    )
    if on_process is not None:
        on_process(process)
    try:
        waited = 0.0
        while True:
            if cancel_event.is_set():
                _stop_process(process)
                return "cancelled"
            try:
                process.wait(timeout=0.4)
                break
            except subprocess.TimeoutExpired:
                waited += 0.4
                if waited >= timeout_seconds:
                    _stop_process(process)
                    raise NmapFailed("The check took too long and was stopped.")
        if process.returncode != 0:
            error = ""
            if process.stderr is not None:
                error = process.stderr.read().decode("utf-8", errors="replace").strip()
            detail = error or f"Nmap exited with code {process.returncode}."
            raise NmapFailed(detail[:500])
        return "completed"
    finally:
        if process.stderr is not None:
            process.stderr.close()


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.kill()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass
