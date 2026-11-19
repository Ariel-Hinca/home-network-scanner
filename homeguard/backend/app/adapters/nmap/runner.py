"""Run one discovery scan with a fixed Nmap argument list.

The caller supplies the binary, the already-checked CIDR, and the XML path.
Nothing in the request can add flags.
"""

from __future__ import annotations

import shutil
import subprocess
import threading
from collections.abc import Callable
from pathlib import Path

# Ports that common home devices answer on. This is how phase 1 notices a
# device. It is not a full port scan.
DISCOVERY_PORTS = "22,53,80,139,443,445,515,631,3000,5000,5357,8000,8080,8443,9100,62078"

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


def run_discovery(
    nmap_bin: str,
    cidr: str,
    xml_path: Path,
    cancel_event: threading.Event,
    timeout_seconds: int,
    on_process: Callable[[subprocess.Popen[bytes]], None] | None = None,
) -> str:
    """Return 'completed' or 'cancelled'. Raise NmapFailed when Nmap errors."""

    xml_path.parent.mkdir(parents=True, exist_ok=True)
    process = subprocess.Popen(
        build_discovery_args(nmap_bin, cidr, xml_path),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        shell=False,
    )
    if on_process is not None:
        on_process(process)
    try:
        deadline = timeout_seconds
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
                if waited >= deadline:
                    _stop_process(process)
                    raise NmapFailed("Discovery took too long and was stopped.")
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
