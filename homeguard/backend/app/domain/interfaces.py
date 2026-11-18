"""Local IPv4 interfaces and the /24 HomeGuard would suggest for each."""

import socket
from dataclasses import dataclass

import psutil

from app.domain.policy import ScopeRejected, propose_default_target, validate_cidr


@dataclass(frozen=True)
class InterfaceView:
    name: str
    address: str
    netmask: str
    interface_cidr: str
    interface_allowed: bool
    suggested_scan_cidr: str | None
    detail: str | None


def list_scan_interfaces(
    *,
    largest_prefix_length: int,
    default_prefix_length: int,
) -> list[InterfaceView]:
    views: list[InterfaceView] = []
    for name, addresses in psutil.net_if_addrs().items():
        for addr in addresses:
            if addr.family != socket.AF_INET:
                continue
            if not addr.address or addr.address.startswith("127."):
                continue
            if not addr.netmask:
                continue
            views.append(
                _classify(
                    name=name,
                    address=addr.address,
                    netmask=addr.netmask,
                    largest_prefix_length=largest_prefix_length,
                    default_prefix_length=default_prefix_length,
                )
            )
    return views


def _classify(
    *,
    name: str,
    address: str,
    netmask: str,
    largest_prefix_length: int,
    default_prefix_length: int,
) -> InterfaceView:
    import ipaddress

    try:
        interface_network = ipaddress.ip_network(f"{address}/{netmask}", strict=False)
    except ValueError:
        return InterfaceView(
            name=name,
            address=address,
            netmask=netmask,
            interface_cidr="",
            interface_allowed=False,
            suggested_scan_cidr=None,
            detail="This interface address could not be parsed.",
        )

    interface_allowed = True
    details: list[str] = []
    try:
        validate_cidr(str(interface_network), largest_prefix_length=largest_prefix_length)
    except ScopeRejected as exc:
        interface_allowed = False
        details.append(exc.message)

    suggested: str | None = None
    try:
        suggested = propose_default_target(
            address,
            default_prefix_length=default_prefix_length,
            largest_prefix_length=largest_prefix_length,
        ).cidr
    except ScopeRejected as exc:
        details.append(exc.message)

    return InterfaceView(
        name=name,
        address=address,
        netmask=netmask,
        interface_cidr=str(interface_network),
        interface_allowed=interface_allowed,
        suggested_scan_cidr=suggested,
        detail=" ".join(details) or None,
    )
