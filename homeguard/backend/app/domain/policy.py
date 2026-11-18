"""Which IPv4 networks HomeGuard is willing to record.

A scope is accepted only when it is entirely inside one RFC 1918 block and
its prefix length is at least the configured floor (default /16). A lower
prefix length is a larger network, so /8 and /0 are rejected. The suggested
scan size for a single host is /24.
"""

from dataclasses import dataclass

import ipaddress

RFC1918_NETWORKS: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


class ScopeRejected(Exception):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)


@dataclass(frozen=True)
class ValidatedScope:
    network: ipaddress.IPv4Network
    host_bits_normalized: bool

    @property
    def cidr(self) -> str:
        return str(self.network)

    @property
    def prefix_length(self) -> int:
        return self.network.prefixlen

    @property
    def num_addresses(self) -> int:
        return self.network.num_addresses


def validate_cidr(cidr: str, *, largest_prefix_length: int = 16) -> ValidatedScope:
    raw = cidr.strip()
    if not raw:
        raise ScopeRejected("invalid_cidr", "Enter an IPv4 CIDR such as 192.168.1.0/24.")

    try:
        parsed = ipaddress.ip_network(raw, strict=False)
    except ValueError:
        raise ScopeRejected(
            "invalid_cidr",
            "Enter an IPv4 CIDR such as 192.168.1.0/24.",
        ) from None

    if not isinstance(parsed, ipaddress.IPv4Network):
        raise ScopeRejected(
            "ipv6_not_supported",
            "IPv6 targets are not part of this phase. Enter an IPv4 CIDR.",
        )

    if parsed.prefixlen < largest_prefix_length:
        raise ScopeRejected(
            "scope_too_large",
            f"The largest allowed network is /{largest_prefix_length}.",
        )

    if not any(parsed.subnet_of(block) for block in RFC1918_NETWORKS):
        raise ScopeRejected(
            "public_range",
            "Only RFC 1918 private ranges are allowed: "
            "10.0.0.0/8, 172.16.0.0/12, and 192.168.0.0/16.",
        )

    host_bits_normalized = _has_host_bits(raw)
    return ValidatedScope(network=parsed, host_bits_normalized=host_bits_normalized)


def propose_default_target(
    host: str,
    *,
    default_prefix_length: int = 24,
    largest_prefix_length: int = 16,
) -> ValidatedScope:
    raw = host.strip()
    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        raise ScopeRejected(
            "invalid_cidr",
            "Enter an IPv4 address.",
        ) from None

    if not isinstance(address, ipaddress.IPv4Address):
        raise ScopeRejected(
            "ipv6_not_supported",
            "IPv6 targets are not part of this phase. Enter an IPv4 address.",
        )

    network = ipaddress.ip_network(f"{address}/{default_prefix_length}", strict=False)
    return validate_cidr(str(network), largest_prefix_length=largest_prefix_length)


def _has_host_bits(raw: str) -> bool:
    try:
        ipaddress.ip_network(raw, strict=True)
    except ValueError:
        return True
    return False
