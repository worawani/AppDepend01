from __future__ import annotations

import ipaddress
import re

_SPLIT = re.compile(r"[;,\s]+")
# RFC1918, CGNAT (often used for internal transit) and IPv6 ULA
_INTERNAL = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")]


def parse_ip(text: str):
    try:
        ip = ipaddress.ip_address(text.strip().split("%")[0])
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return ip.ipv4_mapped
    return ip


def split_ips(text: str | None) -> list[str]:
    """'10.0.0.1, 10.0.0.2;fe80::1' -> ['10.0.0.1', '10.0.0.2']. Drops link-local/loopback."""
    out = []
    for part in _SPLIT.split(text or ""):
        ip = parse_ip(part) if part else None
        if ip is None or ip.is_loopback or ip.is_link_local or ip.is_unspecified:
            continue
        out.append(str(ip))
    return out


def classify_ip(text: str) -> str:
    """Returns 'private', 'public', 'loopback', 'multicast', 'link-local' or 'invalid'."""
    ip = parse_ip(text)
    if ip is None:
        return "invalid"
    if ip.is_loopback:
        return "loopback"
    if ip.is_multicast:
        return "multicast"
    if ip.is_link_local:
        return "link-local"
    if any(ip.version == n.version and ip in n for n in _INTERNAL):
        return "private"
    # Other non-global space (documentation, benchmarking, reserved) is not routable on the internet either.
    return "public" if ip.is_global else "private"


class CidrTable:
    """Longest-prefix match of an IP against labelled networks."""

    def __init__(self):
        self._nets: list[tuple[ipaddress._BaseNetwork, object]] = []

    def add(self, cidr: str, value) -> None:
        self._nets.append((ipaddress.ip_network(cidr.strip(), strict=False), value))
        self._nets.sort(key=lambda nv: nv[0].prefixlen, reverse=True)

    def lookup(self, ip_text: str):
        ip = parse_ip(ip_text)
        if ip is None:
            return None
        for net, value in self._nets:
            if ip.version == net.version and ip in net:
                return value
        return None

    def __len__(self) -> int:
        return len(self._nets)
