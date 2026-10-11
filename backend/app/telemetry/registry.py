"""Parser registry. A new source = a new TelemetryParser subclass + one register() call.

Only the vendor-neutral canonical parsers are registered. Vendor parsers (firewall logs, VDS IPFIX
collector exports, ...) are added only after the real source and a sanitized sample are confirmed."""

from __future__ import annotations

from ..importers.common import FileError
from .base import TelemetryParser
from .canonical import CanonicalAddressCsv, CanonicalFlowCsv

_REGISTRY: dict[str, type[TelemetryParser]] = {}


def register(parser_cls: type[TelemetryParser]) -> type[TelemetryParser]:
    name = parser_cls.info.name
    if name in _REGISTRY and _REGISTRY[name] is not parser_cls:
        raise ValueError(f"Parser '{name}' is already registered.")
    _REGISTRY[name] = parser_cls
    return parser_cls


def get_parser(name: str) -> TelemetryParser:
    cls = _REGISTRY.get(name)
    if cls is None:
        raise FileError("unsupported_format", f"Unsupported source format '{name}'. Supported: {', '.join(sorted(_REGISTRY))}.")
    return cls()


def list_parsers() -> list[type[TelemetryParser]]:
    return [_REGISTRY[k] for k in sorted(_REGISTRY)]


register(CanonicalFlowCsv)
register(CanonicalAddressCsv)
