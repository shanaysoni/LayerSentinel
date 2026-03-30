from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass(slots=True)
class PortInfo:
    port: int
    protocol: str
    state: str
    service: str | None = None
    product: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(slots=True)
class ScanDevice:
    ip: str | None = None
    mac: str | None = None
    vendor: str | None = None
    hostname: str | None = None
    os_summary: str | None = None
    status: str = "up"
    ports: list[PortInfo] = field(default_factory=list)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["ports"] = [port.to_dict() for port in self.ports]
        return data


@dataclass(slots=True)
class BaselineDevice:
    name: str
    mac: str | None = None
    ip: str | None = None
    owner: str | None = None
    notes: str | None = None
    allowed_ports: list[int] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)
