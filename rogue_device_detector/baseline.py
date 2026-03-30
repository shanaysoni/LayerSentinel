from __future__ import annotations

import json
from pathlib import Path

from .models import BaselineDevice

DEFAULT_BASELINE_PATH = Path("baseline") / "approved_devices.json"


def normalize_mac(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = value.replace("-", ":").upper()
    return cleaned


def load_baseline(path: str | Path = DEFAULT_BASELINE_PATH) -> list[BaselineDevice]:
    baseline_path = Path(path)
    if not baseline_path.exists():
        return []
    payload = json.loads(baseline_path.read_text(encoding="utf-8"))
    return [BaselineDevice(**item) for item in payload]


def save_baseline(
    devices: list[BaselineDevice], path: str | Path = DEFAULT_BASELINE_PATH
) -> Path:
    baseline_path = Path(path)
    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    baseline_path.write_text(
        json.dumps([device.to_dict() for device in devices], indent=2),
        encoding="utf-8",
    )
    return baseline_path


def add_device(
    name: str,
    mac: str | None = None,
    ip: str | None = None,
    owner: str | None = None,
    notes: str | None = None,
    allowed_ports: list[int] | None = None,
    path: str | Path = DEFAULT_BASELINE_PATH,
) -> BaselineDevice:
    devices = load_baseline(path)
    entry = BaselineDevice(
        name=name,
        mac=normalize_mac(mac),
        ip=ip,
        owner=owner,
        notes=notes,
        allowed_ports=allowed_ports or [],
    )
    devices.append(entry)
    save_baseline(devices, path)
    return entry
