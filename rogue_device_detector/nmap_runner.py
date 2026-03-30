from __future__ import annotations

import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

from .baseline import normalize_mac
from .models import PortInfo, ScanDevice


DEFAULT_NMAP_ARGS = ["-sn", "-O", "-sV"]


class NmapUnavailableError(RuntimeError):
    """Raised when Nmap is not installed or not on PATH."""


def run_nmap_scan(targets: str, extra_args: list[str] | None = None) -> list[ScanDevice]:
    if shutil.which("nmap") is None:
        raise NmapUnavailableError(
            "Nmap is not installed or not available on PATH. Install it from https://nmap.org/."
        )

    command = ["nmap", *DEFAULT_NMAP_ARGS, *(extra_args or []), "-oX", "-", targets]
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "Nmap scan failed.")
    return parse_nmap_xml_text(result.stdout)


def parse_nmap_xml(xml_path: str | Path) -> list[ScanDevice]:
    return parse_nmap_xml_text(Path(xml_path).read_text(encoding="utf-8"))


def parse_nmap_xml_text(xml_text: str) -> list[ScanDevice]:
    root = ET.fromstring(xml_text)
    devices: list[ScanDevice] = []
    for host in root.findall("host"):
        status_node = host.find("status")
        status = status_node.get("state", "unknown") if status_node is not None else "unknown"

        ip = None
        mac = None
        vendor = None
        for address in host.findall("address"):
            addrtype = address.get("addrtype")
            if addrtype == "ipv4":
                ip = address.get("addr")
            elif addrtype == "mac":
                mac = normalize_mac(address.get("addr"))
                vendor = address.get("vendor")

        hostname = None
        hostname_node = host.find("hostnames/hostname")
        if hostname_node is not None:
            hostname = hostname_node.get("name")

        os_summary = None
        os_match = host.find("os/osmatch")
        if os_match is not None:
            os_summary = os_match.get("name")

        ports: list[PortInfo] = []
        for port in host.findall("ports/port"):
            state_node = port.find("state")
            service_node = port.find("service")
            ports.append(
                PortInfo(
                    port=int(port.get("portid", "0")),
                    protocol=port.get("protocol", "tcp"),
                    state=state_node.get("state", "unknown") if state_node is not None else "unknown",
                    service=service_node.get("name") if service_node is not None else None,
                    product=service_node.get("product") if service_node is not None else None,
                )
            )

        devices.append(
            ScanDevice(
                ip=ip,
                mac=mac,
                vendor=vendor,
                hostname=hostname,
                os_summary=os_summary,
                status=status or "unknown",
                ports=ports,
            )
        )
    return devices
