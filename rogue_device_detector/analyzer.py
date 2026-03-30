from __future__ import annotations

from .baseline import normalize_mac
from .models import BaselineDevice, ScanDevice

RISKY_HOSTNAME_KEYWORDS = ("rogue", "unknown", "guest", "freewifi", "hotspot", "temp")
SUSPICIOUS_SERVICES = {"telnet", "ftp", "vnc", "rdp", "ssh", "http", "https"}


def _is_locally_administered_mac(mac: str | None) -> bool:
    if not mac:
        return False
    first_octet = int(mac.split(":")[0], 16)
    return bool(first_octet & 0b10)


def _build_lookup(baseline_devices: list[BaselineDevice]) -> tuple[dict[str, BaselineDevice], dict[str, BaselineDevice]]:
    by_mac = {}
    by_ip = {}
    for device in baseline_devices:
        if device.mac:
            by_mac[normalize_mac(device.mac)] = device
        if device.ip:
            by_ip[device.ip] = device
    return by_mac, by_ip


def analyze_devices(
    scanned_devices: list[ScanDevice], baseline_devices: list[BaselineDevice]
) -> dict:
    baseline_by_mac, baseline_by_ip = _build_lookup(baseline_devices)
    findings = []

    for scanned in scanned_devices:
        matched = None
        if scanned.mac and normalize_mac(scanned.mac) in baseline_by_mac:
            matched = baseline_by_mac[normalize_mac(scanned.mac)]
        elif scanned.ip and scanned.ip in baseline_by_ip:
            matched = baseline_by_ip[scanned.ip]

        reasons: list[str] = []
        score = 0

        if matched is None:
            reasons.append("Device not found in approved baseline.")
            score += 45

        open_ports = [port for port in scanned.ports if port.state == "open"]
        if open_ports and matched is None:
            reasons.append(f"Host exposes {len(open_ports)} open port(s).")
            score += min(20, len(open_ports) * 5)

        if matched and matched.allowed_ports:
            observed_ports = {port.port for port in open_ports}
            unexpected_ports = sorted(observed_ports - set(matched.allowed_ports))
            if unexpected_ports:
                reasons.append(
                    f"Approved device has unexpected open ports: {', '.join(map(str, unexpected_ports))}."
                )
                score += min(25, len(unexpected_ports) * 8)

        if scanned.hostname and any(
            keyword in scanned.hostname.lower() for keyword in RISKY_HOSTNAME_KEYWORDS
        ):
            reasons.append("Hostname contains risky naming patterns.")
            score += 15

        suspicious_services = [
            port.service for port in open_ports if port.service in SUSPICIOUS_SERVICES
        ]
        if suspicious_services and matched is None:
            reasons.append(
                f"Unknown device exposes notable services: {', '.join(sorted(set(suspicious_services)))}."
            )
            score += 20

        if _is_locally_administered_mac(scanned.mac):
            reasons.append("MAC address is locally administered and may be randomized or spoofed.")
            score += 10

        classification = "known"
        if score >= 60:
            classification = "suspicious"
        elif score > 0:
            classification = "unknown"

        findings.append(
            {
                "device": scanned.to_dict(),
                "baseline_match": matched.to_dict() if matched else None,
                "classification": classification,
                "score": score,
                "reasons": reasons or ["No anomaly detected."],
            }
        )

    counts = {
        "known": sum(1 for item in findings if item["classification"] == "known"),
        "unknown": sum(1 for item in findings if item["classification"] == "unknown"),
        "suspicious": sum(1 for item in findings if item["classification"] == "suspicious"),
    }
    return {"summary": counts, "findings": findings}
