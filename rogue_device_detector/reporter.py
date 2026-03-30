from __future__ import annotations

import csv
import json
from html import escape
from datetime import UTC, datetime
from pathlib import Path


def write_reports(
    analysis: dict, report_dir: str | Path = "reports"
) -> tuple[Path, Path, Path, Path]:
    target_dir = Path(report_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")

    json_path = target_dir / f"rogue_device_report_{timestamp}.json"
    markdown_path = target_dir / f"rogue_device_report_{timestamp}.md"
    csv_path = target_dir / f"rogue_device_report_{timestamp}.csv"
    html_path = target_dir / f"rogue_device_dashboard_{timestamp}.html"

    json_path.write_text(json.dumps(analysis, indent=2), encoding="utf-8")
    markdown_path.write_text(_render_markdown(analysis), encoding="utf-8")
    _write_csv(analysis, csv_path)
    html_path.write_text(_render_html_dashboard(analysis), encoding="utf-8")
    return json_path, markdown_path, csv_path, html_path


def load_report(report_path: str | Path) -> dict:
    return json.loads(Path(report_path).read_text(encoding="utf-8"))


def list_reports(report_dir: str | Path = "reports") -> list[Path]:
    target_dir = Path(report_dir)
    if not target_dir.exists():
        return []
    return sorted(target_dir.glob("rogue_device_report_*.json"), reverse=True)


def _render_markdown(analysis: dict) -> str:
    summary = analysis["summary"]
    lines = [
        "# Rogue Device Investigation Report",
        "",
        "## Summary",
        "",
        f"- Known devices: {summary['known']}",
        f"- Unknown devices: {summary['unknown']}",
        f"- Suspicious devices: {summary['suspicious']}",
        "",
        "## Findings",
        "",
    ]

    for index, finding in enumerate(analysis["findings"], start=1):
        device = finding["device"]
        lines.extend(
            [
                f"### Device {index}",
                "",
                f"- Classification: {finding['classification']}",
                f"- Score: {finding['score']}",
                f"- IP: {device.get('ip') or 'N/A'}",
                f"- MAC: {device.get('mac') or 'N/A'}",
                f"- Hostname: {device.get('hostname') or 'N/A'}",
                f"- Vendor: {device.get('vendor') or 'N/A'}",
                f"- OS: {device.get('os_summary') or 'N/A'}",
                "- Reasons:",
            ]
        )
        for reason in finding["reasons"]:
            lines.append(f"  - {reason}")
        lines.append("")

    return "\n".join(lines)


def _write_csv(analysis: dict, csv_path: Path) -> None:
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "classification",
                "score",
                "ip",
                "mac",
                "hostname",
                "vendor",
                "os_summary",
                "open_ports",
                "baseline_name",
                "owner",
                "reasons",
            ],
        )
        writer.writeheader()
        for finding in analysis["findings"]:
            device = finding["device"]
            baseline_match = finding["baseline_match"] or {}
            open_ports = [
                str(port["port"]) for port in device.get("ports", []) if port.get("state") == "open"
            ]
            writer.writerow(
                {
                    "classification": finding["classification"],
                    "score": finding["score"],
                    "ip": device.get("ip") or "",
                    "mac": device.get("mac") or "",
                    "hostname": device.get("hostname") or "",
                    "vendor": device.get("vendor") or "",
                    "os_summary": device.get("os_summary") or "",
                    "open_ports": ",".join(open_ports),
                    "baseline_name": baseline_match.get("name", ""),
                    "owner": baseline_match.get("owner", ""),
                    "reasons": " | ".join(finding["reasons"]),
                }
            )


def _render_html_dashboard(analysis: dict) -> str:
    summary = analysis["summary"]
    cards = [
        ("Known", summary["known"], "#2f855a"),
        ("Unknown", summary["unknown"], "#b7791f"),
        ("Suspicious", summary["suspicious"], "#c53030"),
    ]
    finding_rows = []
    finding_cards = []
    for finding in analysis["findings"]:
        device = finding["device"]
        classification = finding["classification"]
        score = finding["score"]
        reasons = "<br>".join(escape(reason) for reason in finding["reasons"])
        open_ports = ", ".join(
            escape(str(port["port"])) for port in device.get("ports", []) if port.get("state") == "open"
        ) or "None"
        finding_rows.append(
            f"""
            <tr>
              <td><span class="badge badge-{escape(classification)}">{escape(classification.title())}</span></td>
              <td>{score}</td>
              <td>{escape(device.get("ip") or "N/A")}</td>
              <td>{escape(device.get("hostname") or "N/A")}</td>
              <td>{escape(device.get("mac") or "N/A")}</td>
              <td>{escape(open_ports)}</td>
            </tr>
            """
        )
        finding_cards.append(
            f"""
            <article class="finding finding-{escape(classification)}">
              <div class="finding-header">
                <h3>{escape(device.get("hostname") or device.get("ip") or "Unknown Device")}</h3>
                <span class="badge badge-{escape(classification)}">{escape(classification.title())}</span>
              </div>
              <p class="meta">IP: {escape(device.get("ip") or "N/A")} | MAC: {escape(device.get("mac") or "N/A")} | Score: {score}</p>
              <p class="meta">Vendor: {escape(device.get("vendor") or "N/A")} | OS: {escape(device.get("os_summary") or "N/A")}</p>
              <p class="meta">Open ports: {escape(open_ports)}</p>
              <div class="reasons">{reasons}</div>
            </article>
            """
        )

    summary_html = "\n".join(
        f'<section class="summary-card"><h2>{escape(title)}</h2><p style="color:{escape(color)}">{count}</p></section>'
        for title, count, color in cards
    )
    findings_table = "\n".join(finding_rows) or "<tr><td colspan='6'>No findings</td></tr>"
    findings_html = "\n".join(finding_cards) or "<p>No findings available.</p>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Rogue Device Dashboard</title>
  <style>
    :root {{
      --bg: #f3efe6;
      --panel: #fffdf8;
      --ink: #1f2933;
      --muted: #52606d;
      --border: #d9cbb8;
      --known: #2f855a;
      --unknown: #b7791f;
      --suspicious: #c53030;
      --accent: #0f4c5c;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: Georgia, "Segoe UI", serif;
      color: var(--ink);
      background:
        radial-gradient(circle at top left, rgba(15, 76, 92, 0.14), transparent 28%),
        linear-gradient(135deg, #efe4d1, var(--bg));
    }}
    main {{ max-width: 1120px; margin: 0 auto; padding: 32px 20px 48px; }}
    .hero {{
      background: linear-gradient(135deg, rgba(15, 76, 92, 0.95), rgba(83, 37, 23, 0.88));
      color: #fffdf7;
      border-radius: 24px;
      padding: 28px;
      box-shadow: 0 24px 60px rgba(31, 41, 51, 0.18);
    }}
    .hero h1 {{ margin: 0 0 10px; font-size: clamp(2rem, 4vw, 3.5rem); }}
    .hero p {{ margin: 0; color: rgba(255, 253, 247, 0.85); max-width: 780px; }}
    .summary-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 16px;
      margin: 24px 0 32px;
    }}
    .summary-card, .table-panel, .findings-panel {{
      background: rgba(255, 253, 248, 0.92);
      border: 1px solid var(--border);
      border-radius: 18px;
      box-shadow: 0 12px 30px rgba(31, 41, 51, 0.08);
    }}
    .summary-card {{ padding: 18px 20px; }}
    .summary-card h2 {{ margin: 0; font-size: 0.95rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.08em; }}
    .summary-card p {{ margin: 8px 0 0; font-size: 2.2rem; font-weight: 700; }}
    .table-panel, .findings-panel {{ padding: 20px; margin-top: 20px; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ text-align: left; padding: 12px 10px; border-bottom: 1px solid #eadfce; }}
    th {{ font-size: 0.85rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.06em; }}
    .badge {{
      display: inline-block;
      padding: 6px 10px;
      border-radius: 999px;
      color: white;
      font-size: 0.8rem;
      font-weight: 700;
      letter-spacing: 0.03em;
    }}
    .badge-known {{ background: var(--known); }}
    .badge-unknown {{ background: var(--unknown); }}
    .badge-suspicious {{ background: var(--suspicious); }}
    .findings-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 16px;
    }}
    .finding {{
      border-radius: 18px;
      padding: 18px;
      background: var(--panel);
      border: 1px solid var(--border);
    }}
    .finding-known {{ border-left: 6px solid var(--known); }}
    .finding-unknown {{ border-left: 6px solid var(--unknown); }}
    .finding-suspicious {{ border-left: 6px solid var(--suspicious); }}
    .finding-header {{
      display: flex;
      gap: 12px;
      justify-content: space-between;
      align-items: start;
    }}
    .finding h3 {{ margin: 0 0 8px; font-size: 1.2rem; }}
    .meta {{ margin: 0 0 8px; color: var(--muted); }}
    .reasons {{
      margin-top: 12px;
      padding-top: 12px;
      border-top: 1px dashed var(--border);
      line-height: 1.5;
    }}
    @media (max-width: 700px) {{
      .hero {{ padding: 22px; }}
      th:nth-child(5), td:nth-child(5) {{ display: none; }}
    }}
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <p>Layer 1 Rogue Device Investigation</p>
      <h1>Network Findings Dashboard</h1>
      <p>Use this dashboard to triage scan results quickly, review suspicious hosts, and share a more polished summary than raw JSON alone.</p>
    </section>
    <section class="summary-grid">
      {summary_html}
    </section>
    <section class="table-panel">
      <h2>Device Table</h2>
      <table>
        <thead>
          <tr>
            <th>Classification</th>
            <th>Score</th>
            <th>IP</th>
            <th>Hostname</th>
            <th>MAC</th>
            <th>Open Ports</th>
          </tr>
        </thead>
        <tbody>
          {findings_table}
        </tbody>
      </table>
    </section>
    <section class="findings-panel">
      <h2>Analyst Notes</h2>
      <div class="findings-grid">
        {findings_html}
      </div>
    </section>
  </main>
</body>
</html>
"""
