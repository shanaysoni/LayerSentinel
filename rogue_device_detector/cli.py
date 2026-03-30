from __future__ import annotations

import argparse
import functools
import http.server
import json
import socketserver
from pathlib import Path

from .analyzer import analyze_devices
from .baseline import DEFAULT_BASELINE_PATH, add_device, load_baseline, save_baseline
from .nmap_runner import NmapUnavailableError, parse_nmap_xml, run_nmap_scan
from .reporter import write_reports


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rogue-device-detector",
        description="Investigate rogue devices using Nmap scan results and a baseline of approved hosts.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init-baseline", help="Create an empty approved device baseline.")
    init_parser.add_argument("--baseline", default=str(DEFAULT_BASELINE_PATH))

    add_parser = subparsers.add_parser("add-device", help="Add an approved device to the baseline.")
    add_parser.add_argument("--name", required=True)
    add_parser.add_argument("--mac")
    add_parser.add_argument("--ip")
    add_parser.add_argument("--owner")
    add_parser.add_argument("--notes")
    add_parser.add_argument("--allowed-port", action="append", type=int, default=[])
    add_parser.add_argument("--baseline", default=str(DEFAULT_BASELINE_PATH))

    list_parser = subparsers.add_parser("list-devices", help="List approved devices from the baseline.")
    list_parser.add_argument("--baseline", default=str(DEFAULT_BASELINE_PATH))

    inv_parser = subparsers.add_parser(
        "investigate",
        help="Run Nmap or read an XML file, then compare devices against the baseline.",
    )
    inv_parser.add_argument("--targets", help='Nmap target range such as "192.168.1.0/24".')
    inv_parser.add_argument("--xml-input", help="Path to existing Nmap XML output.")
    inv_parser.add_argument("--baseline", default=str(DEFAULT_BASELINE_PATH))
    inv_parser.add_argument("--report-dir", default="reports")
    inv_parser.add_argument("--extra-arg", action="append", default=[], help="Extra Nmap argument.")

    serve_parser = subparsers.add_parser(
        "serve-dashboard",
        help="Serve generated reports and dashboards over a small local web server.",
    )
    serve_parser.add_argument("--report-dir", default="reports")
    serve_parser.add_argument("--port", type=int, default=8000)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "init-baseline":
        save_baseline([], args.baseline)
        print(f"Initialized baseline at {Path(args.baseline).resolve()}")
        return 0

    if args.command == "add-device":
        entry = add_device(
            name=args.name,
            mac=args.mac,
            ip=args.ip,
            owner=args.owner,
            notes=args.notes,
            allowed_ports=args.allowed_port,
            path=args.baseline,
        )
        print(json.dumps(entry.to_dict(), indent=2))
        return 0

    if args.command == "list-devices":
        devices = [device.to_dict() for device in load_baseline(args.baseline)]
        print(json.dumps(devices, indent=2))
        return 0

    if args.command == "investigate":
        if not args.targets and not args.xml_input:
            parser.error("investigate requires either --targets or --xml-input")
        if args.targets and args.xml_input:
            parser.error("investigate accepts only one of --targets or --xml-input")

        baseline_devices = load_baseline(args.baseline)

        try:
            scanned_devices = (
                parse_nmap_xml(args.xml_input)
                if args.xml_input
                else run_nmap_scan(args.targets, extra_args=args.extra_arg)
            )
        except NmapUnavailableError as exc:
            parser.exit(status=2, message=f"{exc}\n")

        analysis = analyze_devices(scanned_devices, baseline_devices)
        json_path, markdown_path, csv_path, html_path = write_reports(analysis, args.report_dir)

        print(json.dumps(analysis["summary"], indent=2))
        print(f"JSON report: {json_path.resolve()}")
        print(f"Markdown report: {markdown_path.resolve()}")
        print(f"CSV export: {csv_path.resolve()}")
        print(f"Dashboard: {html_path.resolve()}")
        return 0

    if args.command == "serve-dashboard":
        report_dir = Path(args.report_dir).resolve()
        report_dir.mkdir(parents=True, exist_ok=True)
        handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(report_dir))
        with socketserver.TCPServer(("127.0.0.1", args.port), handler) as server:
            print(f"Serving dashboard at http://127.0.0.1:{args.port}/")
            print(f"Report directory: {report_dir}")
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                print("\nServer stopped.")
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
