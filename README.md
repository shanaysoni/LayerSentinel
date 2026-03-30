# LayerSentinel

`LayerSentinel` is a Python project for investigating unauthorized devices on a local network. It uses Nmap for host discovery and service fingerprinting, compares scan results against an approved-device baseline, and produces investigation reports for unknown or suspicious hosts.

## What It Does

- Runs Nmap discovery scans against a target network range
- Parses Nmap XML output without third-party wrappers
- Tracks approved devices in a JSON baseline
- Flags hosts as `known`, `unknown`, or `suspicious`
- Generates JSON evidence, CSV exports, Markdown notes, and an HTML dashboard

## Project Structure

- `rogue_device_detector/cli.py` - command-line interface
- `rogue_device_detector/nmap_runner.py` - Nmap invocation and XML parsing
- `rogue_device_detector/analyzer.py` - rogue device classification logic
- `rogue_device_detector/baseline.py` - baseline storage helpers
- `rogue_device_detector/reporter.py` - JSON, CSV, Markdown, and HTML dashboard generation
- `tests/` - unit tests for scan analysis

## Install

```powershell
python -m pip install -r requirements.txt
python -m pip install -e .
```

`requirements.txt` installs the Python packages used by the project. The editable install registers the local app so the CLI commands work cleanly while you develop.

Nmap must also be installed and available on `PATH` for live scans:

- [Nmap download and docs](https://nmap.org/)

## Quick Start

1. Create a baseline file:

```powershell
python -m rogue_device_detector.cli init-baseline
```

2. Add approved devices:

```powershell
python -m rogue_device_detector.cli add-device --name "Office Laptop" --mac "AA:BB:CC:DD:EE:FF" --owner "Security Team"
python -m rogue_device_detector.cli add-device --name "Printer" --ip "192.168.1.50"
```

3. Run a live investigation scan:

```powershell
python -m rogue_device_detector.cli investigate --targets "192.168.1.0/24"
```

4. Or analyze an existing Nmap XML file:

```powershell
python -m rogue_device_detector.cli investigate --xml-input ".\sample_scan.xml"
```

Reports are written to `reports/` by default.

Each investigation now produces:

- a JSON evidence file for automation
- a CSV export for spreadsheets and SOC workflows
- a Markdown narrative report
- a polished HTML dashboard for browser review

## Detection Rules

The current scoring model marks hosts as more suspicious when they:

- are not present in the approved baseline
- expose open ports or services unexpectedly
- advertise hostnames that match risky keywords such as `rogue`, `unknown`, `freewifi`, or `hotspot`
- appear with a locally administered MAC address

This is a practical investigation aid, not a replacement for NAC, EDR, or dedicated wireless intrusion prevention systems.

## Example Commands

List baseline devices:

```powershell
python -m rogue_device_detector.cli list-devices
```

Change report directory:

```powershell
python -m rogue_device_detector.cli investigate --targets "10.0.0.0/24" --report-dir ".\output"
```

Serve the latest reports locally:

```powershell
python -m rogue_device_detector.cli serve-dashboard --report-dir ".\reports" --port 8000
```

## Run Tests

```powershell
python -m unittest discover -s tests -v
```
