# NIGHTTRACE

NIGHTTRACE is a hacker-style TCP reconnaissance console. It scans target hosts, detects open ports, guesses likely services, attempts lightweight banner grabbing, generates heuristic OS hints, exports JSON reports, and can run from a live browser dashboard.

## Identity

- Project name: `NIGHTTRACE`
- Interface style: `hacker-style`
- Documentation language: `English`

## Features

- Threaded TCP port scanning for fast host recon
- CIDR subnet sweeps with a safety limit on host expansion
- Service guessing from common ports and captured banners
- Lightweight banner grabbing for readable protocol clues
- Heuristic OS hints from service and port fingerprints
- Multi-target support through repeated or comma-separated `--target` values
- Clean terminal output for quick review
- JSON export for reporting and automation
- Live Flask dashboard that can launch scans from the browser

## Quick Start

Run with the project-local Python environment:

```powershell
.\.venv\Scripts\python.exe scanner.py --target 127.0.0.1 --ports 1-1024
```

Install the local environment if needed:

```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

Scan a single host:

```powershell
.\.venv\Scripts\python.exe scanner.py --target 192.168.1.1 --ports 1-1024
```

Scan multiple targets:

```powershell
.\.venv\Scripts\python.exe scanner.py --target 192.168.1.10,192.168.1.11 --target 10.0.0.5 --ports 22,80,443,8080
```

Sweep a subnet:

```powershell
.\.venv\Scripts\python.exe scanner.py --target 192.168.1.0/24 --ports 22,80,443 --host-workers 8 --max-hosts 256
```

Export JSON:

```powershell
.\.venv\Scripts\python.exe scanner.py --target 192.168.1.1 --ports 1-1000 --json-out scan-results\home-lab.scan.json
```

Launch the dashboard after a scan:

```powershell
.\.venv\Scripts\python.exe scanner.py --target 127.0.0.1 --ports 1-1024 --json-out scan-results\local.scan.json --dashboard
```

Launch the live dashboard directly:

```powershell
.\.venv\Scripts\python.exe scanner.py --live-dashboard
```

Open the dashboard from an existing report:

```powershell
.\.venv\Scripts\python.exe scanner.py --dashboard-from scan-results\local.scan.json
```

## CLI Options

```text
.\.venv\Scripts\python.exe scanner.py --target 192.168.1.1 --ports 1-1000 --workers 250 --host-workers 4 --timeout 0.5
```

- `--target`, `-t`: target IP or hostname, repeatable and comma-separated
- `--ports`, `-p`: ports or ranges such as `1-1024` or `22,80,443,8000-8100`
- `--workers`: number of port-scanning threads per target
- `--host-workers`: number of targets scanned in parallel during subnet sweeps
- `--max-hosts`: safety cap for CIDR subnet expansion
- `--timeout`: timeout per socket connection in seconds
- `--json-out`: write structured results to a JSON file
- `--dashboard`: launch the dashboard after scanning
- `--dashboard-from`: launch the dashboard from a previously exported JSON file
- `--live-dashboard`: launch the dashboard as an interactive scan console
- `--no-banner`: disable banner grabbing

## Portfolio Notes

- NIGHTTRACE uses TCP connect scanning, not raw-packet stealth scanning.
- OS fingerprinting is heuristic and intentionally lightweight.
- The dashboard is optional; the terminal scanner works on its own.
- The project identity is intentionally styled as a personal recon console rather than a generic classroom demo.

## Verification

Current local verification completed with:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe scanner.py --target 127.0.0.1/32 --ports 22,80 --host-workers 2 --no-banner
```
