from __future__ import annotations

import argparse
from pathlib import Path
import sys

from signalscope import APP_NAME, APP_TAGLINE
from signalscope.core import (
    build_report_payload,
    empty_report_payload,
    export_json,
    load_json_report,
    parse_ports,
    parse_targets,
    scan_targets,
)
from signalscope.dashboard import launch_dashboard
from signalscope.formatters import format_reports


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scanner.py",
        description=(
            f"{APP_NAME} is a threaded TCP port scanner with banner grabbing, "
            f"CIDR subnet sweeps, OS hints, JSON export, and a live Flask dashboard. {APP_TAGLINE}"
        ),
    )
    parser.add_argument(
        "--target",
        "-t",
        action="append",
        help="Target IP or hostname. Repeat the flag or separate values with commas to scan multiple targets.",
    )
    parser.add_argument(
        "--ports",
        "-p",
        default="1-1024",
        help="Port specification such as 1-1024 or 22,80,443,8000-8100.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=0.8,
        help="Per-port socket timeout in seconds.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=200,
        help="Number of worker threads used per target during port scanning.",
    )
    parser.add_argument(
        "--host-workers",
        type=int,
        default=1,
        help="Number of targets scanned in parallel. Useful for subnet sweeps.",
    )
    parser.add_argument(
        "--max-hosts",
        type=int,
        default=256,
        help="Maximum number of hosts allowed when a CIDR subnet expands into many targets.",
    )
    parser.add_argument(
        "--json-out",
        help="Optional output path for a JSON scan report.",
    )
    parser.add_argument(
        "--dashboard",
        action="store_true",
        help="Launch the local Flask dashboard after the scan completes.",
    )
    parser.add_argument(
        "--dashboard-from",
        help="Load an existing JSON report and launch the dashboard without scanning.",
    )
    parser.add_argument(
        "--live-dashboard",
        action="store_true",
        help="Launch the dashboard as an interactive scan console, with or without an initial CLI scan.",
    )
    parser.add_argument(
        "--dashboard-host",
        default="127.0.0.1",
        help="Host interface for the dashboard server.",
    )
    parser.add_argument(
        "--dashboard-port",
        type=int,
        default=5000,
        help="Port for the dashboard server.",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Disable banner grabbing.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.dashboard_from:
        try:
            payload = load_json_report(args.dashboard_from)
        except FileNotFoundError:
            parser.error(f"dashboard report not found: {args.dashboard_from}")
        except ValueError as exc:
            parser.error(f"invalid dashboard report: {exc}")
        except OSError as exc:
            parser.error(str(exc))

        print(
            f"Launching dashboard from {Path(args.dashboard_from).resolve()} "
            f"at http://{args.dashboard_host}:{args.dashboard_port}"
        )
        try:
            launch_dashboard(payload, args.dashboard_host, args.dashboard_port)
        except RuntimeError as exc:
            parser.error(str(exc))
        return 0

    if args.timeout <= 0:
        parser.error("--timeout must be greater than 0")

    if args.workers <= 0:
        parser.error("--workers must be greater than 0")

    if args.host_workers <= 0:
        parser.error("--host-workers must be greater than 0")

    if args.max_hosts <= 0:
        parser.error("--max-hosts must be greater than 0")

    if args.live_dashboard and not args.target:
        payload = empty_report_payload(
            port_expression=args.ports,
            timeout=args.timeout,
            workers=args.workers,
            host_workers=args.host_workers,
            max_hosts=args.max_hosts,
            grab_banners=not args.no_banner,
        )
        print(f"Launching live dashboard at http://{args.dashboard_host}:{args.dashboard_port}")
        try:
            launch_dashboard(payload, args.dashboard_host, args.dashboard_port)
        except RuntimeError as exc:
            parser.error(str(exc))
        return 0

    if not args.target:
        parser.error("at least one --target value is required unless --dashboard-from is used")

    try:
        targets = parse_targets(args.target, max_hosts=args.max_hosts)
        ports = parse_ports(args.ports)
        reports = scan_targets(
            targets,
            ports,
            timeout=args.timeout,
            workers=args.workers,
            host_workers=args.host_workers,
            grab_banners=not args.no_banner,
        )
    except ValueError as exc:
        parser.error(str(exc))
        return 2

    payload = build_report_payload(
        reports,
        port_expression=args.ports,
        timeout=args.timeout,
        workers=args.workers,
        host_workers=args.host_workers,
        max_hosts=args.max_hosts,
        grab_banners=not args.no_banner,
    )

    print(
        format_reports(
            reports,
            port_expression=args.ports,
            timeout=args.timeout,
            workers=args.workers,
            host_workers=args.host_workers,
            show_banner=not args.no_banner,
        )
    )

    if args.json_out:
        output_path = export_json(payload, args.json_out)
        print(f"\nJSON report written to {output_path.resolve()}")

    if args.dashboard or args.live_dashboard:
        print(f"\nLaunching dashboard at http://{args.dashboard_host}:{args.dashboard_port}")
        try:
            launch_dashboard(payload, args.dashboard_host, args.dashboard_port)
        except RuntimeError as exc:
            parser.error(str(exc))

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
