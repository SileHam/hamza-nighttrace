from __future__ import annotations

from signalscope import APP_AUTHOR, APP_TAGLINE, APP_NAME, __version__
from signalscope.core import TargetReport


def format_reports(
    reports: list[TargetReport],
    *,
    port_expression: str,
    timeout: float,
    workers: int,
    host_workers: int,
    show_banner: bool,
) -> str:
    total_open_ports = sum(report.open_port_count for report in reports)
    lines = [
        f"{APP_NAME} v{__version__} :: hacker-style TCP recon console",
        f"Operator: {APP_AUTHOR} | {APP_TAGLINE}",
        (
            f"Targets: {len(reports)} | Open ports: {total_open_ports} | Ports: {port_expression} "
            f"| Timeout: {timeout:.2f}s | Port workers: {workers} | Host workers: {host_workers}"
        ),
        "",
    ]

    for index, report in enumerate(reports, start=1):
        header = f"[{index}] Target {report.target}"
        if report.resolved_ip:
            header += f" ({report.resolved_ip})"
        lines.append(header)

        if report.error:
            lines.append(f"Resolution error: {report.error}")
        elif not report.findings:
            lines.append(_format_os_hint(report))
            lines.append(
                f"No open TCP ports found across {report.scanned_ports} scanned ports in {report.duration_ms:.2f} ms."
            )
        else:
            lines.append(
                f"Open ports: {report.open_port_count} / {report.scanned_ports} | Duration: {report.duration_ms:.2f} ms"
            )
            lines.append(_format_os_hint(report))
            headers = ["PORT", "STATE", "SERVICE", "LATENCY"]
            rows = [
                [
                    str(finding.port),
                    finding.state,
                    finding.service,
                    f"{finding.latency_ms:.2f} ms",
                ]
                for finding in report.findings
            ]
            if show_banner:
                headers.append("BANNER")
                for row, finding in zip(rows, report.findings, strict=True):
                    row.append(_truncate(finding.banner or "-", 54))

            lines.append(_render_table(headers, rows))

        if index != len(reports):
            lines.append("")

    return "\n".join(lines).rstrip()


def _render_table(headers: list[str], rows: list[list[str]]) -> str:
    widths = [len(header) for header in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))

    def render_row(values: list[str]) -> str:
        return "  ".join(value.ljust(widths[index]) for index, value in enumerate(values))

    divider = "  ".join("-" * width for width in widths)
    rendered_rows = [render_row(headers), divider]
    rendered_rows.extend(render_row(row) for row in rows)
    return "\n".join(rendered_rows)


def _truncate(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return f"{value[: limit - 3]}..."


def _format_os_hint(report: TargetReport) -> str:
    line = f"OS hint: {report.os_family} ({report.os_confidence} confidence)"
    if report.os_evidence:
        line += f" via {', '.join(report.os_evidence)}"
    return line
