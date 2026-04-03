from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
import ipaddress
import json
import socket

from signalscope import APP_AUTHOR, APP_CODENAME, APP_GITHUB_HANDLE, APP_NAME, APP_THEME, __version__

COMMON_SERVICE_PORTS = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    119: "NNTP",
    123: "NTP",
    135: "MSRPC",
    139: "NETBIOS-SSN",
    143: "IMAP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SUBMISSION",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "ORACLE",
    1723: "PPTP",
    2049: "NFS",
    3306: "MYSQL",
    3389: "RDP",
    5432: "POSTGRESQL",
    5900: "VNC",
    6379: "REDIS",
    8000: "HTTP-ALT",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
    9000: "HTTP-ALT",
}

HTTP_PROBE_PORTS = {80, 81, 591, 8000, 8080, 8081, 8888, 9000}
ACTIVE_PROBES = {
    25: b"EHLO nighttrace.local\r\n",
    110: b"CAPA\r\n",
    143: b"a1 CAPABILITY\r\n",
    6379: b"PING\r\n",
}


@dataclass(slots=True)
class PortFinding:
    port: int
    state: str
    service: str
    latency_ms: float
    banner: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "port": self.port,
            "state": self.state,
            "service": self.service,
            "latency_ms": self.latency_ms,
            "banner": self.banner,
        }


@dataclass(slots=True)
class TargetReport:
    target: str
    resolved_ip: str | None
    scanned_ports: int
    duration_ms: float
    started_at: str
    findings: list[PortFinding] = field(default_factory=list)
    error: str | None = None
    os_family: str = "Unknown"
    os_confidence: str = "low"
    os_evidence: list[str] = field(default_factory=list)

    @property
    def open_port_count(self) -> int:
        return len(self.findings)

    def to_dict(self) -> dict[str, object]:
        return {
            "target": self.target,
            "resolved_ip": self.resolved_ip,
            "scanned_ports": self.scanned_ports,
            "open_port_count": self.open_port_count,
            "duration_ms": self.duration_ms,
            "started_at": self.started_at,
            "error": self.error,
            "os_hint": {
                "family": self.os_family,
                "confidence": self.os_confidence,
                "evidence": self.os_evidence,
            },
            "findings": [finding.to_dict() for finding in self.findings],
        }


def parse_targets(target_specs: list[str], *, max_hosts: int = 256) -> list[str]:
    raw_targets: list[str] = []
    for spec in target_specs:
        for item in spec.split(","):
            candidate = item.strip()
            if candidate:
                raw_targets.extend(_expand_target_spec(candidate, max_hosts))

    if not raw_targets:
        raise ValueError("at least one target must be provided")

    unique_targets: list[str] = []
    seen: set[str] = set()
    for target in raw_targets:
        if target not in seen:
            seen.add(target)
            unique_targets.append(target)
    return unique_targets


def parse_ports(port_expression: str) -> list[int]:
    if not port_expression or not port_expression.strip():
        raise ValueError("port expression cannot be empty")

    ports: set[int] = set()

    for chunk in port_expression.split(","):
        part = chunk.strip()
        if not part:
            continue

        if "-" in part:
            start_text, end_text = part.split("-", 1)
            start_port = _parse_single_port(start_text)
            end_port = _parse_single_port(end_text)
            if start_port > end_port:
                raise ValueError(f"invalid port range: {part}")
            ports.update(range(start_port, end_port + 1))
            continue

        ports.add(_parse_single_port(part))

    if not ports:
        raise ValueError("no valid ports were provided")

    return sorted(ports)


def guess_service_name(port: int, banner: str = "") -> str:
    normalized = banner.lower()

    service_signatures = {
        "ssh": "SSH",
        "smtp": "SMTP",
        "imap": "IMAP",
        "pop3": "POP3",
        "mysql": "MYSQL",
        "postgres": "POSTGRESQL",
        "redis": "REDIS",
        "rdp": "RDP",
        "ftp": "FTP",
        "telnet": "TELNET",
        "ldap": "LDAP",
    }

    for marker, service_name in service_signatures.items():
        if marker in normalized:
            return service_name

    if "http/" in normalized or "server:" in normalized or "html" in normalized:
        return "HTTPS" if port in {443, 8443} else "HTTP"

    return COMMON_SERVICE_PORTS.get(port, "UNKNOWN")


def scan_targets(
    targets: list[str],
    ports: list[int],
    *,
    timeout: float,
    workers: int,
    host_workers: int,
    grab_banners: bool,
) -> list[TargetReport]:
    if host_workers <= 1 or len(targets) <= 1:
        return [
            scan_target(
                target,
                ports,
                timeout=timeout,
                workers=workers,
                grab_banners=grab_banners,
            )
            for target in targets
        ]

    ordered_reports: list[TargetReport | None] = [None] * len(targets)
    max_target_workers = max(1, min(host_workers, len(targets)))

    with ThreadPoolExecutor(max_workers=max_target_workers) as executor:
        future_map = {
            executor.submit(
                scan_target,
                target,
                ports,
                timeout=timeout,
                workers=workers,
                grab_banners=grab_banners,
            ): index
            for index, target in enumerate(targets)
        }
        for future in as_completed(future_map):
            ordered_reports[future_map[future]] = future.result()

    return [report for report in ordered_reports if report is not None]


def scan_target(
    target: str,
    ports: list[int],
    *,
    timeout: float,
    workers: int,
    grab_banners: bool,
) -> TargetReport:
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        resolved_ip = socket.gethostbyname(target)
    except socket.gaierror as exc:
        return TargetReport(
            target=target,
            resolved_ip=None,
            scanned_ports=len(ports),
            duration_ms=0.0,
            started_at=started_at,
            error=str(exc),
        )

    findings: list[PortFinding] = []
    started = perf_counter()
    max_workers = max(1, min(workers, len(ports)))

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {
            executor.submit(
                _scan_single_port,
                resolved_ip,
                port,
                timeout,
                grab_banners,
            ): port
            for port in ports
        }
        for future in as_completed(future_map):
            result = future.result()
            if result is not None:
                findings.append(result)

    findings.sort(key=lambda finding: finding.port)
    duration_ms = round((perf_counter() - started) * 1000, 2)
    os_family, os_confidence, os_evidence = infer_os_hint(findings)
    return TargetReport(
        target=target,
        resolved_ip=resolved_ip,
        scanned_ports=len(ports),
        duration_ms=duration_ms,
        started_at=started_at,
        findings=findings,
        os_family=os_family,
        os_confidence=os_confidence,
        os_evidence=os_evidence,
    )


def infer_os_hint(findings: list[PortFinding]) -> tuple[str, str, list[str]]:
    if not findings:
        return "Unknown", "low", []

    open_ports = {finding.port for finding in findings}
    banners = " ".join(finding.banner.lower() for finding in findings if finding.banner)
    scores = {
        "Windows": 0,
        "Linux/Unix": 0,
        "Network Appliance": 0,
    }
    evidence = {family: [] for family in scores}

    def add_signal(family: str, points: int, reason: str) -> None:
        scores[family] += points
        if reason not in evidence[family]:
            evidence[family].append(reason)

    if open_ports & {135, 139, 445}:
        add_signal("Windows", 4, "SMB/MSRPC-style ports are open")
    if 3389 in open_ports:
        add_signal("Windows", 4, "RDP is exposed")
    if any(finding.service in {"MSRPC", "SMB", "RDP"} for finding in findings):
        add_signal("Windows", 2, "Windows-oriented services were identified")
    if any(token in banners for token in ("microsoft", "winrm", "iis")):
        add_signal("Windows", 3, "A Microsoft-flavoured banner was captured")

    if 22 in open_ports:
        add_signal("Linux/Unix", 2, "SSH is open")
    if open_ports & {111, 2049}:
        add_signal("Linux/Unix", 4, "RPC/NFS ports are open")
    if any(finding.service in {"MYSQL", "POSTGRESQL", "REDIS", "NFS"} for finding in findings):
        add_signal("Linux/Unix", 2, "Common Unix-hosted services were identified")
    if any(token in banners for token in ("openssh", "ubuntu", "debian", "centos", "unix")):
        add_signal("Linux/Unix", 3, "A Unix-flavoured banner was captured")

    web_ports = open_ports & {80, 443, 8080, 8443, 8000, 8888, 9000}
    if 23 in open_ports:
        add_signal("Network Appliance", 3, "Telnet management is exposed")
    if web_ports and not open_ports & {135, 3389, 445}:
        add_signal("Network Appliance", 2, "Web management ports are open without desktop OS ports")
    if any(token in banners for token in ("routeros", "mikrotik", "ubiquiti", "cisco", "busybox", "lighttpd")):
        add_signal("Network Appliance", 4, "An embedded-device banner was captured")

    ranked_scores = sorted(scores.items(), key=lambda item: item[1], reverse=True)
    best_family, best_score = ranked_scores[0]
    second_score = ranked_scores[1][1]

    if best_score == 0:
        return "Unknown", "low", []

    if best_score - second_score <= 1 and best_score < 5:
        merged_evidence: list[str] = []
        for family, _score in ranked_scores[:2]:
            for reason in evidence[family]:
                if reason not in merged_evidence:
                    merged_evidence.append(reason)
        return "Mixed/Heuristic", "low", merged_evidence[:3]

    confidence = "low"
    if best_score >= 7 and best_score - second_score >= 3:
        confidence = "high"
    elif best_score >= 4:
        confidence = "medium"

    return best_family, confidence, evidence[best_family][:3]


def build_report_payload(
    reports: list[TargetReport],
    *,
    port_expression: str,
    timeout: float,
    workers: int,
    host_workers: int,
    max_hosts: int,
    grab_banners: bool,
) -> dict[str, object]:
    total_open_ports = sum(report.open_port_count for report in reports)
    payload = empty_report_payload(
        port_expression=port_expression,
        timeout=timeout,
        workers=workers,
        host_workers=host_workers,
        max_hosts=max_hosts,
        grab_banners=grab_banners,
    )
    payload["scan"]["target_count"] = len(reports)
    payload["scan"]["total_open_ports"] = total_open_ports
    payload["reports"] = [report.to_dict() for report in reports]
    return payload


def empty_report_payload(
    *,
    port_expression: str = "1-1024",
    timeout: float = 0.8,
    workers: int = 200,
    host_workers: int = 1,
    max_hosts: int = 256,
    grab_banners: bool = True,
) -> dict[str, object]:
    return {
        "scanner": {
            "name": APP_NAME,
            "codename": APP_CODENAME,
            "operator": APP_AUTHOR,
            "github_handle": APP_GITHUB_HANDLE,
            "theme": APP_THEME,
            "version": __version__,
            "mode": "tcp-connect",
        },
        "scan": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "target_count": 0,
            "total_open_ports": 0,
            "port_expression": port_expression,
            "timeout_seconds": timeout,
            "workers": workers,
            "host_workers": host_workers,
            "max_hosts": max_hosts,
            "banner_grabbing": grab_banners,
        },
        "reports": [],
    }


def export_json(payload: dict[str, object], destination: str | Path) -> Path:
    output_path = Path(destination)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return output_path


def load_json_report(source: str | Path) -> dict[str, object]:
    source_path = Path(source)
    return normalize_report_payload(json.loads(source_path.read_text(encoding="utf-8")))


def normalize_report_payload(payload: dict[str, object]) -> dict[str, object]:
    normalized = empty_report_payload()
    normalized.update(payload)
    normalized_scanner = normalized["scanner"]
    normalized_scanner.update(payload.get("scanner", {}))
    normalized["scanner"] = normalized_scanner

    normalized_scan = normalized["scan"]
    normalized_scan.update(payload.get("scan", {}))
    normalized["scan"] = normalized_scan

    reports = payload.get("reports", [])
    normalized_reports: list[dict[str, object]] = []
    for raw_report in reports:
        report = dict(raw_report)
        report.setdefault("findings", [])
        report.setdefault("open_port_count", len(report["findings"]))
        report.setdefault("error", None)
        os_hint = dict(report.get("os_hint", {}))
        os_hint.setdefault("family", "Unknown")
        os_hint.setdefault("confidence", "low")
        os_hint.setdefault("evidence", [])
        report["os_hint"] = os_hint
        normalized_reports.append(report)

    normalized["reports"] = normalized_reports
    return normalized


def _parse_single_port(port_text: str) -> int:
    try:
        port = int(port_text)
    except ValueError as exc:
        raise ValueError(f"invalid port value: {port_text}") from exc

    if port < 1 or port > 65535:
        raise ValueError(f"port out of range: {port}")
    return port


def _scan_single_port(
    target_ip: str,
    port: int,
    timeout: float,
    grab_banners: bool,
) -> PortFinding | None:
    started = perf_counter()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target_ip, port))
            if result != 0:
                return None

            latency_ms = round((perf_counter() - started) * 1000, 2)
            banner = _probe_banner(sock, port, timeout) if grab_banners else ""
            service = guess_service_name(port, banner)
            return PortFinding(
                port=port,
                state="OPEN",
                service=service,
                latency_ms=latency_ms,
                banner=banner,
            )
    except OSError:
        return None


def _probe_banner(sock: socket.socket, port: int, timeout: float) -> str:
    probe_timeout = min(timeout, 0.5)
    sock.settimeout(probe_timeout)

    initial = _recv_banner(sock)
    if initial:
        return initial

    payload = _build_probe_payload(port)
    if payload is None:
        return ""

    try:
        sock.sendall(payload)
    except OSError:
        return ""

    return _recv_banner(sock)


def _recv_banner(sock: socket.socket) -> str:
    try:
        data = sock.recv(256)
    except (socket.timeout, OSError):
        return ""

    if not data:
        return ""

    cleaned = data.decode("utf-8", errors="ignore").strip()
    cleaned = " ".join(cleaned.split())
    return cleaned[:160]


def _build_probe_payload(port: int) -> bytes | None:
    if port in HTTP_PROBE_PORTS:
        user_agent = f"User-Agent: {APP_CODENAME}/{__version__} ({APP_AUTHOR})\r\n".encode()
        return (
            b"HEAD / HTTP/1.0\r\n"
            b"Host: nighttrace.local\r\n"
            + user_agent
            + b"\r\n"
        )

    return ACTIVE_PROBES.get(port)


def _expand_target_spec(candidate: str, max_hosts: int) -> list[str]:
    if "/" not in candidate:
        return [candidate]

    try:
        network = ipaddress.ip_network(candidate, strict=False)
    except ValueError:
        return [candidate]

    if network.version != 4:
        raise ValueError("only IPv4 targets and CIDR networks are supported")

    hosts = list(network.hosts())
    if not hosts:
        hosts = [network.network_address]

    if len(hosts) > max_hosts:
        raise ValueError(
            f"target range {candidate} expands to {len(hosts)} hosts which exceeds --max-hosts {max_hosts}"
        )

    return [str(host) for host in hosts]
