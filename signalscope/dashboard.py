from __future__ import annotations

from threading import Lock
from typing import Any

from signalscope import APP_NAME, APP_TAGLINE, APP_THEME
from signalscope.core import (
    build_report_payload,
    empty_report_payload,
    parse_ports,
    parse_targets,
    scan_targets,
)

BRAND = {
    "name": APP_NAME,
    "tagline": APP_TAGLINE,
    "theme": APP_THEME,
}


TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{ brand.name }}</title>
  <style>
    :root {
      --bg: #030706;
      --panel: rgba(6, 17, 14, 0.88);
      --panel-strong: rgba(7, 23, 19, 0.96);
      --ink: #d8ffe9;
      --muted: #77b594;
      --accent: #67ff9b;
      --accent-soft: rgba(103, 255, 155, 0.12);
      --warning-soft: rgba(255, 196, 87, 0.12);
      --warning-ink: #ffd166;
      --danger-soft: rgba(255, 93, 93, 0.14);
      --danger-ink: #ff7b7b;
      --line: rgba(103, 255, 155, 0.15);
      --shadow: 0 24px 60px rgba(0, 0, 0, 0.42);
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      font-family: "Cascadia Code", "Fira Code", Consolas, monospace;
      color: var(--ink);
      background:
        radial-gradient(circle at top left, rgba(103, 255, 155, 0.12), transparent 28%),
        radial-gradient(circle at top right, rgba(0, 255, 170, 0.08), transparent 22%),
        linear-gradient(180deg, #020504 0%, var(--bg) 100%);
      min-height: 100vh;
      position: relative;
      overflow-x: hidden;
    }

    body::before {
      content: "";
      position: fixed;
      inset: 0;
      pointer-events: none;
      background:
        linear-gradient(rgba(103, 255, 155, 0.05) 1px, transparent 1px),
        linear-gradient(90deg, rgba(103, 255, 155, 0.05) 1px, transparent 1px);
      background-size: 100% 3px, 3px 100%;
      opacity: 0.18;
    }

    body::after {
      content: "";
      position: fixed;
      inset: 0;
      pointer-events: none;
      background: linear-gradient(180deg, transparent 0%, rgba(103, 255, 155, 0.05) 48%, transparent 100%);
      background-size: 100% 160px;
      mix-blend-mode: screen;
      animation: sweep 10s linear infinite;
      opacity: 0.18;
    }

    .shell {
      width: min(1160px, calc(100% - 2rem));
      margin: 0 auto;
      padding: 2rem 0 3rem;
    }

    .hero {
      background: linear-gradient(135deg, rgba(7, 22, 18, 0.94), rgba(4, 14, 11, 0.84));
      border: 1px solid rgba(103, 255, 155, 0.18);
      box-shadow: var(--shadow);
      border-radius: 24px;
      padding: 1.5rem;
      backdrop-filter: blur(12px);
    }

    .eyebrow {
      text-transform: uppercase;
      letter-spacing: 0.22em;
      font-size: 0.78rem;
      color: var(--accent);
      margin: 0 0 0.75rem;
      font-weight: 700;
    }

    h1 {
      margin: 0;
      font-size: clamp(2rem, 4vw, 3.45rem);
      line-height: 0.96;
    }

    .subhead {
      margin: 0.9rem 0 0;
      color: var(--muted);
      max-width: 780px;
      line-height: 1.75;
    }

    .meta {
      margin-top: 1rem;
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 0.9rem;
    }

    .card, .launcher, .target, .empty-state {
      background: var(--panel);
      border-radius: 20px;
      border: 1px solid rgba(103, 255, 155, 0.15);
      box-shadow: var(--shadow);
    }

    .card {
      padding: 1rem;
    }

    .card strong {
      display: block;
      font-size: 1.45rem;
      margin-top: 0.3rem;
    }

    .label {
      color: var(--muted);
      font-size: 0.84rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }

    .launcher {
      margin-top: 1.2rem;
      padding: 1.15rem;
      background: var(--panel-strong);
    }

    .launcher-top {
      display: flex;
      justify-content: space-between;
      gap: 1rem;
      align-items: center;
      flex-wrap: wrap;
      margin-bottom: 1rem;
    }

    .launcher-title {
      font-size: 1.1rem;
      font-weight: 700;
    }

    .launcher-actions a {
      color: var(--accent);
      text-decoration: none;
      font-weight: 700;
    }

    form {
      display: grid;
      grid-template-columns: repeat(12, 1fr);
      gap: 0.9rem;
    }

    .field {
      display: flex;
      flex-direction: column;
      gap: 0.45rem;
    }

    .field label {
      color: var(--muted);
      font-size: 0.82rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      font-weight: 700;
    }

    .span-12 { grid-column: span 12; }
    .span-6 { grid-column: span 6; }
    .span-3 { grid-column: span 3; }
    .span-2 { grid-column: span 2; }

    input, textarea {
      width: 100%;
      border: 1px solid rgba(103, 255, 155, 0.16);
      background: rgba(1, 9, 7, 0.95);
      border-radius: 14px;
      padding: 0.85rem 0.95rem;
      font: inherit;
      color: var(--ink);
    }

    input:focus, textarea:focus {
      outline: 1px solid rgba(103, 255, 155, 0.55);
      box-shadow: 0 0 0 4px rgba(103, 255, 155, 0.08);
    }

    textarea {
      min-height: 92px;
      resize: vertical;
    }

    .toggle {
      display: flex;
      align-items: center;
      gap: 0.7rem;
      padding-top: 1.9rem;
      color: var(--ink);
      font-weight: 600;
    }

    .toggle input {
      width: 18px;
      height: 18px;
      margin: 0;
    }

    .actions {
      grid-column: span 12;
      display: flex;
      align-items: center;
      gap: 0.9rem;
      flex-wrap: wrap;
    }

    button {
      border: none;
      background: linear-gradient(135deg, #4dff90, #16c76b);
      color: #02140c;
      border-radius: 999px;
      padding: 0.9rem 1.25rem;
      font: inherit;
      font-weight: 700;
      cursor: pointer;
      box-shadow: 0 12px 26px rgba(22, 199, 107, 0.28);
    }

    .helper {
      color: var(--muted);
      font-size: 0.92rem;
    }

    .notice {
      margin-top: 1rem;
      padding: 0.9rem 1rem;
      border-radius: 14px;
      font-weight: 600;
    }

    .notice.success {
      background: var(--accent-soft);
      color: var(--accent);
    }

    .notice.error {
      background: var(--danger-soft);
      color: var(--danger-ink);
    }

    .target, .empty-state {
      margin-top: 1.25rem;
      overflow: hidden;
    }

    .target-head {
      padding: 1.15rem 1.2rem;
      border-bottom: 1px solid var(--line);
      display: flex;
      justify-content: space-between;
      gap: 1rem;
      align-items: center;
      flex-wrap: wrap;
    }

    .target-head h2 {
      margin: 0;
      font-size: 1.35rem;
    }

    .target-summary {
      color: var(--muted);
      margin-top: 0.35rem;
    }

    .pills {
      display: flex;
      gap: 0.6rem;
      flex-wrap: wrap;
    }

    .pill {
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
      padding: 0.45rem 0.7rem;
      border-radius: 999px;
      background: var(--accent-soft);
      color: var(--accent);
      font-weight: 700;
      font-size: 0.85rem;
      border: 1px solid rgba(103, 255, 155, 0.15);
    }

    .pill.warning {
      background: var(--warning-soft);
      color: var(--warning-ink);
    }

    .body {
      padding: 1rem 1.2rem 1.2rem;
    }

    .hint {
      margin: 0 0 1rem;
      color: var(--muted);
      line-height: 1.55;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.95rem;
    }

    th, td {
      text-align: left;
      padding: 0.85rem 0.5rem;
      border-bottom: 1px solid var(--line);
      vertical-align: top;
    }

    th {
      color: var(--muted);
      font-size: 0.78rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }

    tr:last-child td {
      border-bottom: none;
    }

    .empty-state {
      padding: 1.35rem;
    }

    .empty-state h2 {
      margin: 0 0 0.35rem;
    }

    .empty-state p {
      margin: 0;
      color: var(--muted);
      line-height: 1.55;
    }

    .footer {
      margin-top: 1.25rem;
      padding: 1rem 1.2rem;
      border: 1px solid rgba(103, 255, 155, 0.12);
      border-radius: 18px;
      background: rgba(4, 14, 11, 0.7);
      color: var(--muted);
      font-size: 0.88rem;
    }

    @keyframes sweep {
      0% { transform: translateY(-20%); }
      100% { transform: translateY(20%); }
    }

    @media (max-width: 840px) {
      .span-6, .span-3, .span-2 { grid-column: span 12; }
      .toggle { padding-top: 0; }
    }

    @media (max-width: 700px) {
      table, thead, tbody, th, td, tr {
        display: block;
      }

      thead {
        display: none;
      }

      tr {
        padding: 0.7rem 0;
        border-bottom: 1px solid var(--line);
      }

      td {
        border-bottom: none;
        padding: 0.25rem 0;
      }

      td::before {
        display: inline-block;
        min-width: 90px;
        color: var(--muted);
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        font-size: 0.73rem;
        content: attr(data-label);
      }
    }
  </style>
</head>
<body>
  <main class="shell">
    <section class="hero">
      <p class="eyebrow">{{ brand.name }}</p>
      <h1>Launch recon sweeps, classify exposed services, and review live host intel from one console.</h1>
      <p class="subhead">{{ brand.tagline }} Launch recon sweeps, classify exposed services, and review results from a single local console.</p>

      <div class="meta">
        <div class="card">
          <span class="label">Targets</span>
          <strong>{{ payload.scan.target_count }}</strong>
        </div>
        <div class="card">
          <span class="label">Open Ports</span>
          <strong>{{ payload.scan.total_open_ports }}</strong>
        </div>
        <div class="card">
          <span class="label">Port Workers</span>
          <strong>{{ payload.scan.workers }}</strong>
        </div>
        <div class="card">
          <span class="label">Host Workers</span>
          <strong>{{ payload.scan.host_workers }}</strong>
        </div>
      </div>

      <section class="launcher">
        <div class="launcher-top">
          <div class="launcher-title">Scan Launcher</div>
          <div class="launcher-actions">
            <a href="/api/latest" target="_blank" rel="noreferrer">Open latest JSON feed</a>
          </div>
        </div>

        <form method="post">
          <div class="field span-12">
            <label for="targets">Targets or CIDR subnet</label>
            <textarea id="targets" name="targets" placeholder="192.168.1.10,192.168.1.11 or 192.168.1.0/24">{{ form.targets }}</textarea>
          </div>

          <div class="field span-6">
            <label for="ports">Ports</label>
            <input id="ports" name="ports" value="{{ form.ports }}" placeholder="1-1024 or 22,80,443,8080">
          </div>

          <div class="field span-2">
            <label for="timeout">Timeout</label>
            <input id="timeout" name="timeout" value="{{ form.timeout }}" placeholder="0.8">
          </div>

          <div class="field span-2">
            <label for="workers">Port workers</label>
            <input id="workers" name="workers" value="{{ form.workers }}" placeholder="200">
          </div>

          <div class="field span-2">
            <label for="host_workers">Host workers</label>
            <input id="host_workers" name="host_workers" value="{{ form.host_workers }}" placeholder="1">
          </div>

          <div class="field span-3">
            <label for="max_hosts">Max hosts</label>
            <input id="max_hosts" name="max_hosts" value="{{ form.max_hosts }}" placeholder="256">
          </div>

          <div class="field span-3 toggle">
            <input id="grab_banners" name="grab_banners" type="checkbox" {% if form.grab_banners %}checked{% endif %}>
            <label for="grab_banners" style="text-transform: none; letter-spacing: 0; font-size: 0.95rem; color: inherit;">Enable banner grabbing</label>
          </div>

          <div class="actions">
            <button type="submit">Launch Scan</button>
            <span class="helper">CIDR expansion is capped by the max-hosts setting so the console stays deliberate instead of accidentally sweeping huge address space.</span>
          </div>
        </form>

        {% if message %}
        <div class="notice success">{{ message }}</div>
        {% endif %}
        {% if error %}
        <div class="notice error">{{ error }}</div>
        {% endif %}
      </section>
    </section>

    {% if payload.reports %}
      {% for report in payload.reports %}
      <section class="target">
        <div class="target-head">
          <div>
            <h2>{{ report.target }}{% if report.resolved_ip %} <span style="color: var(--muted); font-weight: 500;">({{ report.resolved_ip }})</span>{% endif %}</h2>
            <div class="target-summary">Scanned {{ report.scanned_ports }} ports in {{ "%.2f"|format(report.duration_ms) }} ms</div>
          </div>
          <div class="pills">
            <span class="pill">{{ report.open_port_count }} open</span>
            <span class="pill warning">{{ report.os_hint.family }} | {{ report.os_hint.confidence }}</span>
          </div>
        </div>
        <div class="body">
          {% if report.os_hint.evidence %}
          <p class="hint">OS hint evidence: {{ report.os_hint.evidence | join(", ") }}</p>
          {% endif %}

          {% if report.error %}
          <p class="notice error" style="margin-top: 0;">{{ report.error }}</p>
          {% elif report.findings %}
          <table>
            <thead>
              <tr>
                <th>Port</th>
                <th>State</th>
                <th>Service</th>
                <th>Latency</th>
                <th>Banner</th>
              </tr>
            </thead>
            <tbody>
              {% for finding in report.findings %}
              <tr>
                <td data-label="Port">{{ finding.port }}</td>
                <td data-label="State">{{ finding.state }}</td>
                <td data-label="Service">{{ finding.service }}</td>
                <td data-label="Latency">{{ "%.2f"|format(finding.latency_ms) }} ms</td>
                <td data-label="Banner">{{ finding.banner or "-" }}</td>
              </tr>
              {% endfor %}
            </tbody>
          </table>
          {% else %}
          <p class="hint">No open TCP ports were detected for this target.</p>
          {% endif %}
        </div>
      </section>
      {% endfor %}
    {% else %}
      <section class="empty-state">
        <h2>No scan loaded yet.</h2>
        <p>Use the launcher above to scan a single host, a list of hosts, or a CIDR subnet. The latest report will appear here as soon as the run completes.</p>
      </section>
    {% endif %}
    <section class="footer">
      <strong style="color: var(--accent);">{{ brand.name }}</strong><br>
      Theme: {{ brand.theme }}
    </section>
  </main>
</body>
</html>
"""


def create_dashboard_app(initial_payload: dict[str, Any] | None = None):
    try:
        from flask import Flask, jsonify, render_template_string, request
    except ImportError as exc:
        raise RuntimeError(
            "Flask is required for the dashboard. Install dependencies with 'pip install -r requirements.txt'."
        ) from exc

    payload = initial_payload or empty_report_payload()
    state = {
        "payload": payload,
        "message": None,
        "error": None,
        "form": _build_form_state(payload),
    }
    lock = Lock()
    app = Flask(__name__)

    @app.route("/", methods=["GET", "POST"])
    def index():
        if request.method == "POST":
            form_state = {
                "targets": request.form.get("targets", "").strip(),
                "ports": request.form.get("ports", "1-1024").strip(),
                "timeout": request.form.get("timeout", "0.8").strip(),
                "workers": request.form.get("workers", "200").strip(),
                "host_workers": request.form.get("host_workers", "1").strip(),
                "max_hosts": request.form.get("max_hosts", "256").strip(),
                "grab_banners": request.form.get("grab_banners") == "on",
            }
            with lock:
                payload = state["payload"]

            try:
                timeout = float(form_state["timeout"])
                workers = int(form_state["workers"])
                host_workers = int(form_state["host_workers"])
                max_hosts = int(form_state["max_hosts"])

                if timeout <= 0:
                    raise ValueError("timeout must be greater than 0")
                if workers <= 0:
                    raise ValueError("port workers must be greater than 0")
                if host_workers <= 0:
                    raise ValueError("host workers must be greater than 0")
                if max_hosts <= 0:
                    raise ValueError("max hosts must be greater than 0")

                targets = parse_targets([form_state["targets"]], max_hosts=max_hosts)
                ports = parse_ports(form_state["ports"])
                reports = scan_targets(
                    targets,
                    ports,
                    timeout=timeout,
                    workers=workers,
                    host_workers=host_workers,
                    grab_banners=form_state["grab_banners"],
                )
                payload = build_report_payload(
                    reports,
                    port_expression=form_state["ports"],
                    timeout=timeout,
                    workers=workers,
                    host_workers=host_workers,
                    max_hosts=max_hosts,
                    grab_banners=form_state["grab_banners"],
                )
                message = f"Scan finished for {len(targets)} target(s)."
                error = None
            except ValueError as exc:
                message = None
                error = str(exc)
            else:
                with lock:
                    state["payload"] = payload

            with lock:
                state["form"] = form_state
                state["message"] = message
                state["error"] = error
                payload = state["payload"]
                message = state["message"]
                error = state["error"]
                form = state["form"]
        else:
            with lock:
                payload = state["payload"]
                message = state["message"]
                error = state["error"]
                form = state["form"]

        return render_template_string(
            TEMPLATE,
            brand=BRAND,
            payload=payload,
            message=message,
            error=error,
            form=form,
        )

    @app.get("/api/latest")
    def latest():
        with lock:
            return jsonify(state["payload"])

    return app


def launch_dashboard(payload: dict[str, Any] | None, host: str, port: int) -> None:
    app = create_dashboard_app(payload)
    app.run(host=host, port=port, debug=False, use_reloader=False)


def _build_form_state(payload: dict[str, Any]) -> dict[str, Any]:
    scan = payload.get("scan", {})
    reports = payload.get("reports", [])
    targets = ",".join(report.get("target", "") for report in reports if report.get("target"))
    return {
        "targets": targets,
        "ports": scan.get("port_expression", "1-1024"),
        "timeout": scan.get("timeout_seconds", 0.8),
        "workers": scan.get("workers", 200),
        "host_workers": scan.get("host_workers", 1),
        "max_hosts": scan.get("max_hosts", 256),
        "grab_banners": scan.get("banner_grabbing", True),
    }
