import json
import os
from datetime import datetime
from typing import Any


def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)


def write_json(data: Any, path: str):
    ensure_dir(os.path.dirname(path))
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)


def write_lines(lines: list, path: str):
    ensure_dir(os.path.dirname(path))
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")


def read_lines(path: str) -> list:
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return [l.strip() for l in f if l.strip()]


def generate_report(session: dict, output_dir: str):
    ts = session["timestamp"]
    target = session["target"]
    report_path = os.path.join(output_dir, f"report_{target}_{ts}.json")
    html_path = os.path.join(output_dir, f"report_{target}_{ts}.html")

    write_json(session, report_path)
    _write_html_report(session, html_path)
    return report_path, html_path


def _write_html_report(session: dict, path: str):
    target = session.get("target", "unknown")
    ts = session.get("timestamp", "")
    subdomains = session.get("subdomains", [])
    live_hosts = session.get("live_hosts", [])
    ffuf_results = session.get("ffuf_results", {})
    nuclei_findings = session.get("nuclei_findings", [])

    sev_colors = {
        "critical": "#ff4444",
        "high": "#ff8800",
        "medium": "#ffcc00",
        "low": "#44aaff",
        "info": "#aaaaaa",
        "unknown": "#888888",
    }

    findings_html = ""
    for f in nuclei_findings:
        sev = f.get("info", {}).get("severity", "unknown").lower()
        color = sev_colors.get(sev, "#888888")
        name = f.get("info", {}).get("name", "Unknown")
        host = f.get("host", "")
        matched = f.get("matched-at", "")
        desc = f.get("info", {}).get("description", "")
        template_id = f.get("template-id", "")
        findings_html += f"""
        <div class="finding" style="border-left: 4px solid {color}">
          <div class="finding-header">
            <span class="badge" style="background:{color}">{sev.upper()}</span>
            <strong>{name}</strong>
            <code class="template-id">{template_id}</code>
          </div>
          <div class="finding-body">
            <p><strong>Host:</strong> {host}</p>
            <p><strong>Matched:</strong> {matched}</p>
            {"<p>" + desc + "</p>" if desc else ""}
          </div>
        </div>"""

    ffuf_html = ""
    for host, paths in ffuf_results.items():
        ffuf_html += f"<h4>{host}</h4><ul>"
        for p in paths:
            status = p.get("status", "")
            url = p.get("url", "")
            size = p.get("length", "")
            ffuf_html += f'<li><code>{status}</code> <a href="{url}" target="_blank">{url}</a> <small>({size}b)</small></li>'
        ffuf_html += "</ul>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Recon Report — {target}</title>
<style>
  body {{ font-family: 'Segoe UI', monospace; background: #0d1117; color: #c9d1d9; margin: 0; padding: 20px; }}
  h1, h2, h3 {{ color: #58a6ff; }}
  .header {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin-bottom: 20px; }}
  .stat-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 20px; }}
  .stat {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; text-align: center; }}
  .stat .num {{ font-size: 2em; font-weight: bold; color: #58a6ff; }}
  .stat .label {{ color: #8b949e; font-size: 0.85em; }}
  .section {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin-bottom: 20px; }}
  .finding {{ background: #0d1117; border: 1px solid #30363d; border-radius: 6px; padding: 12px; margin: 8px 0; }}
  .finding-header {{ display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }}
  .badge {{ padding: 2px 8px; border-radius: 4px; font-size: 0.75em; font-weight: bold; color: #fff; }}
  .template-id {{ background: #21262d; padding: 2px 6px; border-radius: 4px; font-size: 0.8em; color: #8b949e; }}
  .finding-body {{ font-size: 0.9em; color: #8b949e; }}
  ul {{ list-style: none; padding: 0; }}
  li {{ padding: 4px 0; border-bottom: 1px solid #21262d; }}
  code {{ background: #21262d; padding: 1px 5px; border-radius: 3px; }}
  a {{ color: #58a6ff; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
</style>
</head>
<body>
<div class="header">
  <h1>Recon Pipeline Report</h1>
  <p><strong>Target:</strong> {target} &nbsp;|&nbsp; <strong>Generated:</strong> {ts}</p>
</div>

<div class="stat-grid">
  <div class="stat"><div class="num">{len(subdomains)}</div><div class="label">Subdomains</div></div>
  <div class="stat"><div class="num">{len(live_hosts)}</div><div class="label">Live Hosts</div></div>
  <div class="stat"><div class="num">{sum(len(v) for v in ffuf_results.values())}</div><div class="label">Endpoints Found</div></div>
  <div class="stat"><div class="num">{len(nuclei_findings)}</div><div class="label">Vulnerabilities</div></div>
</div>

<div class="section">
  <h2>Subdomains ({len(subdomains)})</h2>
  <ul>{"".join(f"<li><code>{s}</code></li>" for s in subdomains)}</ul>
</div>

<div class="section">
  <h2>Live Hosts ({len(live_hosts)})</h2>
  <ul>{"".join(f"<li><a href='{h}' target='_blank'>{h}</a></li>" for h in live_hosts)}</ul>
</div>

{"<div class='section'><h2>Directory Discovery</h2>" + ffuf_html + "</div>" if ffuf_results else ""}

<div class="section">
  <h2>Vulnerability Findings ({len(nuclei_findings)})</h2>
  {findings_html if findings_html else "<p style='color:#8b949e'>No findings.</p>"}
</div>
</body>
</html>"""

    ensure_dir(os.path.dirname(path))
    with open(path, "w") as f:
        f.write(html)
