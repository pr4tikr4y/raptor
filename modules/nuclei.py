import json
import os
from typing import Optional
from config import NucleiConfig
from utils.logger import get_logger
from utils.runner import run_command, check_tool
from utils.output import ensure_dir, write_lines

log = get_logger()

TOOL = "nuclei"

SEV_COLORS = {
    "critical": "\033[91m",
    "high": "\033[33m",
    "medium": "\033[93m",
    "low": "\033[94m",
    "info": "\033[37m",
}
RESET = "\033[0m"


def _update_templates():
    log.info("[nuclei] Updating templates...")
    rc, _, stderr = run_command([TOOL, "-update-templates", "-silent"], timeout=120)
    if rc != 0:
        log.warning(f"[nuclei] Template update failed (continuing with existing): {stderr[:100]}")


def run(
    live_urls: list,
    config: NucleiConfig,
    output_dir: str,
    proxy: Optional[str] = None,
    update_templates: bool = False,
) -> list:
    if not check_tool(TOOL):
        log.error(f"{TOOL} not found — install via: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
        return []

    if not live_urls:
        log.warning("[nuclei] No targets to scan")
        return []

    ensure_dir(output_dir)

    if update_templates:
        _update_templates()

    targets_file = os.path.join(output_dir, "nuclei_targets.txt")
    out_file = os.path.join(output_dir, "nuclei_findings.json")

    write_lines(live_urls, targets_file)

    cmd = [
        TOOL,
        "-l", targets_file,
        "-o", out_file,
        "-json-export", out_file,
        "-c", str(config.threads),
        "-timeout", str(config.timeout),
        "-rl", str(config.rate_limit),
        "-retries", str(config.retries),
        "-severity", ",".join(config.severity),
        "-silent",
        "-no-color",
    ]

    if config.templates:
        cmd += ["-t", ",".join(config.templates)]
    else:
        cmd += ["-automatic-scan"]

    if config.exclude_tags:
        cmd += ["-etags", ",".join(config.exclude_tags)]

    if proxy:
        cmd += ["-proxy", proxy]

    log.info(f"[nuclei] Scanning {len(live_urls)} targets (severity: {', '.join(config.severity)})")
    rc, stdout, stderr = run_command(cmd, timeout=3600)

    if rc not in (0, -1, 1):
        log.debug(f"[nuclei] rc={rc}, stderr={stderr[:300]}")

    findings = []
    if os.path.exists(out_file):
        with open(out_file) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    _print_findings_summary(findings)
    return findings


def _print_findings_summary(findings: list):
    if not findings:
        log.info("[nuclei] No vulnerabilities found")
        return

    by_severity = {}
    for f in findings:
        sev = f.get("info", {}).get("severity", "unknown").lower()
        by_severity.setdefault(sev, []).append(f)

    order = ["critical", "high", "medium", "low", "info", "unknown"]
    log.info(f"[nuclei] Found {len(findings)} issues:")
    for sev in order:
        items = by_severity.get(sev, [])
        if not items:
            continue
        color = SEV_COLORS.get(sev, "")
        print(f"  {color}[{sev.upper()}]{RESET} {len(items)}")
        for item in items:
            name = item.get("info", {}).get("name", "?")
            host = item.get("host", "")
            matched = item.get("matched-at", "")
            print(f"    {color}→{RESET} {name} @ {matched or host}")
