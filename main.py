#!/usr/bin/env python3
"""
Recon Pipeline — Modular attack surface discovery and vuln scanning.
Integrates: subfinder → httpx → ffuf → nuclei
"""

import argparse
import os
import sys
import time
from datetime import datetime

from config import load_config
from utils.logger import get_logger, banner
from utils.output import generate_report
from utils.runner import check_required_tools

import modules.subfinder as subfinder_mod
import modules.httpx_probe as httpx_mod
import modules.ffuf as ffuf_mod
import modules.nuclei as nuclei_mod

log = get_logger()

ALL_MODULES = ["subfinder", "httpx", "ffuf", "nuclei"]
REQUIRED_TOOLS = {
    "subfinder": "subfinder",
    "httpx": "httpx",
    "ffuf": "ffuf",
    "nuclei": "nuclei",
}


def parse_args():
    p = argparse.ArgumentParser(
        description="Recon Pipeline — Attack Surface Discovery & Vulnerability Scanning",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 main.py -t example.com
  python3 main.py -t example.com --modules subfinder,httpx,nuclei
  python3 main.py -t example.com --skip ffuf --update-templates
  python3 main.py -t example.com --proxy http://127.0.0.1:8080 --config custom.yaml
  python3 main.py -t example.com --severity critical,high --max-ffuf-hosts 10
        """,
    )

    p.add_argument("-t", "--target", required=True, help="Target domain (e.g. example.com)")
    p.add_argument(
        "--modules",
        default=",".join(ALL_MODULES),
        help=f"Comma-separated modules to run (default: all). Options: {', '.join(ALL_MODULES)}",
    )
    p.add_argument("--skip", default="", help="Comma-separated modules to skip")
    p.add_argument("--config", default=None, help="Path to YAML config file")
    p.add_argument("--output-dir", default=None, help="Output directory (default: reports/<target>)")
    p.add_argument("--proxy", default=None, help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    p.add_argument("--severity", default=None, help="Nuclei severity filter (critical,high,medium,low,info)")
    p.add_argument("--update-templates", action="store_true", help="Update Nuclei templates before scanning")
    p.add_argument("--max-ffuf-hosts", type=int, default=20, help="Max hosts to fuzz with FFUF (default: 20)")
    p.add_argument("--subdomains-file", default=None, help="Skip subfinder and load subdomains from file")
    p.add_argument("--hosts-file", default=None, help="Skip subfinder+httpx and load live hosts from file")
    p.add_argument("--no-report", action="store_true", help="Skip HTML/JSON report generation")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose/debug output")

    return p.parse_args()


def resolve_modules(args) -> list:
    requested = [m.strip() for m in args.modules.split(",") if m.strip()]
    skipped = [m.strip() for m in args.skip.split(",") if m.strip()]
    return [m for m in requested if m in ALL_MODULES and m not in skipped]


def check_tools_for_modules(modules: list):
    tools_needed = [REQUIRED_TOOLS[m] for m in modules if m in REQUIRED_TOOLS]
    missing = check_required_tools(tools_needed)
    if missing:
        log.warning(f"Missing tools: {', '.join(missing)}")
        log.warning("Some modules may be skipped. Install missing tools to enable them.")


def main():
    args = parse_args()

    cfg = load_config(args.config)

    if args.verbose:
        import logging
        get_logger().setLevel(logging.DEBUG)

    if args.proxy:
        cfg.proxy = args.proxy

    if args.severity:
        cfg.nuclei.severity = [s.strip() for s in args.severity.split(",")]

    modules = resolve_modules(args)
    if not modules:
        log.error("No modules selected. Exiting.")
        sys.exit(1)

    target = args.target.lower().strip()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = args.output_dir or os.path.join(cfg.output_dir, f"{target}_{ts}")
    os.makedirs(output_dir, exist_ok=True)

    banner(target, modules)
    check_tools_for_modules(modules)

    session = {
        "target": target,
        "timestamp": ts,
        "modules": modules,
        "subdomains": [],
        "live_hosts": [],
        "httpx_raw": [],
        "ffuf_results": {},
        "nuclei_findings": [],
    }

    start = time.time()

    # ── 1. Subdomain Enumeration ──────────────────────────────────────────────
    if args.hosts_file:
        log.info(f"Loading live hosts from {args.hosts_file}")
        from utils.output import read_lines
        session["live_hosts"] = read_lines(args.hosts_file)
        modules = [m for m in modules if m not in ("subfinder", "httpx")]
    elif args.subdomains_file:
        log.info(f"Loading subdomains from {args.subdomains_file}")
        from utils.output import read_lines
        session["subdomains"] = read_lines(args.subdomains_file)
        modules = [m for m in modules if m != "subfinder"]
    elif "subfinder" in modules:
        session["subdomains"] = subfinder_mod.run(
            target, cfg.subfinder, output_dir, cfg.proxy
        )
    else:
        log.warning("[!] subfinder skipped and no subdomains file provided — httpx will target root domain only")
        session["subdomains"] = [target]

    # ── 2. HTTP Probing ───────────────────────────────────────────────────────
    if "httpx" in modules:
        hosts_to_probe = session["subdomains"] or [target]
        live_urls, raw = httpx_mod.run(
            hosts_to_probe, cfg.httpx, output_dir, cfg.proxy
        )
        session["live_hosts"] = live_urls
        session["httpx_raw"] = raw

    # ── 3. Directory Fuzzing ──────────────────────────────────────────────────
    if "ffuf" in modules:
        targets_for_ffuf = session["live_hosts"] or ([f"https://{target}", f"http://{target}"])
        session["ffuf_results"] = ffuf_mod.run(
            targets_for_ffuf,
            cfg.ffuf,
            output_dir,
            cfg.proxy,
            max_hosts=args.max_ffuf_hosts,
        )

    # ── 4. Vulnerability Scanning ─────────────────────────────────────────────
    if "nuclei" in modules:
        nuclei_targets = session["live_hosts"] or [f"https://{target}", f"http://{target}"]
        session["nuclei_findings"] = nuclei_mod.run(
            nuclei_targets,
            cfg.nuclei,
            output_dir,
            cfg.proxy,
            update_templates=args.update_templates,
        )

    # ── Summary ───────────────────────────────────────────────────────────────
    elapsed = time.time() - start
    print()
    log.info(f"Pipeline completed in {elapsed:.1f}s")
    log.info(f"  Subdomains  : {len(session['subdomains'])}")
    log.info(f"  Live hosts  : {len(session['live_hosts'])}")
    log.info(f"  Endpoints   : {sum(len(v) for v in session['ffuf_results'].values())}")
    log.info(f"  Vuln finds  : {len(session['nuclei_findings'])}")

    if not args.no_report:
        json_path, html_path = generate_report(session, output_dir)
        log.info(f"  Report JSON : {json_path}")
        log.info(f"  Report HTML : {html_path}")

    log.info(f"  Output dir  : {output_dir}")


if __name__ == "__main__":
    main()
