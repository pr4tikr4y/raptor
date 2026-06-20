import json
import os
from typing import Optional
from config import HttpxConfig
from utils.logger import get_logger
from utils.runner import run_command, check_tool
from utils.output import ensure_dir, write_lines

log = get_logger()

TOOL = "httpx"


def run(
    subdomains: list,
    config: HttpxConfig,
    output_dir: str,
    proxy: Optional[str] = None,
) -> tuple[list, list]:
    """Returns (live_urls, raw_results)"""
    if not check_tool(TOOL):
        log.error(f"{TOOL} not found — install via: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest")
        return [], []

    if not subdomains:
        log.warning("[httpx] No subdomains to probe")
        return [], []

    ensure_dir(output_dir)
    input_file = os.path.join(output_dir, "subdomains.txt")
    out_file = os.path.join(output_dir, "live_hosts.json")
    urls_file = os.path.join(output_dir, "live_urls.txt")

    write_lines(subdomains, input_file)

    cmd = [
        TOOL,
        "-l", input_file,
        "-o", out_file,
        "-threads", str(config.threads),
        "-timeout", str(config.timeout),
        "-json",
        "-silent",
        "-mc", ",".join(str(c) for c in config.status_codes),
        "-rl", str(config.rate_limit),
    ]

    if config.follow_redirects:
        cmd.append("-follow-redirects")

    if config.tech_detect:
        cmd.append("-tech-detect")

    if proxy:
        cmd += ["-http-proxy", proxy]

    log.info(f"[httpx] Probing {len(subdomains)} hosts")
    rc, _, stderr = run_command(cmd, timeout=300)

    if rc not in (0, -1) and rc != 1:
        log.debug(f"[httpx] stderr: {stderr[:200]}")

    live_urls = []
    raw_results = []

    if os.path.exists(out_file):
        with open(out_file) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    raw_results.append(entry)
                    url = entry.get("url", "")
                    if url:
                        live_urls.append(url)
                except json.JSONDecodeError:
                    if line.startswith("http"):
                        live_urls.append(line)

    write_lines(live_urls, urls_file)
    log.info(f"[httpx] {len(live_urls)} live hosts found")
    return live_urls, raw_results
