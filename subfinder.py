import os
from typing import Optional
from config import SubfinderConfig
from utils.logger import get_logger
from utils.runner import run_command, check_tool
from utils.output import write_lines, ensure_dir

log = get_logger()

TOOL = "subfinder"


def run(
    target: str,
    config: SubfinderConfig,
    output_dir: str,
    proxy: Optional[str] = None,
) -> list:
    if not check_tool(TOOL):
        log.error(f"{TOOL} not found — install via: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
        return []

    ensure_dir(output_dir)
    out_file = os.path.join(output_dir, "subdomains.txt")

    cmd = [
        TOOL,
        "-d", target,
        "-o", out_file,
        "-t", str(config.threads),
        "-timeout", str(config.timeout),
        "-silent",
    ]

    if config.all_sources:
        cmd.append("-all")

    if config.resolvers:
        resolvers_str = ",".join(config.resolvers)
        cmd += ["-r", resolvers_str]

    if config.sources:
        cmd += ["-sources", ",".join(config.sources)]

    if proxy:
        cmd += ["-proxy", proxy]

    log.info(f"[subfinder] Enumerating subdomains for {target}")
    rc, stdout, stderr = run_command(cmd, timeout=300)

    if rc != 0 and rc != -1:
        log.warning(f"[subfinder] Exited with code {rc}")

    subdomains = []
    if os.path.exists(out_file):
        with open(out_file) as f:
            subdomains = [l.strip() for l in f if l.strip()]

    if not subdomains and stdout:
        subdomains = [l.strip() for l in stdout.splitlines() if l.strip()]
        write_lines(subdomains, out_file)

    log.info(f"[subfinder] Found {len(subdomains)} subdomains")
    return subdomains
