import json
import os
import tempfile
from typing import Optional
from config import FfufConfig
from utils.logger import get_logger
from utils.runner import run_command, check_tool
from utils.output import ensure_dir

log = get_logger()

TOOL = "ffuf"

DEFAULT_WORDLIST_URL = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"


def _ensure_wordlist(wordlist_path: str) -> Optional[str]:
    if os.path.exists(wordlist_path):
        return wordlist_path

    fallbacks = [
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/dirbuster/wordlists/directory-list-2.3-small.txt",
    ]
    for fb in fallbacks:
        if os.path.exists(fb):
            log.info(f"[ffuf] Using fallback wordlist: {fb}")
            return fb

    log.warning(f"[ffuf] Wordlist not found at {wordlist_path} — skipping directory fuzzing")
    return None


def fuzz_host(
    url: str,
    config: FfufConfig,
    output_dir: str,
    proxy: Optional[str] = None,
) -> list:
    wordlist = _ensure_wordlist(config.wordlist)
    if not wordlist:
        return []

    safe_name = url.replace("://", "_").replace("/", "_").replace(":", "_")
    out_file = os.path.join(output_dir, f"ffuf_{safe_name}.json")

    fuzz_url = url.rstrip("/") + "/FUZZ"

    cmd = [
        TOOL,
        "-u", fuzz_url,
        "-w", wordlist,
        "-t", str(config.threads),
        "-timeout", str(config.timeout),
        "-rate", str(config.rate),
        "-o", out_file,
        "-of", "json",
        "-fc", config.filter_codes,
        "-noninteractive",
        "-s",
    ]

    if config.extensions:
        cmd += ["-e", f".{config.extensions.replace(',', ',.')}"]

    if config.recursion:
        cmd += ["-recursion", "-recursion-depth", str(config.recursion_depth)]

    if proxy:
        cmd += ["-x", proxy]

    rc, _, stderr = run_command(cmd, timeout=600)

    results = []
    if os.path.exists(out_file):
        try:
            with open(out_file) as f:
                data = json.load(f)
            for r in data.get("results", []):
                results.append({
                    "url": r.get("url", ""),
                    "status": r.get("status", 0),
                    "length": r.get("length", 0),
                    "words": r.get("words", 0),
                    "lines": r.get("lines", 0),
                    "redirect": r.get("redirectlocation", ""),
                })
        except (json.JSONDecodeError, KeyError):
            pass

    return results


def run(
    live_urls: list,
    config: FfufConfig,
    output_dir: str,
    proxy: Optional[str] = None,
    max_hosts: int = 20,
) -> dict:
    if not check_tool(TOOL):
        log.error(f"{TOOL} not found — install via: go install github.com/ffuf/ffuf/v2@latest")
        return {}

    if not live_urls:
        log.warning("[ffuf] No live hosts to fuzz")
        return {}

    ensure_dir(output_dir)
    targets = live_urls[:max_hosts]

    if len(live_urls) > max_hosts:
        log.warning(f"[ffuf] Capping at {max_hosts} hosts (use --max-ffuf-hosts to increase)")

    all_results = {}
    for url in targets:
        log.info(f"[ffuf] Fuzzing {url}")
        hits = fuzz_host(url, config, output_dir, proxy)
        if hits:
            all_results[url] = hits
            log.info(f"[ffuf] {url} -> {len(hits)} paths found")
        else:
            log.info(f"[ffuf] {url} -> no new paths")

    total = sum(len(v) for v in all_results.values())
    log.info(f"[ffuf] Done — {total} endpoints across {len(all_results)} hosts")
    return all_results
