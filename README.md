<div align="center">

```
██████╗  █████╗ ██████╗ ████████╗ ██████╗ ██████╗
██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
██████╔╝███████║██████╔╝   ██║   ██║   ██║██████╔╝
██╔══██╗██╔══██║██╔═══╝    ██║   ██║   ██║██╔══██╗
██║  ██║██║  ██║██║        ██║   ╚██████╔╝██║  ██║
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝        ╚═╝    ╚═════╝ ╚═╝  ╚═╝
```

**Recon Automation Pipeline for Target Operations & Reporting**

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey?style=flat-square)
![Tools](https://img.shields.io/badge/Integrates-Subfinder%20%7C%20httpx%20%7C%20FFUF%20%7C%20Nuclei-red?style=flat-square)

*Modular attack surface recon and template-based vulnerability discovery — from a single domain to a full findings report.*

</div>

---

## Overview

RAPTOR is a modular Python/Bash pipeline that chains four industry-standard tools into a single, repeatable workflow — subdomain enumeration → HTTP probing → directory fuzzing → vulnerability scanning — then renders findings into a structured JSON + HTML report. It was built to eliminate the manual overhead of stitching tool outputs together during external assessments and to keep scan coverage consistent across engagements.

```
subfinder ──► httpx ──► ffuf ──► nuclei ──► report
 (enumerate)  (probe)  (fuzz)   (scan)     (HTML + JSON)
```

Each stage is independently runnable. Pass `--subdomains-file` or `--hosts-file` to jump into the pipeline mid-way, or use `--modules` to run only the stages you need.

---

## Features

- **Full pipeline in one command** — `./run.sh -t example.com` runs everything end to end
- **Modular** — any stage can be skipped, replaced, or run in isolation
- **YAML config** — tune threads, rate limits, severities, and wordlists per engagement
- **Proxy-aware** — routes all tool traffic through a single `--proxy` flag (Burp / MITM)
- **Dark-theme HTML report** — severity-colored findings, live host list, discovered endpoints
- **Graceful degradation** — missing tools are warned about and skipped, pipeline continues
- **Rate limiting built in** — configurable per-module to avoid triggering WAFs or rate defenses
- **Template update support** — `--update-templates` pulls latest Nuclei community templates before scanning

---

## Pipeline Stages

| # | Module | Tool | What it does |
|---|--------|------|-------------|
| 1 | `subfinder` | [Subfinder](https://github.com/projectdiscovery/subfinder) | Passive subdomain enumeration across 40+ sources |
| 2 | `httpx` | [httpx](https://github.com/projectdiscovery/httpx) | Probes subdomains for live HTTP/S services, detects tech stack |
| 3 | `ffuf` | [FFUF](https://github.com/ffuf/ffuf) | Wordlist-based directory and endpoint fuzzing on live hosts |
| 4 | `nuclei` | [Nuclei](https://github.com/projectdiscovery/nuclei) | Template-based scanning for CVEs, misconfigurations, and exposures |

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/yourhandle/raptor.git
cd raptor
```

### 2. Install Go tools

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install    github.com/ffuf/ffuf/v2@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

Make sure `$GOPATH/bin` (usually `~/go/bin`) is in your `$PATH`.

### 3. Install a wordlist (for FFUF)

```bash
# Kali / Debian — installs SecLists which RAPTOR auto-detects
sudo apt install seclists

# or place any wordlist at:
wordlists/common.txt
```

### 4. (Optional) Python dependencies

`run.sh` handles this automatically via a virtualenv. To set up manually:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## Usage

### Quick start

```bash
./run.sh -t example.com
```

### Common invocations

```bash
# Full pipeline, verbose output
./run.sh -t example.com -v

# Skip directory fuzzing, only scan critical and high severity
./run.sh -t example.com --skip ffuf --severity critical,high

# Route all traffic through Burp Suite
./run.sh -t example.com --proxy http://127.0.0.1:8080

# Resume from a saved subdomain list (skip subfinder)
./run.sh -t example.com --subdomains-file /tmp/subs.txt

# Jump straight to nuclei from a live-hosts file
./run.sh -t example.com --hosts-file /tmp/live.txt --modules nuclei

# Run only subfinder + httpx (no fuzzing, no vuln scan)
./run.sh -t example.com --modules subfinder,httpx

# Custom config + capped FFUF host count
./run.sh -t example.com --config config.yaml --max-ffuf-hosts 10

# Update Nuclei templates before scanning
./run.sh -t example.com --update-templates
```

### All flags

```
  -t, --target            Target domain (required)
  --modules               Comma-separated modules to run (default: subfinder,httpx,ffuf,nuclei)
  --skip                  Comma-separated modules to skip
  --config                Path to YAML config file
  --output-dir            Output directory (default: reports/<target>_<timestamp>)
  --proxy                 HTTP proxy URL (e.g. http://127.0.0.1:8080)
  --severity              Nuclei severity filter (critical,high,medium,low,info)
  --update-templates      Pull latest Nuclei templates before scan
  --max-ffuf-hosts        Cap FFUF to N hosts (default: 20)
  --subdomains-file       Load subdomains from file, skip subfinder
  --hosts-file            Load live hosts from file, skip subfinder + httpx
  --no-report             Skip HTML/JSON report generation
  -v, --verbose           Debug output
```

---

## Configuration

Copy the example config and adjust per engagement:

```bash
cp config.yaml.example config.yaml
```

```yaml
# config.yaml
subfinder:
  threads: 10
  all_sources: false        # true = slower but more coverage

httpx:
  threads: 50
  rate_limit: 150
  tech_detect: true

ffuf:
  threads: 40
  rate: 100
  wordlist: wordlists/common.txt
  extensions: php,html,js,txt,json,bak
  filter_codes: "404,400"
  recursion: false

nuclei:
  threads: 25
  rate_limit: 150
  severity: [critical, high, medium, low]
  exclude_tags: [dos, fuzz]

proxy: http://127.0.0.1:8080   # optional global proxy
```

Full annotated reference: [`config.yaml.example`](config.yaml.example)

---

## Output

Each run writes to `reports/<target>_<timestamp>/`:

```
reports/example.com_20260620_143022/
├── subdomains.txt          # Raw subfinder output
├── live_hosts.json         # httpx JSON (status, tech, title, etc.)
├── live_urls.txt           # Plain URL list
├── ffuf_<host>.json        # Per-host FFUF results
├── nuclei_targets.txt      # Hosts fed to nuclei
├── nuclei_findings.json    # Raw nuclei JSON output
├── report_example.com_...json   # Full pipeline session (machine-readable)
└── report_example.com_...html   # Dark-theme findings report
```

The HTML report includes:
- Summary stats (subdomains, live hosts, endpoints, vulnerability count)
- Full subdomain and live host lists
- Discovered endpoints per host with status codes
- Vulnerability findings sorted by severity with matched URL and description

---

## Project Structure

```
raptor/
├── main.py               # Pipeline orchestrator
├── config.py             # Dataclass config + YAML loader
├── run.sh                # Bash wrapper (venv, tool checks, wordlist setup)
├── requirements.txt
├── config.yaml.example
├── modules/
│   ├── subfinder.py      # Subdomain enumeration module
│   ├── httpx_probe.py    # HTTP probing module
│   ├── ffuf.py           # Directory fuzzing module
│   └── nuclei.py         # Vulnerability scanning module
├── utils/
│   ├── logger.py         # Colored logger + ASCII banner
│   ├── output.py         # JSON + HTML report generation
│   └── runner.py         # subprocess wrappers with proxy + timeout support
└── wordlists/            # Wordlist directory (auto-linked from SecLists if available)
```

---

## Extending the Pipeline

Each module follows the same interface — it takes a config dataclass, an output directory, and an optional proxy, and returns structured data. Adding a new stage:

1. Create `modules/yourmodule.py` with a `run(targets, config, output_dir, proxy)` function
2. Add it to `ALL_MODULES` in `main.py`
3. Wire it into the pipeline flow and pass its output to the next stage

The `utils/runner.py` helpers (`run_command`, `stream_command`) handle process management, timeouts, and proxy env vars so new modules don't need to reimplement that.

---

## Requirements

| Requirement | Version |
|-------------|---------|
| Python | 3.9+ |
| Go | 1.21+ (for tool installation) |
| subfinder | latest |
| httpx | latest |
| ffuf | v2+ |
| nuclei | v3+ |

All four tools can be installed independently — RAPTOR will warn about missing tools and skip those modules rather than exiting.

---

## Disclaimer

RAPTOR is intended for **authorized security assessments only**. Only run this tool against systems you own or have explicit written permission to test. Unauthorized scanning may violate computer fraud laws in your jurisdiction. The authors assume no liability for misuse.

---

## License

MIT — see [LICENSE](LICENSE)
