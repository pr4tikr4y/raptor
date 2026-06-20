#!/usr/bin/env bash
# Recon Pipeline wrapper — handles venv, tool checks, and invocation
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$SCRIPT_DIR/.venv"
REQUIRED_GO_TOOLS=(subfinder httpx ffuf nuclei)

RED='\033[91m'; YELLOW='\033[93m'; GREEN='\033[92m'; RESET='\033[0m'; BOLD='\033[1m'

info()  { echo -e "${GREEN}[*]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[!]${RESET} $*"; }
error() { echo -e "${RED}[-]${RESET} $*"; }

# ── Python venv ──────────────────────────────────────────────────────────────
if [[ ! -d "$VENV" ]]; then
    info "Creating Python virtual environment..."
    python3 -m venv "$VENV"
fi

source "$VENV/bin/activate"

if [[ ! -f "$VENV/.deps_installed" ]]; then
    info "Installing Python dependencies..."
    pip install -q -r "$SCRIPT_DIR/requirements.txt"
    touch "$VENV/.deps_installed"
fi

# ── Go tool checks ────────────────────────────────────────────────────────────
MISSING_TOOLS=()
for tool in "${REQUIRED_GO_TOOLS[@]}"; do
    if ! command -v "$tool" &>/dev/null; then
        MISSING_TOOLS+=("$tool")
    fi
done

if [[ ${#MISSING_TOOLS[@]} -gt 0 ]]; then
    warn "Missing tools: ${MISSING_TOOLS[*]}"
    warn "Install them with:"
    for t in "${MISSING_TOOLS[@]}"; do
        case "$t" in
            subfinder) warn "  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" ;;
            httpx)     warn "  go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest" ;;
            ffuf)      warn "  go install github.com/ffuf/ffuf/v2@latest" ;;
            nuclei)    warn "  go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" ;;
        esac
    done
    warn "Continuing — modules for missing tools will be skipped."
fi

# ── Wordlist setup ────────────────────────────────────────────────────────────
WORDLIST="$SCRIPT_DIR/wordlists/common.txt"
if [[ ! -f "$WORDLIST" ]]; then
    info "Fetching common wordlist..."
    mkdir -p "$SCRIPT_DIR/wordlists"
    SECLISTS_PATH="/usr/share/seclists/Discovery/Web-Content/common.txt"
    DIRB_PATH="/usr/share/wordlists/dirb/common.txt"
    if [[ -f "$SECLISTS_PATH" ]]; then
        ln -sf "$SECLISTS_PATH" "$WORDLIST"
        info "Linked SecLists common.txt"
    elif [[ -f "$DIRB_PATH" ]]; then
        ln -sf "$DIRB_PATH" "$WORDLIST"
        info "Linked dirb common.txt"
    else
        warn "No wordlist found. Install seclists: sudo apt install seclists"
        warn "Or manually place a wordlist at: $WORDLIST"
    fi
fi

# ── Launch pipeline ───────────────────────────────────────────────────────────
cd "$SCRIPT_DIR"
exec python3 main.py "$@"
