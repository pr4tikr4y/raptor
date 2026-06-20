import logging
import sys
from datetime import datetime


RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"
DIM = "\033[2m"


class ColorFormatter(logging.Formatter):
    LEVEL_COLORS = {
        logging.DEBUG: DIM + WHITE,
        logging.INFO: CYAN,
        logging.WARNING: YELLOW,
        logging.ERROR: RED,
        logging.CRITICAL: BOLD + RED,
    }

    PREFIXES = {
        logging.DEBUG: "[~]",
        logging.INFO: "[*]",
        logging.WARNING: "[!]",
        logging.ERROR: "[-]",
        logging.CRITICAL: "[X]",
    }

    def format(self, record):
        color = self.LEVEL_COLORS.get(record.levelno, WHITE)
        prefix = self.PREFIXES.get(record.levelno, "[*]")
        ts = datetime.now().strftime("%H:%M:%S")
        msg = record.getMessage()
        return f"{DIM}{ts}{RESET} {color}{prefix}{RESET} {msg}"


def get_logger(name: str = "recon", level: str = "INFO") -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(ColorFormatter())
    logger.addHandler(handler)
    return logger


def banner(target: str, modules: list):
    lines = [
        f"{BOLD}{CYAN}",
        "  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗",
        "  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║",
        "  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║",
        "  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║",
        "  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║",
        "  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝",
        f"{RESET}{DIM}  Attack Surface Discovery & Vuln Scanning Pipeline{RESET}",
        "",
        f"  {BOLD}Target  :{RESET} {GREEN}{target}{RESET}",
        f"  {BOLD}Modules :{RESET} {', '.join(modules)}",
        "",
    ]
    print("\n".join(lines))
