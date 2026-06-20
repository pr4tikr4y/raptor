import os
import yaml
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SubfinderConfig:
    timeout: int = 30
    threads: int = 10
    resolvers: list = field(default_factory=lambda: ["1.1.1.1", "8.8.8.8"])
    sources: list = field(default_factory=list)
    all_sources: bool = False


@dataclass
class HttpxConfig:
    threads: int = 50
    timeout: int = 10
    follow_redirects: bool = True
    status_codes: list = field(default_factory=lambda: [200, 301, 302, 403, 404, 500])
    tech_detect: bool = True
    rate_limit: int = 150


@dataclass
class FfufConfig:
    threads: int = 40
    timeout: int = 10
    rate: int = 100
    wordlist: str = "wordlists/common.txt"
    extensions: str = "php,html,js,txt,json,bak"
    filter_codes: str = "404,400"
    recursion: bool = False
    recursion_depth: int = 2


@dataclass
class NucleiConfig:
    threads: int = 25
    timeout: int = 10
    rate_limit: int = 150
    severity: list = field(default_factory=lambda: ["critical", "high", "medium", "low"])
    templates: list = field(default_factory=list)
    exclude_tags: list = field(default_factory=lambda: ["dos", "fuzz"])
    retries: int = 1


@dataclass
class PipelineConfig:
    output_dir: str = "reports"
    log_level: str = "INFO"
    subfinder: SubfinderConfig = field(default_factory=SubfinderConfig)
    httpx: HttpxConfig = field(default_factory=HttpxConfig)
    ffuf: FfufConfig = field(default_factory=FfufConfig)
    nuclei: NucleiConfig = field(default_factory=NucleiConfig)
    skip_modules: list = field(default_factory=list)
    proxy: Optional[str] = None


def load_config(config_path: Optional[str] = None) -> PipelineConfig:
    if config_path is None or not os.path.exists(config_path):
        return PipelineConfig()

    with open(config_path) as f:
        raw = yaml.safe_load(f) or {}

    cfg = PipelineConfig()
    for key, val in raw.items():
        if key == "subfinder" and isinstance(val, dict):
            cfg.subfinder = SubfinderConfig(**val)
        elif key == "httpx" and isinstance(val, dict):
            cfg.httpx = HttpxConfig(**val)
        elif key == "ffuf" and isinstance(val, dict):
            cfg.ffuf = FfufConfig(**val)
        elif key == "nuclei" and isinstance(val, dict):
            cfg.nuclei = NucleiConfig(**val)
        elif hasattr(cfg, key):
            setattr(cfg, key, val)

    return cfg
