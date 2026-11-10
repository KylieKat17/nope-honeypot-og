"""Config loading. Defaults live here, config.yaml only overrides"""

import copy
from pathlib import Path

import yaml

DEFAULTS = {
    "db_path": "nope.db",
    "listen_host": "0.0.0.0",
    "decoys": {
        "ssh": {"enabled": True, "port": 2222},
        "redis": {"enabled": True, "port": 6379},
    },
    "weights": {"connect": 1, "probe": 2, "auth": 5, "exploit": 10},
    "half_life": 300,
    "alert_threshold": 5,
    "block_threshold": 15,
    "block_seconds": 600,
    "whitelist": ["127.0.0.0/8", "::1"],
}

SEARCH_PATHS = [Path("config.yaml"), Path("/etc/nope/config.yaml")]


def _merge(base, override):
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _merge(base[key], value)
        else:
            base[key] = value
    return base


def load(path=None):
    """Return the config dict. Uses `path` if given, else the first file found"""
    cfg = copy.deepcopy(DEFAULTS)
    candidates = [Path(path)] if path else SEARCH_PATHS
    for candidate in candidates:
        if candidate.is_file():
            with open(candidate) as fh:
                data = yaml.safe_load(fh) or {}
            return _merge(cfg, data)
        if path:
            raise FileNotFoundError(f"config file not found: {path}")
    return cfg
