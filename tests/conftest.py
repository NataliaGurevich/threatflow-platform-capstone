"""Global test isolation from developer configuration and credentials."""

from __future__ import annotations

import os
from typing import Any

from threatflow.config import Settings

_MISSING = object()
_ORIGINAL_ENV_FILE: Any = _MISSING
_ORIGINAL_THREATFLOW_ENV: dict[str, str] = {}


def pytest_configure(config: Any) -> None:
    """Disable project dotenv loading before pytest imports test modules."""
    global _ORIGINAL_ENV_FILE, _ORIGINAL_THREATFLOW_ENV
    del config

    _ORIGINAL_ENV_FILE = Settings.model_config.get("env_file", _MISSING)
    Settings.model_config["env_file"] = None
    _ORIGINAL_THREATFLOW_ENV = {
        key: value for key, value in os.environ.items() if key.startswith("THREATFLOW_")
    }
    for key in _ORIGINAL_THREATFLOW_ENV:
        os.environ.pop(key, None)


def pytest_unconfigure(config: Any) -> None:
    """Restore the invoking shell after the test process finishes."""
    del config
    for key in tuple(os.environ):
        if key.startswith("THREATFLOW_"):
            os.environ.pop(key, None)
    os.environ.update(_ORIGINAL_THREATFLOW_ENV)
    if _ORIGINAL_ENV_FILE is _MISSING:
        Settings.model_config.pop("env_file", None)
    else:
        Settings.model_config["env_file"] = _ORIGINAL_ENV_FILE
