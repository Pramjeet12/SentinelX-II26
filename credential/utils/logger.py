"""Logging setup for Credential Leak Monitor."""

import logging
import sys
from pathlib import Path

_LOG_DIR = Path(__file__).parent.parent / "data"
_LOG_DIR.mkdir(exist_ok=True)
_LOG_FILE = _LOG_DIR / "credleak.log"

_file_handler: logging.FileHandler | None = None


def _get_file_handler() -> logging.FileHandler:
    global _file_handler
    if _file_handler is None:
        _file_handler = logging.FileHandler(_LOG_FILE, encoding="utf-8")
        _file_handler.setLevel(logging.DEBUG)
        _file_handler.setFormatter(logging.Formatter(
            "[%(asctime)s] %(levelname)-8s %(name)-18s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))
    return _file_handler


def setup_logger(name: str = "credleak", level: int = logging.DEBUG) -> logging.Logger:
    logger = logging.getLogger(f"credleak.{name}")
    if logger.handlers:
        return logger
    logger.setLevel(level)

    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.INFO)
    console.setFormatter(logging.Formatter(
        "[%(asctime)s] %(levelname)-8s %(name)-18s | %(message)s",
        datefmt="%H:%M:%S",
    ))
    logger.addHandler(console)
    logger.addHandler(_get_file_handler())

    return logger
