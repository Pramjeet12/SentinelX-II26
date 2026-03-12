"""Logging setup for SentinelX."""

import logging
import sys
from pathlib import Path

# Log file lives in data/ directory
_LOG_DIR = Path(__file__).parent.parent / "data"
_LOG_DIR.mkdir(exist_ok=True)
_LOG_FILE = _LOG_DIR / "sentinelx.log"

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


def setup_logger(name: str = "sentinelx", level: int = logging.DEBUG) -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(level)

    # Console handler (INFO and above)
    console_fmt = logging.Formatter(
        "[%(asctime)s] %(levelname)-8s %(name)-18s │ %(message)s",
        datefmt="%H:%M:%S",
    )
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.INFO)
    console.setFormatter(console_fmt)
    logger.addHandler(console)

    # File handler (DEBUG and above — captures everything)
    logger.addHandler(_get_file_handler())

    return logger
