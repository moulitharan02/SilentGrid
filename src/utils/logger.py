"""
Centralized logging configuration for nt-traffic-filter.
Creates two handlers: rotating file for app logs and a dedicated alert log.
"""

import logging
import os
from logging.handlers import RotatingFileHandler

from src.config.config import APP_LOG_PATH, ALERT_LOG_PATH, LOG_LEVEL, LOG_DIR

# Ensure log directory exists
os.makedirs(LOG_DIR, exist_ok=True)

_LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def _build_file_handler(path: str, level: int = logging.DEBUG) -> RotatingFileHandler:
    handler = RotatingFileHandler(
        path,
        maxBytes=10 * 1024 * 1024,  # 10 MB
        backupCount=5,
        encoding="utf-8",
    )
    handler.setLevel(level)
    handler.setFormatter(logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT))
    return handler


def _build_console_handler() -> logging.StreamHandler:
    handler = logging.StreamHandler()
    handler.setLevel(logging.INFO)
    handler.setFormatter(logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT))
    return handler


def get_logger(name: str) -> logging.Logger:
    """Return a configured logger for the given module name."""
    logger = logging.getLogger(name)

    if logger.handlers:
        return logger  # already configured

    numeric_level = getattr(logging, LOG_LEVEL.upper(), logging.INFO)
    logger.setLevel(numeric_level)
    logger.addHandler(_build_file_handler(APP_LOG_PATH))
    logger.addHandler(_build_console_handler())
    logger.propagate = False
    return logger


def get_alert_logger() -> logging.Logger:
    """Return a dedicated logger that writes only to the alerts log file."""
    logger = logging.getLogger("alerts")

    if logger.handlers:
        return logger

    logger.setLevel(logging.WARNING)
    logger.addHandler(_build_file_handler(ALERT_LOG_PATH, level=logging.WARNING))
    logger.addHandler(_build_console_handler())
    logger.propagate = False
    return logger
