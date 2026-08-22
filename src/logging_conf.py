"""Central logging configuration, shared by app.py, api.py, and CLI scripts."""

from __future__ import annotations
import logging
import os


def configure_logging() -> None:
    level = os.environ.get("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # Quiet noisy third-party loggers unless explicitly debugging.
    if level != "DEBUG":
        logging.getLogger("urllib3").setLevel(logging.WARNING)
