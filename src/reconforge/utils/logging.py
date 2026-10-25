"""Logging configuration for ReconForge."""

import logging
import sys

from rich.logging import RichHandler


def setup_logging(level: str = "INFO") -> None:
    """Configure structured logging using Rich."""
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=numeric_level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[
            RichHandler(
                rich_tracebacks=True,
                show_path=False,
                tracebacks_suppress=[sys],
            )
        ],
    )
