"""Abstract base class and sanitization helpers for service fingerprinting probes."""

import asyncio
import logging
import re
from abc import ABC, abstractmethod
from collections.abc import Sequence

from reconforge.fingerprinting.models import ServiceFingerprint

logger = logging.getLogger("reconforge.probes.base")


def sanitize_banner(raw: bytes | str, max_length: int = 256) -> str:
    """Sanitize and truncate raw protocol banners.

    - Strips non-printable ASCII / control characters.
    - Limits string length to prevent memory bloat and log pollution.
    - Prevents terminal escape injection.
    """
    if isinstance(raw, bytes):
        text = raw.decode("latin-1", errors="replace")
    else:
        text = str(raw)

    # Remove non-printable control characters (except common whitespace)
    cleaned = "".join(ch if (ch.isprintable() or ch in (" ", "\t")) else " " for ch in text)
    # Collapse multiple spaces
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned[:max_length]


async def safe_close_writer(writer: asyncio.StreamWriter | None) -> None:
    """Safely terminate and wait for an asyncio socket writer to close without unhandled exceptions."""
    if writer is None:
        return
    try:
        writer.close()
        await writer.wait_closed()
    except Exception as err:
        logger.debug("Socket writer close suppressed: %s", err)


class BaseServiceProbe(ABC):
    """Abstract interface for protocol-specific service identification probes."""

    name: str = "generic"
    default_ports: Sequence[int] = ()

    @abstractmethod
    async def probe(self, ip: str, port: int, timeout: float = 3.0) -> ServiceFingerprint | None:
        """Execute a non-intrusive protocol probe against an open target port.

        Returns:
            ServiceFingerprint if service responded to this protocol probe; None otherwise.
        """
        raise NotImplementedError
