"""
pattern.py
----------
Provides :class:`PatternScanner` for AOB (Array-of-Bytes) pattern scanning
with single- or double-question-mark wildcard support (``?`` / ``??``).
"""

import logging
from typing import List, Optional, Tuple, TYPE_CHECKING

import pymem
import pymem.pattern
import pymem.process

if TYPE_CHECKING:
    from .process import Process

logger = logging.getLogger(__name__)

# Sentinel used internally to represent a wildcard byte slot
_WILDCARD = None


class PatternScanner:
    """Scan a remote process's memory for byte patterns.

    Supports the common AOB notation where ``?`` or ``??`` act as single-byte
    wildcards that match any value.

    Parameters
    ----------
    process:
        An attached :class:`~swedz_hooks.process.Process` instance.

    Examples
    --------
    >>> scanner = PatternScanner(proc)
    >>> hits = scanner.scan_module("ntdll.dll", "48 8B C4 ?? ?? 41 56")
    >>> print(hex(hits[0]))
    """

    def __init__(self, process: "Process") -> None:
        self.process = process

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_module(self, module_name: str, pattern: str) -> List[int]:
        """Scan a loaded module for *pattern*.

        Parameters
        ----------
        module_name:
            Name of the module to scan (e.g. ``"ntdll.dll"``).  The module
            must already be loaded in the target process.
        pattern:
            AOB pattern string.  Bytes are expressed as two-digit hex values
            separated by spaces; ``?`` or ``??`` are wildcards, e.g.
            ``"48 8B C4 ?? 41 56"``.

        Returns
        -------
        list[int]
            Sorted list of virtual addresses where the pattern matched.

        Raises
        ------
        ValueError
            If *module_name* is not found in the process.
        OSError
            If a memory read fails during the scan.
        """
        # Resolve the module's base address and size
        module = pymem.process.module_from_name(self.process.handle, module_name)
        if module is None:
            raise ValueError(
                f"Module {module_name!r} not found in process PID={self.process.pid}."
            )

        base = module.lpBaseOfDll
        size = module.SizeOfImage

        logger.debug(
            "Scanning module %s (base=0x%X, size=0x%X) for pattern: %s",
            module_name,
            base,
            size,
            pattern,
        )

        parts, mask = self._pattern_to_parts(pattern)
        return self._scan_region(base, size, parts, mask)

    def scan_all(self, pattern: str) -> List[int]:
        """Scan the entire virtual address space of the attached process.

        Internally delegates to ``pymem.pattern.pattern_scan_all``.

        Parameters
        ----------
        pattern:
            AOB pattern string (same format as :meth:`scan_module`).

        Returns
        -------
        list[int]
            List of virtual addresses where the pattern matched.

        .. note::
            Scanning the full address space can be slow for large processes.
        """
        byte_array, mask_str = self._pattern_to_pymem_args(pattern)
        results = pymem.pattern.pattern_scan_all(
            self.process.handle,
            byte_array,
            return_multiple=True,
        )
        return list(results) if results else []

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _pattern_to_parts(
        self, pattern: str
    ) -> Tuple[List[Optional[int]], bytes]:
        """Parse a pattern string into a list of byte values / wildcards and a mask.

        Parameters
        ----------
        pattern:
            AOB pattern string.

        Returns
        -------
        tuple
            ``(parts, mask)`` where *parts* is a list whose entries are either
            an ``int`` (0–255) or ``None`` (wildcard), and *mask* is a
            ``bytes`` object using ``'x'`` for concrete bytes and ``'?'`` for
            wildcards (IDA/Cheat Engine style).

        Examples
        --------
        >>> parts, mask = scanner._pattern_to_parts("48 8B ?? C4")
        >>> parts
        [0x48, 0x8B, None, 0xC4]
        >>> mask
        b'xx?x'
        """
        tokens = pattern.strip().split()
        parts: List[Optional[int]] = []
        mask_chars: List[str] = []

        for token in tokens:
            if token in ("?", "??"):
                parts.append(_WILDCARD)
                mask_chars.append("?")
            else:
                parts.append(int(token, 16))
                mask_chars.append("x")

        return parts, "".join(mask_chars).encode()

    def _pattern_to_pymem_args(self, pattern: str) -> Tuple[bytes, str]:
        """Convert a pattern string to the byte-array / mask-string that
        ``pymem.pattern`` functions expect.

        Returns
        -------
        tuple
            ``(byte_array, mask)`` where wildcard bytes are ``0x00`` in the
            byte array and ``'?'`` in the mask.
        """
        parts, mask = self._pattern_to_parts(pattern)
        byte_array = bytes(b if b is not None else 0x00 for b in parts)
        return byte_array, mask.decode()

    def _scan_region(
        self,
        base: int,
        size: int,
        parts: List[Optional[int]],
        mask: bytes,
    ) -> List[int]:
        """Brute-force scan *size* bytes starting at *base*.

        Parameters
        ----------
        base:
            Start virtual address.
        size:
            Number of bytes to read and scan.
        parts:
            Parsed pattern (list of ints / Nones from :meth:`_pattern_to_parts`).
        mask:
            Corresponding mask bytes (``b'x'`` / ``b'?'``).

        Returns
        -------
        list[int]
            Sorted list of match addresses.
        """
        pattern_len = len(parts)
        if pattern_len == 0:
            return []

        try:
            data = self.process.read_bytes(base, size)
        except OSError as exc:
            logger.warning("Could not read module region: %s", exc)
            return []

        hits: List[int] = []
        limit = len(data) - pattern_len + 1

        for i in range(limit):
            if all(
                mask[j:j+1] == b"?" or data[i + j] == parts[j]
                for j, _ in enumerate(parts)
            ):
                hits.append(base + i)

        logger.debug("Pattern scan found %d hit(s).", len(hits))
        return hits
