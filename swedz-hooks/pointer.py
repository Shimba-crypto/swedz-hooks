"""
pointer.py
----------
Provides :class:`PointerResolver` for following multi-level pointer chains
(base address + list of offsets) as used in many games and applications.
"""

import struct
import logging
from typing import List, Union, TYPE_CHECKING

if TYPE_CHECKING:
    from .process import Process

logger = logging.getLogger(__name__)

# Supported scalar types for read/write operations
_SCALAR_TYPES = {
    "int":    ("i", 4),
    "uint":   ("I", 4),
    "float":  ("f", 4),
    "double": ("d", 8),
    "int64":  ("q", 8),
    "uint64": ("Q", 8),
    "short":  ("h", 2),
    "byte":   ("B", 1),
}

# Pointer sizes by platform (we assume 8 bytes on 64-bit Windows)
_PTR_FMT = "<Q"  # little-endian unsigned 64-bit
_PTR_SIZE = 8


class PointerResolver:
    """Resolve multi-level pointer chains in a remote Windows process.

    A *pointer chain* consists of a *base address* (often a module base plus a
    static offset) followed by one or more *offsets*.  At each level the
    resolver reads a pointer-sized value from the current address, adds the
    next offset, and repeats until the final address is reached.

    Parameters
    ----------
    process:
        An attached :class:`~swedz_hooks.process.Process` instance.

    Examples
    --------
    >>> resolver = PointerResolver(proc)
    >>> final = resolver.resolve(module_base + 0x1A3C50, [0x10, 0x4, 0x58])
    >>> value  = resolver.resolve_and_read(module_base + 0x1A3C50,
    ...                                    [0x10, 0x4, 0x58], 'float')
    """

    def __init__(self, process: "Process") -> None:
        self.process = process

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def resolve(self, base_address: int, offsets: List[int]) -> int:
        """Walk a pointer chain and return the final virtual address.

        Parameters
        ----------
        base_address:
            The starting address (e.g. module base + static offset).
        offsets:
            Sequence of offsets to apply at each indirection level.  The
            chain is: ``ptr = *(base_address) + offsets[0]``,
            ``ptr = *(ptr) + offsets[1]``, …

        Returns
        -------
        int
            The final resolved address (before reading a value from it).

        Raises
        ------
        OSError
            If any pointer dereference fails (invalid memory).

        Notes
        -----
        If *offsets* is empty the function returns *base_address* unchanged.
        """
        if not offsets:
            return base_address

        current = base_address
        for i, offset in enumerate(offsets):
            try:
                raw = self.process.read_bytes(current, _PTR_SIZE)
                (ptr,) = struct.unpack(_PTR_FMT, raw)
            except OSError as exc:
                raise OSError(
                    f"Pointer dereference failed at level {i} "
                    f"(address=0x{current:X}): {exc}"
                ) from exc

            current = ptr + offset
            logger.debug(
                "resolve level %d: 0x%X -> 0x%X + 0x%X = 0x%X",
                i, ptr, ptr, offset, current,
            )

        return current

    def resolve_and_read(
        self,
        base_address: int,
        offsets: List[int],
        data_type: str = "int",
    ) -> Union[int, float]:
        """Resolve a pointer chain, then read a scalar value from the result.

        Parameters
        ----------
        base_address:
            The starting address.
        offsets:
            Pointer-chain offsets (same semantics as :meth:`resolve`).
        data_type:
            One of ``'int'``, ``'uint'``, ``'float'``, ``'double'``,
            ``'int64'``, ``'uint64'``, ``'short'``, ``'byte'``.

        Returns
        -------
        int or float
            The value read from the resolved address.

        Raises
        ------
        KeyError
            If *data_type* is not recognised.
        OSError
            If any memory read fails.
        """
        if data_type not in _SCALAR_TYPES:
            raise KeyError(
                f"Unknown data_type {data_type!r}. "
                f"Choose from: {sorted(_SCALAR_TYPES)}"
            )
        final_addr = self.resolve(base_address, offsets)
        fmt_char, size = _SCALAR_TYPES[data_type]
        raw = self.process.read_bytes(final_addr, size)
        (value,) = struct.unpack(f"<{fmt_char}", raw)
        logger.debug(
            "resolve_and_read: 0x%X -> %r (%s)", final_addr, value, data_type
        )
        return value

    def resolve_and_write(
        self,
        base_address: int,
        offsets: List[int],
        value: Union[int, float],
        data_type: str = "int",
    ) -> None:
        """Resolve a pointer chain, then write a scalar value to the result.

        Parameters
        ----------
        base_address:
            The starting address.
        offsets:
            Pointer-chain offsets (same semantics as :meth:`resolve`).
        value:
            The value to write.
        data_type:
            One of ``'int'``, ``'uint'``, ``'float'``, ``'double'``,
            ``'int64'``, ``'uint64'``, ``'short'``, ``'byte'``.

        Raises
        ------
        KeyError
            If *data_type* is not recognised.
        OSError
            If any memory operation fails.
        """
        if data_type not in _SCALAR_TYPES:
            raise KeyError(
                f"Unknown data_type {data_type!r}. "
                f"Choose from: {sorted(_SCALAR_TYPES)}"
            )
        final_addr = self.resolve(base_address, offsets)
        fmt_char, _ = _SCALAR_TYPES[data_type]
        payload = struct.pack(f"<{fmt_char}", value)
        self.process.write_bytes_safe(final_addr, payload)
        logger.debug(
            "resolve_and_write: 0x%X <- %r (%s)", final_addr, value, data_type
        )
