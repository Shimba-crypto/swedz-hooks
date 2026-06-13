"""
structs.py
----------
Provides :class:`StructHelpers`, a collection of high-level helpers for
reading and writing common in-process data structures such as null-terminated
strings, typed arrays, and 2-D / 3-D vectors.
"""

import struct
from typing import List, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from .process import Process

# ---------------------------------------------------------------------------
# Mapping of friendly type names → struct format characters
# ---------------------------------------------------------------------------
_TYPE_FMT = {
    "int":    ("i", 4),
    "uint":   ("I", 4),
    "short":  ("h", 2),
    "ushort": ("H", 2),
    "long":   ("l", 4),
    "ulong":  ("L", 4),
    "float":  ("f", 4),
    "double": ("d", 8),
    "int64":  ("q", 8),
    "uint64": ("Q", 8),
    "byte":   ("B", 1),
}


class StructHelpers:
    """High-level memory-structure helpers attached to a :class:`~swedz_hooks.process.Process`.

    You rarely construct this class directly; use the
    :attr:`~swedz_hooks.process.Process.structs` property instead.

    Parameters
    ----------
    process:
        An attached :class:`~swedz_hooks.process.Process` instance whose
        ``read_bytes`` / ``write_bytes`` methods are used for all I/O.
    """

    def __init__(self, process: "Process") -> None:
        self._proc = process

    # ------------------------------------------------------------------
    # Strings
    # ------------------------------------------------------------------

    def read_string(
        self,
        address: int,
        max_len: int = 256,
        encoding: str = "utf-8",
    ) -> str:
        """Read a null-terminated string from *address*.

        Parameters
        ----------
        address:
            Virtual address of the first character in the remote process.
        max_len:
            Maximum number of bytes to read before giving up (safety cap).
        encoding:
            Character encoding used to decode the raw bytes (default: UTF-8).

        Returns
        -------
        str
            The decoded string, stripped at the first null byte.

        Raises
        ------
        OSError
            If the memory read fails.
        UnicodeDecodeError
            If the bytes cannot be decoded with *encoding*.
        """
        raw: bytes = self._proc.read_bytes(address, max_len)
        # Trim at the first null terminator
        null_idx = raw.find(b"\x00")
        if null_idx != -1:
            raw = raw[:null_idx]
        return raw.decode(encoding, errors="replace")

    def write_string(
        self,
        address: int,
        text: str,
        encoding: str = "utf-8",
    ) -> None:
        """Write a null-terminated string to *address*.

        Parameters
        ----------
        address:
            Destination address in the remote process.
        text:
            Python string to encode and write.
        encoding:
            Target encoding (default: UTF-8).

        Raises
        ------
        OSError
            If the memory write fails.
        """
        payload: bytes = text.encode(encoding) + b"\x00"
        self._proc.write_bytes(address, payload)

    # ------------------------------------------------------------------
    # Arrays
    # ------------------------------------------------------------------

    def read_array(
        self,
        address: int,
        element_type: str = "int",
        count: int = 10,
    ) -> List:
        """Read *count* consecutive values of *element_type* starting at *address*.

        Parameters
        ----------
        address:
            Base address of the array in the remote process.
        element_type:
            One of ``'int'``, ``'uint'``, ``'short'``, ``'ushort'``,
            ``'long'``, ``'ulong'``, ``'float'``, ``'double'``,
            ``'int64'``, ``'uint64'``, ``'byte'``.
        count:
            Number of elements to read.

        Returns
        -------
        list
            Python list of decoded values.

        Raises
        ------
        KeyError
            If *element_type* is not recognised.
        OSError
            If the memory read fails.
        """
        if element_type not in _TYPE_FMT:
            raise KeyError(
                f"Unknown element_type {element_type!r}. "
                f"Choose from: {sorted(_TYPE_FMT)}"
            )
        fmt_char, size = _TYPE_FMT[element_type]
        raw = self._proc.read_bytes(address, size * count)
        fmt = f"<{count}{fmt_char}"
        return list(struct.unpack(fmt, raw))

    # ------------------------------------------------------------------
    # Vectors
    # ------------------------------------------------------------------

    def read_vector_2d(
        self,
        address: int,
        coord_type: str = "float",
    ) -> Tuple:
        """Read a 2-D vector (X, Y) from *address*.

        Parameters
        ----------
        address:
            Base address of the vector structure.
        coord_type:
            Data type of each component (default: ``'float'``).

        Returns
        -------
        tuple
            ``(x, y)``
        """
        x, y = self.read_array(address, element_type=coord_type, count=2)
        return (x, y)

    def read_vector_3d(
        self,
        address: int,
        coord_type: str = "float",
    ) -> Tuple:
        """Read a 3-D vector (X, Y, Z) from *address*.

        Parameters
        ----------
        address:
            Base address of the vector structure.
        coord_type:
            Data type of each component (default: ``'float'``).

        Returns
        -------
        tuple
            ``(x, y, z)``
        """
        x, y, z = self.read_array(address, element_type=coord_type, count=3)
        return (x, y, z)

    def write_vector_3d(
        self,
        address: int,
        x,
        y,
        z,
        coord_type: str = "float",
    ) -> None:
        """Write a 3-D vector (X, Y, Z) to *address*.

        Parameters
        ----------
        address:
            Destination address in the remote process.
        x, y, z:
            Component values (must be compatible with *coord_type*).
        coord_type:
            Data type of each component (default: ``'float'``).

        Raises
        ------
        KeyError
            If *coord_type* is not recognised.
        OSError
            If the memory write fails.
        """
        if coord_type not in _TYPE_FMT:
            raise KeyError(
                f"Unknown coord_type {coord_type!r}. "
                f"Choose from: {sorted(_TYPE_FMT)}"
            )
        fmt_char, _ = _TYPE_FMT[coord_type]
        payload = struct.pack(f"<3{fmt_char}", x, y, z)
        self._proc.write_bytes(address, payload)
