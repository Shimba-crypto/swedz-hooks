"""
process.py
----------
Provides :class:`Process`, the central object that attaches to a running
Windows process via *pymem* and exposes memory-read/write primitives as
well as convenience accessors for the rest of the library.
"""

import ctypes
import ctypes.wintypes
import struct
import logging
from typing import Callable, Optional, Union

import pymem
import pymem.process

from .memory import MemoryProtection
from .watchdog import ProcessWatchdog
from .structs import StructHelpers

logger = logging.getLogger(__name__)


class Process:
    """Attach to a running Windows process and expose memory I/O helpers.

    Parameters
    ----------
    name_or_pid:
        Either a process name (e.g. ``"notepad.exe"``) or an integer PID.
        When a name is supplied the *first* matching process is used.

    Attributes
    ----------
    pm : pymem.Pymem
        The underlying pymem instance.
    pid : int
        Process identifier of the attached process.
    handle : int
        Win32 process handle opened by pymem (``PROCESS_ALL_ACCESS``).

    Raises
    ------
    pymem.exception.ProcessNotFound
        If *name_or_pid* does not match a running process.
    pymem.exception.CouldNotOpenProcess
        If the handle cannot be opened (insufficient privileges).

    Examples
    --------
    >>> proc = Process("notepad.exe")
    >>> value = proc.read_int(some_address)
    """

    def __init__(self, name_or_pid: Union[str, int]) -> None:
        if isinstance(name_or_pid, int):
            self.pm = pymem.Pymem()
            self.pm.open_process_from_id(name_or_pid)
        else:
            self.pm = pymem.Pymem(name_or_pid)

        self.pid: int = self.pm.process_id
        self.handle: int = self.pm.process_handle
        self._structs: Optional[StructHelpers] = None
        logger.info("Attached to process PID=%d.", self.pid)

    # ------------------------------------------------------------------
    # Debug attachment
    # ------------------------------------------------------------------

    def debug_attach(self) -> None:
        """Attach as a debugger to this process using ``DebugActiveProcess``.

        This is required before breakpoints or debug events can be used.

        Raises
        ------
        ctypes.WinError
            If ``DebugActiveProcess`` returns ``FALSE``.
        """
        kernel32 = ctypes.windll.kernel32
        success = kernel32.DebugActiveProcess(ctypes.wintypes.DWORD(self.pid))
        if not success:
            raise ctypes.WinError(ctypes.get_last_error())
        logger.debug("DebugActiveProcess succeeded for PID=%d.", self.pid)

    # ------------------------------------------------------------------
    # Raw read / write
    # ------------------------------------------------------------------

    def read_bytes(self, address: int, length: int) -> bytes:
        """Read *length* raw bytes from *address*.

        Parameters
        ----------
        address:
            Virtual address to read from.
        length:
            Number of bytes to read.

        Returns
        -------
        bytes
            The raw bytes read from the process.

        Raises
        ------
        OSError
            If the read fails.
        """
        try:
            return self.pm.read_bytes(address, length)
        except pymem.exception.MemoryReadError as exc:
            raise OSError(f"read_bytes failed at 0x{address:X}: {exc}") from exc

    def write_bytes(self, address: int, data: bytes) -> None:
        """Write raw *data* bytes to *address*.

        Parameters
        ----------
        address:
            Destination virtual address.
        data:
            Bytes to write.

        Raises
        ------
        OSError
            If the write fails.
        """
        try:
            self.pm.write_bytes(address, data, len(data))
        except pymem.exception.MemoryWriteError as exc:
            raise OSError(f"write_bytes failed at 0x{address:X}: {exc}") from exc

    # ------------------------------------------------------------------
    # Typed reads
    # ------------------------------------------------------------------

    def read_int(self, address: int) -> int:
        """Read a signed 32-bit integer from *address*.

        Returns
        -------
        int
        """
        return self.pm.read_int(address)

    def read_float(self, address: int) -> float:
        """Read a 32-bit IEEE-754 float from *address*.

        Returns
        -------
        float
        """
        return self.pm.read_float(address)

    # ------------------------------------------------------------------
    # Typed writes
    # ------------------------------------------------------------------

    def write_int(self, address: int, value: int) -> None:
        """Write a signed 32-bit integer to *address*.

        Parameters
        ----------
        value:
            Integer value to write.
        """
        self.pm.write_int(address, value)

    def write_float(self, address: int, value: float) -> None:
        """Write a 32-bit IEEE-754 float to *address*.

        Parameters
        ----------
        value:
            Float value to write.
        """
        self.pm.write_float(address, value)

    # ------------------------------------------------------------------
    # Safe write (unlocks page first)
    # ------------------------------------------------------------------

    def write_bytes_safe(self, address: int, data: bytes) -> None:
        """Write *data* to *address* after temporarily relaxing page protection.

        Internally uses :class:`~swedz_hooks.memory.MemoryProtection` to call
        ``VirtualProtectEx`` with ``PAGE_EXECUTE_READWRITE`` before writing
        and to restore the original flags afterwards.

        Parameters
        ----------
        address:
            Destination virtual address.
        data:
            Bytes to write.

        Raises
        ------
        ctypes.WinError
            If ``VirtualProtectEx`` fails.
        OSError
            If the memory write fails.
        """
        MemoryProtection.write_bytes_safe(self, address, data)

    # ------------------------------------------------------------------
    # Watchdog
    # ------------------------------------------------------------------

    def watch(
        self,
        on_exit: Optional[Callable[[], None]] = None,
        interval: float = 1.0,
    ) -> ProcessWatchdog:
        """Create and start a :class:`~swedz_hooks.watchdog.ProcessWatchdog`.

        Parameters
        ----------
        on_exit:
            Optional callback invoked when the process exits.
        interval:
            Poll interval in seconds (default: ``1.0``).

        Returns
        -------
        ProcessWatchdog
            An already-started watchdog instance.
        """
        wd = ProcessWatchdog(self, check_interval=interval, on_exit=on_exit)
        wd.start()
        return wd

    # ------------------------------------------------------------------
    # Struct helpers accessor
    # ------------------------------------------------------------------

    @property
    def structs(self) -> StructHelpers:
        """Lazily-initialised :class:`~swedz_hooks.structs.StructHelpers` instance.

        Returns
        -------
        StructHelpers
        """
        if self._structs is None:
            self._structs = StructHelpers(self)
        return self._structs

    # ------------------------------------------------------------------
    # Dunder
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        return f"<Process pid={self.pid}>"
