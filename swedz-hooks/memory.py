"""
memory.py
---------
Provides :class:`MemoryProtection`, a context manager that temporarily changes
the memory-protection flags of a page in a remote process via
``kernel32.VirtualProtectEx``, performs an operation, then restores the
original flags on exit.
"""

import ctypes
import ctypes.wintypes
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .process import Process

# Common Win32 page-protection constants
PAGE_EXECUTE_READWRITE = 0x40
PAGE_READWRITE = 0x04


class MemoryProtection:
    """Context manager that changes page protection around a memory write.

    Parameters
    ----------
    process:
        An attached :class:`~swedz_hooks.process.Process` instance.
    address:
        The target virtual address inside the remote process.
    size:
        Number of bytes whose protection should be changed.
    new_protect:
        The desired ``PAGE_*`` flag (default: ``PAGE_EXECUTE_READWRITE``).

    Examples
    --------
    >>> with MemoryProtection(proc, addr, len(payload)) as mp:
    ...     proc.write_bytes(addr, payload)
    """

    def __init__(
        self,
        process: "Process",
        address: int,
        size: int,
        new_protect: int = PAGE_EXECUTE_READWRITE,
    ) -> None:
        self.process = process
        self.address = address
        self.size = size
        self.new_protect = new_protect
        self._old_protect = ctypes.wintypes.DWORD(0)

    # ------------------------------------------------------------------
    # Context-manager protocol
    # ------------------------------------------------------------------

    def __enter__(self) -> "MemoryProtection":
        """Apply the new protection flags and save the old ones."""
        kernel32 = ctypes.windll.kernel32
        success = kernel32.VirtualProtectEx(
            self.process.handle,
            ctypes.c_void_p(self.address),
            ctypes.c_size_t(self.size),
            ctypes.c_ulong(self.new_protect),
            ctypes.byref(self._old_protect),
        )
        if not success:
            raise ctypes.WinError(ctypes.get_last_error())
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        """Restore the original protection flags."""
        kernel32 = ctypes.windll.kernel32
        dummy = ctypes.wintypes.DWORD(0)
        kernel32.VirtualProtectEx(
            self.process.handle,
            ctypes.c_void_p(self.address),
            ctypes.c_size_t(self.size),
            self._old_protect,
            ctypes.byref(dummy),
        )
        # Do not suppress exceptions
        return False

    # ------------------------------------------------------------------
    # Static convenience method
    # ------------------------------------------------------------------

    @staticmethod
    def write_bytes_safe(process: "Process", address: int, data: bytes) -> None:
        """Write *data* to *address* after temporarily unlocking the page.

        This combines :class:`MemoryProtection` and
        :py:meth:`~swedz_hooks.process.Process.write_bytes` in a single call.

        Parameters
        ----------
        process:
            An attached :class:`~swedz_hooks.process.Process` instance.
        address:
            Destination address in the remote process.
        data:
            Raw bytes to write.

        Raises
        ------
        ctypes.WinError
            If ``VirtualProtectEx`` fails.
        OSError
            If the underlying pymem write fails.
        """
        with MemoryProtection(process, address, len(data)):
            process.write_bytes(address, data)
