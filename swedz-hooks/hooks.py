"""
hooks.py
--------
Provides :class:`Hooks`, which manages a collection of
:class:`~swedz_hooks.breakpoint.Breakpoint` objects and runs the Win32
debug-event loop (``WaitForDebugEvent`` / ``ContinueDebugEvent``).
"""

import ctypes
import ctypes.wintypes
import logging
from typing import Callable, Dict, Optional, TYPE_CHECKING

from .breakpoint import Breakpoint

if TYPE_CHECKING:
    from .process import Process

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Win32 debug-event constants
# ---------------------------------------------------------------------------
EXCEPTION_DEBUG_EVENT = 1
CREATE_THREAD_DEBUG_EVENT = 2
CREATE_PROCESS_DEBUG_EVENT = 3
EXIT_THREAD_DEBUG_EVENT = 4
EXIT_PROCESS_DEBUG_EVENT = 5
LOAD_DLL_DEBUG_EVENT = 6
UNLOAD_DLL_DEBUG_EVENT = 7
OUTPUT_DEBUG_STRING_EVENT = 8
RIP_EVENT = 9

EXCEPTION_BREAKPOINT = 0x80000003
EXCEPTION_SINGLE_STEP = 0x80000004

DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001

INFINITE = 0xFFFFFFFF


# ---------------------------------------------------------------------------
# Minimal ctypes structures for DEBUG_EVENT
# ---------------------------------------------------------------------------

class _EXCEPTION_RECORD(ctypes.Structure):
    pass  # forward declaration


_EXCEPTION_RECORD._fields_ = [
    ("ExceptionCode", ctypes.wintypes.DWORD),
    ("ExceptionFlags", ctypes.wintypes.DWORD),
    ("ExceptionRecord", ctypes.POINTER(_EXCEPTION_RECORD)),
    ("ExceptionAddress", ctypes.c_void_p),
    ("NumberParameters", ctypes.wintypes.DWORD),
    ("ExceptionInformation", ctypes.c_ulong_p if hasattr(ctypes, "c_ulong_p")
     else ctypes.c_ulong * 15),
]


class _EXCEPTION_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("ExceptionRecord", _EXCEPTION_RECORD),
        ("dwFirstChance", ctypes.wintypes.DWORD),
    ]


class _DEBUG_EVENT_UNION(ctypes.Union):
    _fields_ = [
        ("Exception", _EXCEPTION_DEBUG_INFO),
        # Other event types omitted for brevity; reserved bytes cover them.
        ("_reserved", ctypes.c_byte * 160),
    ]


class DEBUG_EVENT(ctypes.Structure):
    """Minimal Win32 ``DEBUG_EVENT`` structure for exception handling."""

    _fields_ = [
        ("dwDebugEventCode", ctypes.wintypes.DWORD),
        ("dwProcessId", ctypes.wintypes.DWORD),
        ("dwThreadId", ctypes.wintypes.DWORD),
        ("u", _DEBUG_EVENT_UNION),
    ]


class Hooks:
    """Manage INT3 breakpoints and the Win32 debug-event loop.

    Parameters
    ----------
    process:
        An attached (and debug-attached) :class:`~swedz_hooks.process.Process`
        instance.

    Examples
    --------
    >>> proc = Process("target.exe")
    >>> proc.debug_attach()
    >>> hooks = Hooks(proc)
    >>> hooks.add_breakpoint(0x00401000, lambda ctx: print("hit!"))
    >>> hooks.wait_for_events()   # blocks until the process exits
    """

    def __init__(self, process: "Process") -> None:
        self.process = process
        self._breakpoints: Dict[int, Breakpoint] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_breakpoint(self, address: int, callback: Callable) -> Breakpoint:
        """Create and enable an INT3 breakpoint at *address*.

        Parameters
        ----------
        address:
            Target virtual address.
        callback:
            Callable invoked (with the raw ``DEBUG_EVENT``) when the
            breakpoint fires.

        Returns
        -------
        Breakpoint
            The enabled :class:`~swedz_hooks.breakpoint.Breakpoint` object.

        Raises
        ------
        ValueError
            If a breakpoint already exists at *address*.
        """
        if address in self._breakpoints:
            raise ValueError(
                f"A breakpoint at 0x{address:X} already exists.  "
                f"Remove it first with remove_breakpoint()."
            )
        bp = Breakpoint(self.process, address, callback)
        bp.enable()
        self._breakpoints[address] = bp
        logger.info("Breakpoint added at 0x%X.", address)
        return bp

    def remove_breakpoint(self, address: int) -> None:
        """Disable and remove the breakpoint at *address*.

        Parameters
        ----------
        address:
            Address of the breakpoint to remove.

        Raises
        ------
        KeyError
            If no breakpoint exists at *address*.
        """
        bp = self._breakpoints.pop(address)
        if bp.enabled:
            bp.disable()
        logger.info("Breakpoint removed from 0x%X.", address)

    def wait_for_events(self) -> None:
        """Block and dispatch Win32 debug events until the process exits.

        The loop calls ``WaitForDebugEvent`` indefinitely and dispatches
        ``EXCEPTION_BREAKPOINT`` events to the matching
        :class:`~swedz_hooks.breakpoint.Breakpoint` callback.

        Unhandled events and all other exceptions are continued with
        ``DBG_EXCEPTION_NOT_HANDLED`` or ``DBG_CONTINUE`` as appropriate.

        Raises
        ------
        ctypes.WinError
            If ``WaitForDebugEvent`` returns ``FALSE``.

        .. note::
            This method *blocks* the calling thread.  Run it from a dedicated
            thread if you need concurrent work.
        """
        kernel32 = ctypes.windll.kernel32
        debug_event = DEBUG_EVENT()

        logger.info("Entering debug event loop for PID=%d.", self.process.pid)

        while True:
            result = kernel32.WaitForDebugEvent(
                ctypes.byref(debug_event),
                ctypes.wintypes.DWORD(INFINITE),
            )
            if not result:
                raise ctypes.WinError(ctypes.get_last_error())

            event_code = debug_event.dwDebugEventCode
            continue_status = DBG_CONTINUE

            if event_code == EXIT_PROCESS_DEBUG_EVENT:
                logger.info("Target process exited — leaving debug loop.")
                kernel32.ContinueDebugEvent(
                    debug_event.dwProcessId,
                    debug_event.dwThreadId,
                    ctypes.wintypes.DWORD(DBG_CONTINUE),
                )
                break

            if event_code == EXCEPTION_DEBUG_EVENT:
                exc_code = debug_event.u.Exception.ExceptionRecord.ExceptionCode
                exc_addr = self._get_exception_address(debug_event)

                if exc_code == EXCEPTION_BREAKPOINT:
                    # Adjust for the INT3 (EIP is already past the 0xCC)
                    bp_addr = exc_addr - 1 if exc_addr else None
                    if bp_addr in self._breakpoints:
                        self._breakpoints[bp_addr].hit(debug_event)
                    else:
                        logger.debug(
                            "Unhandled EXCEPTION_BREAKPOINT at 0x%X.",
                            exc_addr or 0,
                        )
                        continue_status = DBG_EXCEPTION_NOT_HANDLED

                elif exc_code == EXCEPTION_SINGLE_STEP:
                    # Re-enable the preceding breakpoint after single-step
                    logger.debug("EXCEPTION_SINGLE_STEP at 0x%X.", exc_addr or 0)

                else:
                    continue_status = DBG_EXCEPTION_NOT_HANDLED

            kernel32.ContinueDebugEvent(
                debug_event.dwProcessId,
                debug_event.dwThreadId,
                ctypes.wintypes.DWORD(continue_status),
            )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_exception_address(self, debug_event: DEBUG_EVENT) -> Optional[int]:
        """Extract the exception address from a ``DEBUG_EVENT`` structure.

        Parameters
        ----------
        debug_event:
            A populated :class:`DEBUG_EVENT` ctypes structure.

        Returns
        -------
        int or None
            The faulting virtual address, or ``None`` if unavailable.

        .. note::
            This is a best-effort stub.  A production implementation should
            also handle 32-bit vs 64-bit address widths explicitly.
        """
        try:
            raw = debug_event.u.Exception.ExceptionRecord.ExceptionAddress
            return raw if raw is not None else None
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Dunder
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        return (
            f"<Hooks process={self.process!r} "
            f"breakpoints={list(f'0x{a:X}' for a in self._breakpoints)}>"
        )
