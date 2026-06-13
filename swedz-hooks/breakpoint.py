"""
breakpoint.py
-------------
Provides :class:`Breakpoint`, which plants an INT3 (``0xCC``) byte at a
target address, intercepts the resulting debug exception, invokes a callback,
and then transparently single-steps past the original instruction before
re-enabling the breakpoint.
"""

import ctypes
import ctypes.wintypes
import logging
from typing import Callable, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .process import Process

logger = logging.getLogger(__name__)

# INT3 opcode
_INT3 = b"\xcc"


class Breakpoint:
    """Software (INT3) breakpoint for a remote Windows process.

    Parameters
    ----------
    process:
        The :class:`~swedz_hooks.process.Process` to which the breakpoint
        belongs.  The process must already be debug-attached via
        :meth:`~swedz_hooks.process.Process.debug_attach`.
    address:
        Virtual address at which to insert the breakpoint.
    callback:
        Callable invoked when the breakpoint is hit.  It receives a single
        argument – the raw ``DEBUG_EVENT`` ctypes structure passed to
        :meth:`hit`.

    Attributes
    ----------
    enabled : bool
        ``True`` when the INT3 byte is currently patched in.

    Examples
    --------
    >>> def on_hit(ctx):
    ...     print("Breakpoint hit!")
    >>> bp = Breakpoint(proc, 0x00401000, on_hit)
    >>> bp.enable()
    >>> # …wait for debug event…
    >>> bp.disable()
    """

    def __init__(
        self,
        process: "Process",
        address: int,
        callback: Callable,
    ) -> None:
        self.process = process
        self.address = address
        self.callback = callback
        self.enabled: bool = False
        self._original_byte: Optional[bytes] = None

    # ------------------------------------------------------------------
    # Enable / disable
    # ------------------------------------------------------------------

    def enable(self) -> None:
        """Write ``0xCC`` (INT3) at :attr:`address`, saving the original byte.

        Raises
        ------
        RuntimeError
            If the breakpoint is already enabled.
        OSError
            If reading or writing the target byte fails.
        """
        if self.enabled:
            raise RuntimeError(
                f"Breakpoint at 0x{self.address:X} is already enabled."
            )

        # Save original byte
        self._original_byte = self.process.read_bytes(self.address, 1)
        # Patch in INT3
        self.process.write_bytes_safe(self.address, _INT3)
        self.enabled = True
        logger.debug("Breakpoint enabled at 0x%X (original: %s).",
                     self.address, self._original_byte.hex())

    def disable(self) -> None:
        """Restore the original byte at :attr:`address`.

        Raises
        ------
        RuntimeError
            If the breakpoint is not currently enabled.
        OSError
            If writing the restored byte fails.
        """
        if not self.enabled:
            raise RuntimeError(
                f"Breakpoint at 0x{self.address:X} is not enabled."
            )
        if self._original_byte is None:
            raise RuntimeError("No original byte saved — was enable() called?")

        self.process.write_bytes_safe(self.address, self._original_byte)
        self.enabled = False
        logger.debug("Breakpoint disabled at 0x%X (restored: %s).",
                     self.address, self._original_byte.hex())

    # ------------------------------------------------------------------
    # Hit handling
    # ------------------------------------------------------------------

    def hit(self, context) -> None:
        """Handle a breakpoint exception for this address.

        This method:

        1. Calls the user-supplied :attr:`callback` with *context*.
        2. Temporarily restores the original byte.
        3. Calls :meth:`_single_step` (placeholder) to advance the IP.
        4. Re-enables the breakpoint so it fires on the next pass.

        Parameters
        ----------
        context:
            The raw debug-event context (e.g. a ``DEBUG_EVENT`` ctypes
            structure) as forwarded by the debug-event loop in
            :class:`~swedz_hooks.hooks.Hooks`.
        """
        logger.debug("Breakpoint hit at 0x%X.", self.address)

        try:
            self.callback(context)
        except Exception as exc:  # pragma: no cover
            logger.error("Breakpoint callback raised an exception: %s", exc)

        # Restore original instruction so the thread can execute it
        self.disable()
        self._single_step()
        # Re-arm for the next hit
        self.enable()

    def _single_step(self) -> None:
        """Placeholder: set the TRAP flag in the thread context for single-stepping.

        A full implementation would:

        1. Suspend the faulting thread.
        2. Call ``GetThreadContext`` to retrieve the ``CONTEXT`` structure.
        3. Set the ``TF`` (trap flag, bit 8) in ``CONTEXT.EFlags``.
        4. Call ``SetThreadContext`` to commit the change.
        5. Resume the thread.

        This placeholder logs the intent only; the actual Win32 calls require
        the faulting thread handle, which must be supplied by the debug-event
        loop.

        .. note::
            Integrate this with the ``EXCEPTION_SINGLE_STEP`` handler in
            :class:`~swedz_hooks.hooks.Hooks` to complete the flow.
        """
        logger.debug(
            "_single_step called for 0x%X — full CONTEXT manipulation "
            "must be wired up by the debug-event loop.",
            self.address,
        )

    # ------------------------------------------------------------------
    # Dunder
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        state = "enabled" if self.enabled else "disabled"
        return f"<Breakpoint address=0x{self.address:X} {state}>"
