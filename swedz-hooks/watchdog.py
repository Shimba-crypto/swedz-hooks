"""
watchdog.py
-----------
Provides :class:`ProcessWatchdog`, a lightweight background-thread monitor
that calls a user-supplied callback when a watched process disappears.
"""

import threading
import time
import logging
from typing import Callable, Optional, TYPE_CHECKING

import psutil

if TYPE_CHECKING:
    from .process import Process

logger = logging.getLogger(__name__)


class ProcessWatchdog:
    """Monitor a process on a background thread and fire a callback on exit.

    Parameters
    ----------
    process:
        An attached :class:`~swedz_hooks.process.Process` instance.
        The watchdog uses ``process.pid`` to poll ``psutil.pid_exists``.
    check_interval:
        How often (in seconds) to check whether the process is still alive.
        Defaults to ``1.0``.
    on_exit:
        Optional callable invoked (with no arguments) when the process is no
        longer found.  It is called from the background thread, so ensure it
        is thread-safe.

    Examples
    --------
    >>> def bye():
    ...     print("Process exited!")
    >>> wd = ProcessWatchdog(proc, check_interval=0.5, on_exit=bye)
    >>> wd.start()
    >>> # … do work …
    >>> wd.stop()
    """

    def __init__(
        self,
        process: "Process",
        check_interval: float = 1.0,
        on_exit: Optional[Callable[[], None]] = None,
    ) -> None:
        self.process = process
        self.check_interval = check_interval
        self.on_exit = on_exit

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the background monitoring thread.

        Raises
        ------
        RuntimeError
            If the watchdog is already running.
        """
        if self._thread is not None and self._thread.is_alive():
            raise RuntimeError("ProcessWatchdog is already running.")

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._monitor,
            name=f"swedz-watchdog-{self.process.pid}",
            daemon=True,
        )
        self._thread.start()
        logger.debug("ProcessWatchdog started for PID %d.", self.process.pid)

    def stop(self) -> None:
        """Signal the monitoring thread to stop and wait for it to finish.

        Safe to call even if the watchdog was never started.
        """
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=self.check_interval * 2 + 1)
            self._thread = None
        logger.debug("ProcessWatchdog stopped.")

    @property
    def is_running(self) -> bool:
        """``True`` while the background thread is alive."""
        return self._thread is not None and self._thread.is_alive()

    # ------------------------------------------------------------------
    # Internal monitor loop
    # ------------------------------------------------------------------

    def _monitor(self) -> None:
        """Poll ``psutil.pid_exists`` until the process disappears or stop() is called."""
        pid = self.process.pid
        while not self._stop_event.is_set():
            try:
                alive = psutil.pid_exists(pid)
            except Exception as exc:  # pragma: no cover
                logger.warning("ProcessWatchdog poll error: %s", exc)
                alive = True  # assume alive on error to avoid false positives

            if not alive:
                logger.info("PID %d no longer exists — firing on_exit callback.", pid)
                if callable(self.on_exit):
                    try:
                        self.on_exit()
                    except Exception as exc:  # pragma: no cover
                        logger.error("on_exit callback raised: %s", exc)
                break

            self._stop_event.wait(self.check_interval)
