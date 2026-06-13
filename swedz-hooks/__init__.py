"""
swedz-hooks
===========
A Windows process memory manipulation and hooking library built on top of
pymem, psutil, and the Windows API (ctypes).

Exports
-------
Process           – Attach to a running process and read/write memory.
Hooks             – Manage INT3 breakpoints and the debug event loop.
PatternScanner    – AOB / byte-pattern scanning with wildcard support.
PointerResolver   – Resolve multi-level pointer chains.
MemoryProtection  – Context-manager for VirtualProtectEx page permissions.
ProcessWatchdog   – Background thread that fires a callback when a process exits.
StructHelpers     – High-level helpers for strings, arrays, and vectors.
"""

from .process import Process
from .hooks import Hooks
from .pattern import PatternScanner
from .pointer import PointerResolver
from .memory import MemoryProtection
from .watchdog import ProcessWatchdog
from .structs import StructHelpers

__all__ = [
    "Process",
    "Hooks",
    "PatternScanner",
    "PointerResolver",
    "MemoryProtection",
    "ProcessWatchdog",
    "StructHelpers",
]

__version__ = "1.0.0"
__author__ = "swedz-hooks contributors"
