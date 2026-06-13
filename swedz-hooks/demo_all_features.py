"""
demo_all_features.py
--------------------
End-to-end demonstration of every public feature in **swedz-hooks**.

This script targets ``notepad.exe`` (or any process you choose to edit
``TARGET`` to).  It should be run **as Administrator** so that
:meth:`Process.debug_attach` and :meth:`MemoryProtection` succeed.

Usage
-----
::

    python demo_all_features.py

.. warning::
    *This is a demonstration script.*  Memory addresses used for pointer
    chains, patterns, and writes are **illustrative placeholders** and will
    not match the live process unless you replace them with values specific
    to your target binary and OS version.
"""

import logging
import sys
import time

# ---------------------------------------------------------------------------
# Configure logging so we can see what the library is doing
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("demo")

# ---------------------------------------------------------------------------
# Import the library
# ---------------------------------------------------------------------------
try:
    from swedz_hooks import (
        Process,
        Hooks,
        PatternScanner,
        PointerResolver,
        MemoryProtection,
        ProcessWatchdog,
        StructHelpers,
    )
except ImportError as exc:
    sys.exit(
        f"Could not import swedz_hooks: {exc}\n"
        "Run  pip install -e .  from the repository root first."
    )

# ---------------------------------------------------------------------------
# Configuration — change these to match your target
# ---------------------------------------------------------------------------
TARGET = "notepad.exe"

# Replace with a real static address / module offset for your binary
DEMO_ADDRESS = 0x00000000_DEADBEEF   # placeholder — will fail gracefully

# ---------------------------------------------------------------------------
# 1. Attach to the process
# ---------------------------------------------------------------------------
logger.info("=== 1. Attaching to %s ===", TARGET)
try:
    proc = Process(TARGET)
    logger.info("Attached: %r", proc)
except Exception as exc:
    logger.error("Could not attach: %s", exc)
    logger.info("Tip: Start Notepad and rerun this script.")
    sys.exit(1)

# ---------------------------------------------------------------------------
# 2. Process watchdog
# ---------------------------------------------------------------------------
logger.info("=== 2. ProcessWatchdog ===")

def _on_notepad_exit():
    logger.info(">>> Watchdog: notepad.exe has exited!")

watchdog = proc.watch(on_exit=_on_notepad_exit, interval=2.0)
logger.info("Watchdog started: %r", watchdog)

# ---------------------------------------------------------------------------
# 3. Pattern scanning
# ---------------------------------------------------------------------------
logger.info("=== 3. PatternScanner ===")
scanner = PatternScanner(proc)

# Scan ntdll.dll for a common prologue pattern (adjust to a real signature)
PATTERN = "48 89 5C 24 ?? 48 89 74 24 ??"
try:
    hits = scanner.scan_module("ntdll.dll", PATTERN)
    if hits:
        logger.info("Pattern found at: %s", [hex(h) for h in hits[:5]])
    else:
        logger.info("Pattern not found in ntdll.dll (expected for placeholder).")
except Exception as exc:
    logger.warning("scan_module error: %s", exc)

# scan_all demo (can be slow on large processes)
logger.info("Skipping scan_all in demo to avoid long runtime.")

# ---------------------------------------------------------------------------
# 4. PointerResolver
# ---------------------------------------------------------------------------
logger.info("=== 4. PointerResolver ===")
resolver = PointerResolver(proc)

# Resolve a fake pointer chain — will raise OSError because the address is
# a placeholder; we catch it gracefully.
FAKE_BASE = 0x10000000
OFFSETS   = [0x30, 0x08, 0x18]
try:
    final_addr = resolver.resolve(FAKE_BASE, OFFSETS)
    logger.info("Resolved address: 0x%X", final_addr)
    value = resolver.resolve_and_read(FAKE_BASE, OFFSETS, data_type="float")
    logger.info("Read float: %f", value)
except OSError as exc:
    logger.warning("Pointer resolution failed (expected for placeholder): %s", exc)

# ---------------------------------------------------------------------------
# 5. MemoryProtection — safe write
# ---------------------------------------------------------------------------
logger.info("=== 5. MemoryProtection / write_bytes_safe ===")

SAFE_ADDR  = 0x10000000   # placeholder
SAFE_BYTES = b"\x90\x90"  # NOP * 2

try:
    proc.write_bytes_safe(SAFE_ADDR, SAFE_BYTES)
    logger.info("Safe write succeeded at 0x%X.", SAFE_ADDR)
except Exception as exc:
    logger.warning("Safe write failed (expected for placeholder): %s", exc)

# Context-manager form:
try:
    with MemoryProtection(proc, SAFE_ADDR, len(SAFE_BYTES)) as mp:
        proc.write_bytes(SAFE_ADDR, SAFE_BYTES)
    logger.info("Context-manager write succeeded.")
except Exception as exc:
    logger.warning("Context-manager write failed (expected): %s", exc)

# ---------------------------------------------------------------------------
# 6. StructHelpers via proc.structs
# ---------------------------------------------------------------------------
logger.info("=== 6. StructHelpers ===")
sh = proc.structs   # same as StructHelpers(proc)

# read_string
try:
    s = sh.read_string(DEMO_ADDRESS, max_len=64)
    logger.info("read_string: %r", s)
except OSError as exc:
    logger.warning("read_string failed (expected): %s", exc)

# read_array
try:
    arr = sh.read_array(DEMO_ADDRESS, element_type="float", count=4)
    logger.info("read_array (float×4): %s", arr)
except OSError as exc:
    logger.warning("read_array failed (expected): %s", exc)

# read_vector_3d
try:
    vec = sh.read_vector_3d(DEMO_ADDRESS)
    logger.info("read_vector_3d: x=%f, y=%f, z=%f", *vec)
except OSError as exc:
    logger.warning("read_vector_3d failed (expected): %s", exc)

# write_vector_3d
try:
    sh.write_vector_3d(DEMO_ADDRESS, 1.0, 2.0, 3.0)
    logger.info("write_vector_3d succeeded.")
except OSError as exc:
    logger.warning("write_vector_3d failed (expected): %s", exc)

# ---------------------------------------------------------------------------
# 7. Hooks / Breakpoints (debug attach + event loop)
# ---------------------------------------------------------------------------
logger.info("=== 7. Hooks (breakpoint demo — 3 second timeout) ===")

# Attaching as a debugger prevents other debuggers from attaching.
# In this demo we show the API but skip the blocking event loop.
try:
    proc.debug_attach()
    logger.info("debug_attach() succeeded.")
    hooks = Hooks(proc)

    # Add a breakpoint at a placeholder address
    def _bp_callback(ctx):
        logger.info("Breakpoint hit! Context: %s", ctx)

    # NB: adding a breakpoint requires the address to be writable code.
    # We skip the actual add here to avoid crashing notepad.
    logger.info(
        "Hooks instance ready: %r  (skipping add_breakpoint on live process).",
        hooks,
    )

    # Normally you would call hooks.wait_for_events() here (blocks).
    # Instead we just demonstrate the API is reachable:
    logger.info("hooks.wait_for_events() would block here — skipping in demo.")

except Exception as exc:
    logger.warning("debug_attach / Hooks error: %s", exc)

# ---------------------------------------------------------------------------
# 8. Cleanup
# ---------------------------------------------------------------------------
logger.info("=== 8. Cleanup ===")
watchdog.stop()
logger.info("Watchdog stopped.")
logger.info("Demo complete.")
