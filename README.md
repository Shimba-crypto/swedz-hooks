# swedz-hooks

A Windows process memory manipulation and hooking library built on top of
[pymem](https://github.com/srounet/Pymem), [psutil](https://github.com/giampaolo/psutil),
and the Windows API (`ctypes`).

---

## Features

| Module | What it does |
|---|---|
| `Process` | Attach to any running process by name or PID; read/write memory with typed helpers |
| `Hooks` | Plant INT3 breakpoints and run the Win32 debug-event loop |
| `PatternScanner` | AOB pattern scanning with `?` / `??` wildcard support |
| `PointerResolver` | Follow multi-level pointer chains and read/write the final value |
| `MemoryProtection` | Context-manager that temporarily unlocks page protection via `VirtualProtectEx` |
| `ProcessWatchdog` | Background thread that fires a callback when a watched process exits |
| `StructHelpers` | Read/write strings, typed arrays, and 2-D / 3-D vectors |

---

## Requirements

- **Windows** (Win32 API is used throughout)
- Python 3.7+
- Run as **Administrator** for `DebugActiveProcess` and `VirtualProtectEx`

---

## Installation

```bash
# From PyPI (once published)
pip install swedz-hooks

# From source
git clone https://github.com/example/swedz-hooks.git
cd swedz-hooks
pip install -e .
```

---

## Quick Example

```python
from swedz_hooks import Process, PatternScanner, PointerResolver

# 1. Attach to a running process
proc = Process("notepad.exe")

# 2. Scan a module for a byte pattern
scanner = PatternScanner(proc)
hits = scanner.scan_module("ntdll.dll", "48 8B C4 ?? ?? 41 56")
print("Pattern found at:", [hex(h) for h in hits])

# 3. Follow a pointer chain and read a float
resolver = PointerResolver(proc)
hp = resolver.resolve_and_read(
    base_address=0x10A3C500,
    offsets=[0x30, 0x08, 0x18],
    data_type="float",
)
print("Player HP:", hp)

# 4. Safe write (unlocks page, writes, restores protection)
proc.write_bytes_safe(0x10A3C518, b"\x90\x90\x90")

# 5. Read a 3-D vector
vec = proc.structs.read_vector_3d(0x10A3C520)
print("Position:", vec)

# 6. Watch for process exit
def bye():
    print("Process exited!")

watchdog = proc.watch(on_exit=bye, interval=1.0)
# … do work …
watchdog.stop()
```

### Breakpoints

```python
from swedz_hooks import Process, Hooks

proc = Process("target.exe")
proc.debug_attach()           # must be called before Hooks

hooks = Hooks(proc)

def on_hit(debug_event):
    print(f"Breakpoint fired! Event code: {debug_event.dwDebugEventCode}")

hooks.add_breakpoint(0x00401000, on_hit)
hooks.wait_for_events()       # blocks; run in a thread for async use
```

---

## Project Layout

```
swedz-hooks/
├── swedz_hooks/
│   ├── __init__.py       # Public exports
│   ├── process.py        # Process attachment & I/O
│   ├── breakpoint.py     # INT3 breakpoint
│   ├── hooks.py          # Debug-event loop
│   ├── pattern.py        # AOB pattern scanner
│   ├── pointer.py        # Pointer-chain resolver
│   ├── memory.py         # VirtualProtectEx context manager
│   ├── watchdog.py       # Process-exit monitor
│   └── structs.py        # String / array / vector helpers
├── examples/
│   └── demo_all_features.py
├── setup.py
└── README.md
```

---

## License

MIT — see `LICENSE` for details.
