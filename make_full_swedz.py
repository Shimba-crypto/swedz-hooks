# save as make_full_swedz.py
import os

modules = {
    "process.py": '''import pymem
import pymem.process
import ctypes

class Process:
    def __init__(self, name_or_pid):
        if isinstance(name_or_pid, int):
            self.pid = name_or_pid
            self.pm = pymem.Pymem(self.pid)
        else:
            self.pm = pymem.Pymem(name_or_pid)
            self.pid = self.pm.process_id
        self.handle = self.pm.process_handle
        self.is_debugged = False

    def debug_attach(self):
        kernel32 = ctypes.windll.kernel32
        if not kernel32.DebugActiveProcess(self.pid):
            raise ctypes.WinError()
        self.is_debugged = True

    def read_bytes(self, address, size):
        return self.pm.read_bytes(address, size)

    def write_bytes(self, address, data):
        self.pm.write_bytes(address, data)

    def read_int(self, address):
        return self.pm.read_int(address)

    def write_int(self, address, value):
        self.pm.write_int(address, value)

    def read_float(self, address):
        return self.pm.read_float(address)

    def write_float(self, address, value):
        self.pm.write_float(address, value)

    def write_bytes_safe(self, address, data):
        from .memory import MemoryProtection
        MemoryProtection.write_bytes_safe(self, address, data)

    def watch(self, on_exit=None, interval=1.0):
        from .watchdog import ProcessWatchdog
        wd = ProcessWatchdog(self, interval, on_exit)
        wd.start()
        return wd

    @property
    def structs(self):
        from .structs import StructHelpers
        return StructHelpers(self)
''',
    "pattern.py": '''import re
import pymem
from typing import List

class PatternScanner:
    def __init__(self, process):
        self.process = process
        self.pm = process.pm

    def scan_module(self, module_name: str, pattern: str) -> List[int]:
        module = pymem.process.module_from_name(self.pm.process_handle, module_name)
        start = module.lpBaseOfDll
        end = start + module.SizeOfImage
        pattern = pattern.replace(' ', '')
        parts = []
        for hex_pair in re.findall(r'..', pattern):
            if hex_pair == '??' or hex_pair == '?':
                parts.append(None)
            else:
                parts.append(bytes([int(hex_pair, 16)]))
        results = []
        chunk = 0x10000
        for offset in range(0, end - start, chunk):
            chunk_start = start + offset
            chunk_end = min(chunk_start + chunk + len(parts), end)
            data = self.pm.read_bytes(chunk_start, chunk_end - chunk_start)
            for i in range(len(data) - len(parts) + 1):
                match = True
                for j, p in enumerate(parts):
                    if p is not None and data[i + j] != p[0]:
                        match = False
                        break
                if match:
                    results.append(chunk_start + i)
        return results

    def scan_all(self, pattern: str) -> List[int]:
        return self.pm.pattern_scan_all(pattern)
''',
    "pointer.py": '''from typing import List

class PointerResolver:
    def __init__(self, process):
        self.process = process
        self.pm = process.pm

    def resolve(self, base_address: int, offsets: List[int]) -> int:
        addr = base_address
        for i, off in enumerate(offsets):
            if i == 0:
                ptr = self.pm.read_int(addr + off)
            else:
                ptr = self.pm.read_int(ptr + off)
            if ptr == 0:
                raise ValueError(f"Null pointer at offset {off}")
        return ptr

    def resolve_and_read(self, base_address: int, offsets: List[int], data_type='int'):
        final = self.resolve(base_address, offsets)
        if data_type == 'int':
            return self.pm.read_int(final)
        elif data_type == 'float':
            return self.pm.read_float(final)
        else:
            raise ValueError("Unsupported type")

    def resolve_and_write(self, base_address: int, offsets: List[int], value, data_type='int'):
        final = self.resolve(base_address, offsets)
        if data_type == 'int':
            self.pm.write_int(final, value)
        elif data_type == 'float':
            self.pm.write_float(final, value)
        else:
            raise ValueError("Unsupported type")
''',
    "memory.py": '''import ctypes
from ctypes import wintypes

PAGE_EXECUTE_READWRITE = 0x40
kernel32 = ctypes.windll.kernel32

class MemoryProtection:
    def __init__(self, process, address: int, size: int, new_protect=PAGE_EXECUTE_READWRITE):
        self.process = process
        self.address = address
        self.size = size
        self.new_protect = new_protect
        self.old_protect = wintypes.DWORD()

    def __enter__(self):
        if not kernel32.VirtualProtectEx(
            self.process.handle,
            ctypes.c_void_p(self.address),
            self.size,
            self.new_protect,
            ctypes.byref(self.old_protect)
        ):
            raise ctypes.WinError()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        kernel32.VirtualProtectEx(
            self.process.handle,
            ctypes.c_void_p(self.address),
            self.size,
            self.old_protect,
            ctypes.byref(wintypes.DWORD())
        )

    @staticmethod
    def write_bytes_safe(process, address: int, data: bytes):
        with MemoryProtection(process, address, len(data)):
            process.write_bytes(address, data)
''',
    "watchdog.py": '''import threading
import time
import psutil
from typing import Callable, Optional

class ProcessWatchdog:
    def __init__(self, process, check_interval=1.0, on_exit: Optional[Callable] = None):
        self.process = process
        self.pid = process.pid
        self.interval = check_interval
        self.on_exit = on_exit
        self._stop_event = threading.Event()
        self._thread = None

    def _monitor(self):
        while not self._stop_event.is_set():
            if not psutil.pid_exists(self.pid):
                if self.on_exit:
                    self.on_exit(self.pid)
                break
            time.sleep(self.interval)

    def start(self):
        self._thread = threading.Thread(target=self._monitor, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=1)
''',
    "structs.py": '''from typing import List, Tuple
from .memory import MemoryProtection

class StructHelpers:
    def __init__(self, process):
        self.process = process

    def read_string(self, address: int, max_len=256, encoding='utf-8') -> str:
        data = self.process.read_bytes(address, max_len)
        null = data.find(b'\\x00')
        if null != -1:
            data = data[:null]
        return data.decode(encoding, errors='replace')

    def write_string(self, address: int, text: str, encoding='utf-8'):
        data = text.encode(encoding) + b'\\x00'
        MemoryProtection.write_bytes_safe(self.process, address, data)

    def read_array(self, address: int, element_type='int', count=10) -> List:
        if element_type == 'int':
            size, func = 4, self.process.read_int
        elif element_type == 'float':
            size, func = 4, self.process.read_float
        else:
            raise ValueError("Unsupported type")
        return [func(address + i * size) for i in range(count)]

    def read_vector_2d(self, address: int, coord_type='float') -> Tuple:
        if coord_type == 'float':
            return (self.process.read_float(address), self.process.read_float(address + 4))
        else:
            return (self.process.read_int(address), self.process.read_int(address + 4))

    def read_vector_3d(self, address: int, coord_type='float') -> Tuple:
        if coord_type == 'float':
            return (self.process.read_float(address), self.process.read_float(address + 4), self.process.read_float(address + 8))
        else:
            return (self.process.read_int(address), self.process.read_int(address + 4), self.process.read_int(address + 8))

    def write_vector_3d(self, address: int, x, y, z, coord_type='float'):
        with MemoryProtection(self.process, address, 12):
            if coord_type == 'float':
                self.process.write_float(address, x)
                self.process.write_float(address + 4, y)
                self.process.write_float(address + 8, z)
            else:
                self.process.write_int(address, x)
                self.process.write_int(address + 4, y)
                self.process.write_int(address + 8, z)
''',
}

os.makedirs("swedz_hooks", exist_ok=True)
for filename, content in modules.items():
    with open(f"swedz_hooks/{filename}", "w", encoding="utf-8") as f:
        f.write(content)
    print(f"Created swedz_hooks/{filename}")

# Update __init__.py to export everything
init_content = '''from .process import Process
from .pattern import PatternScanner
from .pointer import PointerResolver
from .memory import MemoryProtection
from .watchdog import ProcessWatchdog
from .structs import StructHelpers

__all__ = [
    "Process",
    "PatternScanner",
    "PointerResolver",
    "MemoryProtection",
    "ProcessWatchdog",
    "StructHelpers",
]
'''
with open("swedz_hooks/__init__.py", "w", encoding="utf-8") as f:
    f.write(init_content)
print("Updated __init__.py")

# Update setup.py version to 0.2.0
setup_content = '''from setuptools import setup, find_packages

setup(
    name="swedz-hooks",
    version="0.2.0",
    packages=find_packages(),
    install_requires=["pymem", "psutil"],
    author="Shimba-crypto",
    description="Process hooking and memory tools (full version)",
)
'''
with open("setup.py", "w", encoding="utf-8") as f:
    f.write(setup_content)
print("Updated setup.py to version 0.2.0")