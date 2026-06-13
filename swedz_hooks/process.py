import pymem
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
