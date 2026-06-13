import ctypes
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
