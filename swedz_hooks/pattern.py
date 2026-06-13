import re
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
