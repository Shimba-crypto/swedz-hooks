from typing import List

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
