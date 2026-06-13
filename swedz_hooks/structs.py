from typing import List, Tuple
from .memory import MemoryProtection

class StructHelpers:
    def __init__(self, process):
        self.process = process

    def read_string(self, address: int, max_len=256, encoding='utf-8') -> str:
        data = self.process.read_bytes(address, max_len)
        null = data.find(b'\x00')
        if null != -1:
            data = data[:null]
        return data.decode(encoding, errors='replace')

    def write_string(self, address: int, text: str, encoding='utf-8'):
        data = text.encode(encoding) + b'\x00'
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
