"""
Description: This file defines the ELF32 class inheriting from the BinaryFile class.
"""

from BinaryFile import BinaryFile


class ELF32(BinaryFile):
    """Executable and Linkable Format (32-bit addressable)"""

    def __init__(self, path):
        super().__init__()
        self.path = path
