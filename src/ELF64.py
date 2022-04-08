"""
Description: This file defines the ELF64 class inheriting from the BinaryFile class.
"""

from BinaryFile import BinaryFile


class ELF64(BinaryFile):
    """Executable and Linkable Format (64-bit addressable)"""

    def __init__(self, path):
        super().__init__()
        self.path = path
