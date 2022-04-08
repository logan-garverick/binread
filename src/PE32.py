"""
Description: This file defines the PE32 class inheriting from the BinaryFile class.
"""

from BinaryFile import BinaryFile


class PE32(BinaryFile):
    """Windows Portable Executable (32-bit addressable)"""

    def __init__(self, path):
        super().__init__()
        self.path = path
