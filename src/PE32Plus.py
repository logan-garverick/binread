"""
Description: This file defines the PE32+ class inheriting from the BinaryFile class.
"""

from BinaryFile import BinaryFile


class PE32Plus(BinaryFile):
    """Windows Portable Executable Plus (64-bit addressable)"""

    def __init__(self, path):
        super().__init__()
        self.path = path
