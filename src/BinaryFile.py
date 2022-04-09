"""
Description: This file defines the BinaryFile class and its abstract methods
"""


from abc import abstractmethod


class BinaryFile:
    """This is the class pattern for format specific BinaryFile instances"""

    @abstractmethod
    def _find_endianess(self) -> None:
        """Determines the endianness of the provided binary file and allocated the proper unpacking formatters"""
