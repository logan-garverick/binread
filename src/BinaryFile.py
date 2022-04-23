"""
Description: This file defines the BinaryFile class and its abstract methods
"""


from abc import abstractmethod


class BinaryFile:
    """This is the class pattern for format specific BinaryFile instances"""

    @abstractmethod
    def _find_endianess(self) -> None:
        """Determines the endianness of the provided binary file and allocated the proper unpacking formatters"""

    @abstractmethod
    def print_file_type(self) -> None:
        """Display the file type of the provided binary file"""

    @abstractmethod
    def print_header_info(self) -> None:
        """Displays the information parsed from the provided binary file's headers"""

    @abstractmethod
    def print_compressed_header_info(self) -> None:
        """Displays a compressed version of the information parsed from the provided binary file's headers"""

    @abstractmethod
    def print_section_info(self) -> None:
        """Displays the information parsed from the provided binary file's section headers"""

    @abstractmethod
    def print_compressed_section_info(self) -> None:
        """Displays a compressed version of the information parsed from the provided binary file's section headers"""
