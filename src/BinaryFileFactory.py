"""
Description: This file defines the BinaryFileFactory class and its associated methods.  This class 
             is used to create an instance of a BinaryFile subclass based on a file's format.
"""

from abc import ABC
import struct
from typing import Optional
from BinaryFile import BinaryFile
from ELF32 import ELF32
from ELF64 import ELF64
from PE32 import PE32
from PE32Plus import PE32Plus

FILE_FORMAT_INFO = [
    {
        "ABBR": "ELF",
        "MAGIC": bytes([0x7F, 0x45, 0x4C, 0x46]),
        "e_type": 0x4,
    },
    {
        "ABBR": "PE",
        "MAGIC": bytes([0x4D, 0x5A]),
        "e_lfanew": 0x3C,
        "Magic": 0x18,
        "BitnessFlags": {
            32: 0x010B,
            64: 0x020B,
        },
    },
]


class BinaryFileFactory(ABC):
    """Factory class that generates a BinaryFile object based on the file format signature and bit addressing discovered"""

    def get_BinaryFile_instance(self, path) -> BinaryFile:
        """Determine a file format of a provided binary based on magic numbers and bit addressing scheme

        Args:
            path (str): file path of the provided binary

        Returns:
            BinaryFile: a BinaryFile instance corresponding to the determined file format
        """

        # Determine file format details
        fileFormatDict = self._read_magic(path)
        if fileFormatDict == None:
            return None

        fileFormat = fileFormatDict["ABBR"]
        bitAddressingScheme = self._read_bitness(path, fileFormatDict)
        if fileFormatDict == None:
            return None

        # Generate the appropriate BinaryFile instance based on determined file format details
        if (fileFormat == "ELF") and (bitAddressingScheme == 32):
            return ELF32(path)
        elif (fileFormat == "ELF") and (bitAddressingScheme == 64):
            return ELF64(path)
        elif (fileFormat == "PE") and (bitAddressingScheme == 32):
            return PE32(path)
        elif (fileFormat == "PE") and (bitAddressingScheme == 64):
            return PE32Plus(path)
        else:
            return None

    def _read_magic(self, path) -> dict:
        """Read the file header and parse the magic numbers

        Args:
            path (str): file path of the provided binary

        Returns:
            dict: dictionary containing information based on determined file format
        """

        with open(path, "rb") as binary:
            fileHeader = binary.read(32)
            for format in FILE_FORMAT_INFO:
                if fileHeader.startswith(format.get("MAGIC")):
                    return format
            return None
        return None

    def _read_bitness(self, path, fileFormatDict) -> Optional[int]:
        """Read the bit addressing scheme from the provided binary

        Args:
            path (str): file path of the provided binary
            fileFormatDict (dict): dictionary containing necessary file format information

        Returns:
            int: bit addressing scheme of the provided binary
        """

        with open(path, "rb") as bin:
            # Read bit addressing from ELF header
            if fileFormatDict["ABBR"] == "ELF":
                bin.seek(fileFormatDict["e_type"], 1)
                (bitAddressingFlag,) = struct.unpack("<b", bin.read(1))
                if bitAddressingFlag == 1:
                    return 32
                else:
                    return 64

            # Read bit addressing from PE
            if fileFormatDict["ABBR"] == "PE":
                # Find e_lfanew pointer to _IMAGE_NT_HEADERS
                bin.seek(fileFormatDict["e_lfanew"], 1)
                (e_lfanew_ptr,) = struct.unpack("<L", bin.read(4))

                # Get format magic numbers (PE32/PE32+) in _IMAGE_OPTIONAL_HEADER
                bin.seek(e_lfanew_ptr + fileFormatDict["Magic"], 0)
                (machine_flag,) = struct.unpack("<H", bin.read(2))

                # Determine bit addressing of the PE file
                for bitAddressing in fileFormatDict["BitnessFlags"]:
                    if machine_flag == fileFormatDict["BitnessFlags"].get(
                        bitAddressing
                    ):
                        return bitAddressing
        return None