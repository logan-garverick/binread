"""
Description: This file defines the PE32 class inheriting from the BinaryFile class.
"""

from BinaryFile import BinaryFile
import struct


E_RES1_SIZE = 0x8
E_RES2_SIZE = 0x14
IMAGE_FILE_HEADER_OFFSET = 0x4
IMAGE_OPTIONAL_HEADER_OFFSET = 0x18
IMAGE_DIRECTORY_ENTRY_IMPORT_OFFSET = 0x80
IMAGE_IMPORT_DESCRIPTOR_SIZE = 0x14


class PE32(BinaryFile):
    """Windows Portable Executable (32-bit addressable)"""

    def __init__(self, path):
        self.path = path
        self.formatDict = None
        self._find_endianess()
        self._IMAGE_DOS_HEADER = self._read_IMAGE_DOS_HEADER()
        self._IMAGE_FILE_HEADER = self._read_IMAGE_FILE_HEADER()
        self._IMAGE_OPTIONAL_HEADER = self._read_IMAGE_OPTIONAL_HEADER()
        self._IMAGE_DIRECTORY_ENTRY_IMPORT = self._read_IMAGE_DIRECTORY_ENTRY_IMPORT()

    def _find_endianess(self) -> None:
        """All windows PE formats are assumed to be compiled in Little Endian format"""
        self.formatDict = {
            "BYTE_F": "<B",
            "BYTE_S": 1,
            "WORD_F": "<H",
            "WORD_S": 2,
            "DWORD_F": "<L",
            "DWORD_S": 4,
            "QWORD_F": "<Q",
            "QWORD_S": 8,
        }

    def _read_IMAGE_DOS_HEADER(self) -> dict:

        _IMAGE_DOS_HEADER = {}
        with open(self.path, "rb") as file:
            (_IMAGE_DOS_HEADER["e_magic"],) = struct.unpack(
                self.formatDict["WORD_F"], file.read(self.formatDict["WORD_S"])
            )
            (_IMAGE_DOS_HEADER["e_cblp"],) = struct.unpack(
                self.formatDict["WORD_F"], file.read(self.formatDict["WORD_S"])
            )
            (_IMAGE_DOS_HEADER["e_cp"],) = struct.unpack(
                self.formatDict["WORD_F"], file.read(self.formatDict["WORD_S"])
            )
            (_IMAGE_DOS_HEADER["e_crlc"],) = struct.unpack(
                self.formatDict["WORD_F"], file.read(self.formatDict["WORD_S"])
            )
            (_IMAGE_DOS_HEADER["e_cparhdr"],) = struct.unpack(
                self.formatDict["WORD_F"], file.read(self.formatDict["WORD_S"])
            )
            (_IMAGE_DOS_HEADER["e_minalloc"],) = struct.unpack(
                self.formatDict["WORD_F"], file.read(self.formatDict["WORD_S"])
            )
            (_IMAGE_DOS_HEADER["e_maxalloc"],) = struct.unpack(
                self.formatDict["WORD_F"], file.read(self.formatDict["WORD_S"])
            )
            (_IMAGE_DOS_HEADER["e_ss"],) = struct.unpack(
                self.formatDict["WORD_F"], file.read(self.formatDict["WORD_S"])
            )
            (_IMAGE_DOS_HEADER["e_sp"],) = struct.unpack(
                self.formatDict["WORD_F"], file.read(self.formatDict["WORD_S"])
            )
            (_IMAGE_DOS_HEADER["e_csum"],) = struct.unpack(
                self.formatDict["WORD_F"], file.read(self.formatDict["WORD_S"])
            )
            (_IMAGE_DOS_HEADER["e_ip"],) = struct.unpack(
                self.formatDict["WORD_F"], file.read(self.formatDict["WORD_S"])
            )
            (_IMAGE_DOS_HEADER["e_cs"],) = struct.unpack(
                self.formatDict["WORD_F"], file.read(self.formatDict["WORD_S"])
            )
            (_IMAGE_DOS_HEADER["e_lfarlc"],) = struct.unpack(
                self.formatDict["WORD_F"], file.read(self.formatDict["WORD_S"])
            )
            (_IMAGE_DOS_HEADER["e_ovno"],) = struct.unpack(
                self.formatDict["WORD_F"], file.read(self.formatDict["WORD_S"])
            )
            # Skip reserved word section 1
            file.seek(E_RES1_SIZE, 1)
            (_IMAGE_DOS_HEADER["e_oemid"],) = struct.unpack(
                self.formatDict["WORD_F"], file.read(self.formatDict["WORD_S"])
            )
            (_IMAGE_DOS_HEADER["e_oeminfo"],) = struct.unpack(
                self.formatDict["WORD_F"], file.read(self.formatDict["WORD_S"])
            )
            # Skip reserved word section 2
            file.seek(E_RES2_SIZE, 1)
            (_IMAGE_DOS_HEADER["e_lfanew"],) = struct.unpack(
                self.formatDict["DWORD_F"], file.read(self.formatDict["DWORD_S"])
            )

            return _IMAGE_DOS_HEADER

    def _read_IMAGE_FILE_HEADER(self) -> dict:
        _IMAGE_FILE_HEADER = {}
        with open(self.path, "rb") as file:
            # Jump to the _IMAGE_FILE_HEADER struct
            file.seek(self._IMAGE_DOS_HEADER["e_lfanew"], 0)
            file.seek(IMAGE_FILE_HEADER_OFFSET, 1)

            # Parse _IMAGE_FILE_HEADER struct
            (_IMAGE_FILE_HEADER["Machine"],) = struct.unpack(
                self.formatDict["WORD_F"], file.read(self.formatDict["WORD_S"])
            )
            (_IMAGE_FILE_HEADER["NumberOfSections"],) = struct.unpack(
                self.formatDict["WORD_F"], file.read(self.formatDict["WORD_S"])
            )
            (_IMAGE_FILE_HEADER["TimeDateStamp"],) = struct.unpack(
                self.formatDict["DWORD_F"], file.read(self.formatDict["DWORD_S"])
            )
            (_IMAGE_FILE_HEADER["PointerToSymbolTable"],) = struct.unpack(
                self.formatDict["DWORD_F"], file.read(self.formatDict["DWORD_S"])
            )
            (_IMAGE_FILE_HEADER["NumberOfSymbols"],) = struct.unpack(
                self.formatDict["DWORD_F"], file.read(self.formatDict["DWORD_S"])
            )
            (_IMAGE_FILE_HEADER["SizeOfOptionalHeader"],) = struct.unpack(
                self.formatDict["WORD_F"], file.read(self.formatDict["WORD_S"])
            )
            (_IMAGE_FILE_HEADER["Characteristics"],) = struct.unpack(
                self.formatDict["WORD_F"], file.read(self.formatDict["WORD_S"])
            )

            return _IMAGE_FILE_HEADER

    def _read_IMAGE_OPTIONAL_HEADER(self) -> dict:
        _IMAGE_OPTIONAL_HEADER = {}
        with open(self.path, "rb") as file:
            # Jump to the _IMAGE_OPTIONAL_HEADER struct
            file.seek(self._IMAGE_DOS_HEADER["e_lfanew"], 0)
            file.seek(IMAGE_OPTIONAL_HEADER_OFFSET, 1)

            # Parse _IMAGE_OPTIONAL_HEADER struct
            (_IMAGE_OPTIONAL_HEADER["Magic"],) = struct.unpack(
                self.formatDict["WORD_F"], file.read(self.formatDict["WORD_S"])
            )
            (_IMAGE_OPTIONAL_HEADER["MajorLinkerVersion"],) = struct.unpack(
                self.formatDict["BYTE_F"], file.read(self.formatDict["BYTE_S"])
            )
            (_IMAGE_OPTIONAL_HEADER["MinorLinkerVersion"],) = struct.unpack(
                self.formatDict["BYTE_F"], file.read(self.formatDict["BYTE_S"])
            )
            (_IMAGE_OPTIONAL_HEADER["SizeOfCode"],) = struct.unpack(
                self.formatDict["DWORD_F"], file.read(self.formatDict["DWORD_S"])
            )
            (_IMAGE_OPTIONAL_HEADER["SizeOfInitializedData"],) = struct.unpack(
                self.formatDict["DWORD_F"], file.read(self.formatDict["DWORD_S"])
            )
            (_IMAGE_OPTIONAL_HEADER["SizeOfUninitializedData"],) = struct.unpack(
                self.formatDict["DWORD_F"], file.read(self.formatDict["DWORD_S"])
            )
            (_IMAGE_OPTIONAL_HEADER["AddressOfEntryPoint"],) = struct.unpack(
                self.formatDict["DWORD_F"], file.read(self.formatDict["DWORD_S"])
            )
            (_IMAGE_OPTIONAL_HEADER["BaseOfCode"],) = struct.unpack(
                self.formatDict["DWORD_F"], file.read(self.formatDict["DWORD_S"])
            )
            (_IMAGE_OPTIONAL_HEADER["BaseOfData"],) = struct.unpack(
                self.formatDict["DWORD_F"], file.read(self.formatDict["DWORD_S"])
            )
            (_IMAGE_OPTIONAL_HEADER["ImageBase"],) = struct.unpack(
                self.formatDict["DWORD_F"], file.read(self.formatDict["DWORD_S"])
            )
            (_IMAGE_OPTIONAL_HEADER["SectionAlignment"],) = struct.unpack(
                self.formatDict["DWORD_F"], file.read(self.formatDict["DWORD_S"])
            )
            (_IMAGE_OPTIONAL_HEADER["FileAlignment"],) = struct.unpack(
                self.formatDict["DWORD_F"], file.read(self.formatDict["DWORD_S"])
            )
            (_IMAGE_OPTIONAL_HEADER["MajorOperatingSystemVersion"],) = struct.unpack(
                self.formatDict["WORD_F"], file.read(self.formatDict["WORD_S"])
            )
            (_IMAGE_OPTIONAL_HEADER["MinorOperatingSystemVersion"],) = struct.unpack(
                self.formatDict["WORD_F"], file.read(self.formatDict["WORD_S"])
            )
            (_IMAGE_OPTIONAL_HEADER["MajorImageVersion"],) = struct.unpack(
                self.formatDict["WORD_F"], file.read(self.formatDict["WORD_S"])
            )
            (_IMAGE_OPTIONAL_HEADER["MinorImageVersion"],) = struct.unpack(
                self.formatDict["WORD_F"], file.read(self.formatDict["WORD_S"])
            )
            (_IMAGE_OPTIONAL_HEADER["MajorSubsystemVersion"],) = struct.unpack(
                self.formatDict["WORD_F"], file.read(self.formatDict["WORD_S"])
            )
            (_IMAGE_OPTIONAL_HEADER["MinorSubsystemVersion"],) = struct.unpack(
                self.formatDict["WORD_F"], file.read(self.formatDict["WORD_S"])
            )
            (_IMAGE_OPTIONAL_HEADER["Win32VersionValue"],) = struct.unpack(
                self.formatDict["DWORD_F"], file.read(self.formatDict["DWORD_S"])
            )
            (_IMAGE_OPTIONAL_HEADER["SizeOfImage"],) = struct.unpack(
                self.formatDict["DWORD_F"], file.read(self.formatDict["DWORD_S"])
            )
            (_IMAGE_OPTIONAL_HEADER["SizeOfHeaders"],) = struct.unpack(
                self.formatDict["DWORD_F"], file.read(self.formatDict["DWORD_S"])
            )
            (_IMAGE_OPTIONAL_HEADER["Checksum"],) = struct.unpack(
                self.formatDict["DWORD_F"], file.read(self.formatDict["DWORD_S"])
            )
            (_IMAGE_OPTIONAL_HEADER["Subsystem"],) = struct.unpack(
                self.formatDict["WORD_F"], file.read(self.formatDict["WORD_S"])
            )
            (_IMAGE_OPTIONAL_HEADER["DllCharacteristics"],) = struct.unpack(
                self.formatDict["WORD_F"], file.read(self.formatDict["WORD_S"])
            )
            (_IMAGE_OPTIONAL_HEADER["SizeOfStackReserve"],) = struct.unpack(
                self.formatDict["DWORD_F"], file.read(self.formatDict["DWORD_S"])
            )
            (_IMAGE_OPTIONAL_HEADER["SizeOfStackCommit"],) = struct.unpack(
                self.formatDict["DWORD_F"], file.read(self.formatDict["DWORD_S"])
            )
            (_IMAGE_OPTIONAL_HEADER["SizeOfHeapReserve"],) = struct.unpack(
                self.formatDict["DWORD_F"], file.read(self.formatDict["DWORD_S"])
            )
            (_IMAGE_OPTIONAL_HEADER["SizeOfHeapCommit"],) = struct.unpack(
                self.formatDict["DWORD_F"], file.read(self.formatDict["DWORD_S"])
            )
            (_IMAGE_OPTIONAL_HEADER["LoaderFlags"],) = struct.unpack(
                self.formatDict["DWORD_F"], file.read(self.formatDict["DWORD_S"])
            )
            (_IMAGE_OPTIONAL_HEADER["NumberOfRvaAndSizes"],) = struct.unpack(
                self.formatDict["DWORD_F"], file.read(self.formatDict["DWORD_S"])
            )

            return _IMAGE_OPTIONAL_HEADER

    def _read_IMAGE_DIRECTORY_ENTRY_IMPORT(self) -> dict:
        IMAGE_DIRECTORY_ENTRY_IMPORT = {}
        with open(self.path, "rb") as file:
            # Jump to the _IMAGE_DIRECTORY_ENTRY_IMPORT struct
            file.seek(self._IMAGE_DOS_HEADER["e_lfanew"], 0)
            file.seek(IMAGE_DIRECTORY_ENTRY_IMPORT_OFFSET, 1)

            # Parse information from _IMAGE_DIRECTORY_ENTRY_IMPORT struct
            (IMAGE_DIRECTORY_ENTRY_IMPORT["VirtualAddress"],) = struct.unpack(
                self.formatDict["DWORD_F"], file.read(self.formatDict["DWORD_S"])
            )
            (IMAGE_DIRECTORY_ENTRY_IMPORT["Size"],) = struct.unpack(
                self.formatDict["DWORD_F"], file.read(self.formatDict["DWORD_S"])
            )

            # Read imported DLL information
            dlls = self._read_IMAGE_IMPORT_DESCRIPTORs(
                IMAGE_DIRECTORY_ENTRY_IMPORT["VirtualAddress"]
            )

            print("Collected DLLs:\n")
            for dll in dlls:
                print(dll)

    def _read_IMAGE_IMPORT_DESCRIPTORs(self, virtualAddress) -> list:

        # Initialize a list to store the parsed DLL information
        dlls = []

        with open(self.path, "rb") as file:
            # Jump to the first _IMAGE_IMPORT_DESCRIPTOR struct
            file.seek(virtualAddress, 0)

            # Parse _IMAGE_IMPORT_DESCRIPTOR structs until terminating NULL struct is found
            while True:
                # Initialize a new dictionary entry for imported DLL
                dll = {}

                # Jump to Name in _IMAGE_IMPORT_DESCRIPTOR struct
                file.seek(0xC, 1)

                # Parse information from _IMAGE_IMPORT_DESCRIPTOR struct
                (namePointer,) = struct.unpack(
                    self.formatDict["DWORD_F"], file.read(self.formatDict["DWORD_S"])
                )
                (firstThunkPointer,) = struct.unpack(
                    self.formatDict["DWORD_F"], file.read(self.formatDict["DWORD_S"])
                )

                # Exit if the terminating NULL struct is found
                if namePointer == 0 and firstThunkPointer == 0:
                    break

                # Collect data from parsed pointers
                dll["Name"] = self._read_string_from_offset(namePointer)
                dll["ListOfFunctions"] = self._read_IMAGE_THUNK_DATA_entries(
                    firstThunkPointer
                )

                # Append the parsed DLL information to the list of imported DLLs
                dlls.append(dll)

            # Return the list of imnported DLLs
            return dlls

    def _read_IMAGE_THUNK_DATA_entries(self, firstThunkPointer) -> list:

        # Initialize a list to store the parsed function names
        functions = []

        # Jump to provided offset of the first _IMAGE_THUNK_DATA struct
        with open(self.path, "rb") as file:
            file.seek(firstThunkPointer, 0)

            # Iterate over _IMAGE_THUNK_DATA structs and collect function names
            while True:
                # Read the pointer to the function name
                (functionNamePointer,) = struct.unpack(
                    self.formatDict["DWORD_F"], file.read(self.formatDict["DWORD_S"])
                )

                # Check for the terminating NULL entry
                if functionNamePointer == 0:
                    break

                # Read the name of the imported function
                functions.append(self._read_string_from_offset(functionNamePointer))

            # Return the collected list of imported functions
            return functions

    def _read_string_from_offset(self, stringOffset) -> str:
        with open(self.path, "rb") as file:
            # Jump to provided offset of string
            file.seek(stringOffset)
            # Read character-by-character until null terminator
            parsedString = "".join(iter(lambda: file.read(1).decode("ascii"), "\x00"))
            # Return the parsed string
            return parsedString
