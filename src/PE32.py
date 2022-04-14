"""
Description: This file defines the PE32 class inheriting from the BinaryFile class.
"""

from BinaryFile import BinaryFile
from bcolors import colors
import struct


E_RES1_SIZE = 0x8
E_RES2_SIZE = 0x14
IMAGE_FILE_HEADER_OFFSET = 0x4
IMAGE_FILE_HEADER_CHARACTERISTICS_DICT = {
    0x0001: "IMAGE_FILE_RELOCS_STRIPPED",
    0x0002: "IMAGE_FILE_EXECUTABLE_IMAGE",
    0x0004: "IMAGE_FILE_LINE_NUMS_STRIPPED",
    0x0008: "IMAGE_FILE_LOCAL_SYMS_STRIPPED",
    0x0010: "IMAGE_FILE_AGGRESIVE_WS_TRIM",
    0x0020: "IMAGE_FILE_LARGE_ADDRESS_AWARE",
    0x0080: "IMAGE_FILE_BYTES_REVERSED_LO",
    0x0100: "IMAGE_FILE_32BIT_MACHINE",
    0x0200: "IMAGE_FILE_DEBUG_STRIPPED",
    0x0400: "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP",
    0x0800: "IMAGE_FILE_NET_RUN_FROM_SWAP",
    0x1000: "IMAGE_FILE_SYSTEM",
    0x2000: "IMAGE_FILE_DLL",
    0x4000: "IMAGE_FILE_UP_SYSTEM_ONLY",
    0x8000: "IMAGE_FILE_BYTES_REVERSED_HI",
}
IMAGE_OPTIONAL_HEADER_OFFSET = 0x18
IMAGE_OPTIONAL_HEADER_MAGIC_DICT = {
    0x10B: "IMAGE_NT_OPTIONAL_HDR32_MAGIC",
    0x20B: "IMAGE_NT_OPTIONAL_HDR64_MAGIC",
    0x107: "IMAGE_ROM_OPTIONAL_HDR_MAGIC",
}
IMAGE_OPTIONAL_HEADER_SUBSYSTEM_DICT = {
    0: "IMAGE_SUBSYSTEM_UNKNOWN",
    1: "IMAGE_SUBSYSTEM_NATIVE",
    2: "IMAGE_SUBSYSTEM_WINDOWS_GUI",
    3: "IMAGE_SUBSYSTEM_WINDOWS_CUI",
    5: "IMAGE_SUBSYSTEM_OS2_CUI",
    7: "IMAGE_SUBSYSTEM_POSIX_CUI",
    9: "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI",
    10: "IMAGE_SUBSYSTEM_EFI_APPLICATION",
    11: "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER",
    12: "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER",
    13: "IMAGE_SUBSYSTEM_EFI_ROM",
    14: "IMAGE_SUBSYSTEM_XBOX",
    16: "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION",
}
IMAGE_OPTIONAL_HEADER_DLLCHARACTERISTICS_DICT = {
    0x0001: "Reserved",
    0x0002: "Reserved",
    0x0004: "Reserved",
    0x0008: "Reserved",
    0x0020: "IMAGE_DLL_CHARACTERISTICS_HIGH_ENTROPY_VA",
    0x0040: "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE",
    0x0080: "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY",
    0x0100: "IMAGE_DLLCHARACTERISTICS_NX_COMPAT",
    0x0200: "IMAGE_DLLCHARACTERISTICS_NO_ISOLATION",
    0x0400: "IMAGE_DLLCHARACTERISTICS_NO_SEH",
    0x0800: "IMAGE_DLLCHARACTERISTICS_NO_BIND",
    0x1000: "IMAGE_DLL_CHARACTERISTICS_APPCONTAINER",
    0x2000: "IMAGE_DLLCHARACTERISTICS_WDM_DRIVER",
    0x4000: "IMAGE_DLL_CHARACTERISTICS_GUARD_CF",
    0x8000: "IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE",
}
IMAGE_DATA_DIRECTORY_TABLE_OFFSET = 0x78
IMAGE_DATA_DIRECTORY_DICT = [
    "IMAGE_DIRECTORY_ENTRY_EXPORT",
    "IMAGE_DIRECTORY_ENTRY_IMPORT",
    "IMAGE_DIRECTORY_ENTRY_RESOURCE",
    "IMAGE_DIRECTORY_ENTRY_EXCEPTION",
    "IMAGE_DIRECTORY_ENTRY_SECURITY",
    "IMAGE_DIRECTORY_ENTRY_BASERELOC",
    "IMAGE_DIRECTORY_ENTRY_DEBUG",
    "IMAGE_DIRECTORY_ENTRY_COPYRIGHT",
    "IMAGE_DIRECTORY_ENTRY_GLOBALPTR",
    "IMAGE_DIRECTORY_ENTRY_TLS",
    "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG",
    "IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT",
    "IMAGE_DIRECTORY_ENTRY_IAT",
    "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT",
    "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR",
]
IMAGE_FILE_MACHINE_DICT = {
    0x014C: "IMAGE_FILE_MACHINE_I386",
    0x0200: "IMAGE_FILE_MACHINE_IA64",
    0x8664: "IMAGE_FILE_MACHINE_AMD64",
}


class PE32(BinaryFile):
    """Windows Portable Executable (32-bit addressable)"""

    def __init__(self, path):
        """Initializes local variables and analyze the provided binary file

        Args:
            path (str): file path of the provided binary
        """
        self.path = path
        self.formatDict = None
        self._find_endianess()
        self._IMAGE_DOS_HEADER = self._read_IMAGE_DOS_HEADER()
        self._IMAGE_FILE_HEADER = self._read_IMAGE_FILE_HEADER()
        self._IMAGE_OPTIONAL_HEADER = self._read_IMAGE_OPTIONAL_HEADER()
        self._IMAGE_DATA_DIRECTORY_TABLE = self._read_IMAGE_DATA_DIRECTORY_array()

    def print_file_type(self) -> None:
        """Display the file type of the provided binary file"""
        print(
            f"\n{colors.HEADER}{colors.BOLD}Windows Portable Executable, 32-bit Addressable (PE32){colors.ENDC}\n"
        )

    def print_header_info(self) -> None:
        """Prints the header information parsed from the provided binary for the user to view"""

        print(
            f"DOS HEADER (_IMAGE_DOS_HEADER):\n"
            + f"    Magic Number:\t\t\t{hex(self._IMAGE_DOS_HEADER['e_magic'])} ({self._IMAGE_DOS_HEADER['e_magic_characters']})\n"
            + f"    Bytes in Last Page:\t\t\t{self._IMAGE_DOS_HEADER['e_cblp']}\n"
            + f"    Pages in File:\t\t\t{self._IMAGE_DOS_HEADER['e_cp']}\n"
            + f"    Relocations:\t\t\t{self._IMAGE_DOS_HEADER['e_crlc']}\n"
            + f"    Size of Header in Paragraphs:\t{self._IMAGE_DOS_HEADER['e_cparhdr']}\n"
            + f"    Minimum Extra Paragraphs:\t\t{self._IMAGE_DOS_HEADER['e_minalloc']}\n"
            + f"    Maximum Extra Paragraphs:\t\t{self._IMAGE_DOS_HEADER['e_maxalloc']}\n"
            + f"    Initial (relative) SS Value:\t{self._IMAGE_DOS_HEADER['e_ss']}\n"
            + f"    Initial SP Value:\t\t\t{hex(self._IMAGE_DOS_HEADER['e_sp'])}\n"
            + f"    Checksum:\t\t\t\t{self._IMAGE_DOS_HEADER['e_csum']}\n"
            + f"    Initial IP Value:\t\t\t{self._IMAGE_DOS_HEADER['e_ip']}\n"
            + f"    Initial (relative) CS Value:\t{self._IMAGE_DOS_HEADER['e_cs']}\n"
            + f"    File Address of relocation table:\t{hex(self._IMAGE_DOS_HEADER['e_lfarlc'])}\n"
            + f"    Overlay Number:\t\t\t{hex(self._IMAGE_DOS_HEADER['e_ovno'])}\n"
            + f"    OEM Identifier:\t\t\t{self._IMAGE_DOS_HEADER['e_oemid']}\n"
            + f"    OEM Information:\t\t\t{self._IMAGE_DOS_HEADER['e_oeminfo']}\n"
            + f"    File Address of New Exe Header:\t{hex(self._IMAGE_DOS_HEADER['e_lfanew'])}\n"
            + f"\n"
            + f"COFF/FILE HEADER (_IMAGE_FILE_HEADER):\n"
            + f"    Machine:\t\t\t\t{hex(self._IMAGE_FILE_HEADER['Machine'])} ({self._IMAGE_FILE_HEADER['MachineName']})\n"
            + f"    Number of Sections:\t\t\t{self._IMAGE_FILE_HEADER['NumberOfSections']}\n"
            + f"    Time Stamp:\t\t\t\t{self._IMAGE_FILE_HEADER['TimeDateStamp']}\n"
            + f"    Address of Symbol Table:\t\t{hex(self._IMAGE_FILE_HEADER['PointerToSymbolTable'])}\n"
            + f"    Number of Symbols:\t\t\t{self._IMAGE_FILE_HEADER['NumberOfSymbols']}\n"
            + f"    Size of Optional Header:\t\t{hex(self._IMAGE_FILE_HEADER['SizeOfOptionalHeader'])}\n"
            + f"    Characteristics:\t\t\t{hex(self._IMAGE_FILE_HEADER['Characteristics'])}"
        )
        # If Characteristics is not 0, print all Characteristics
        if self._IMAGE_FILE_HEADER["Characteristics"] != 0:
            for characteristic in self._IMAGE_FILE_HEADER["ListOfChars"]:
                print(f"       - {characteristic}")
        print(
            f"\n"
            + f"OPTIONAL HEADER (_IMAGE_OPTIONAL_HEADER):\n"
            + f"    Magic:\t\t\t\t{hex(self._IMAGE_OPTIONAL_HEADER['Magic'])} ({self._IMAGE_OPTIONAL_HEADER['MagicName']})\n"
            + f"    Linker Version:\t\t\t{self._IMAGE_OPTIONAL_HEADER['MajorLinkerVersion']}.{self._IMAGE_OPTIONAL_HEADER['MinorLinkerVersion']}\n"
            + f"    Size of .text section:\t\t{hex(self._IMAGE_OPTIONAL_HEADER['SizeOfCode'])}\n"
            + f"    Size of .data section:\t\t{hex(self._IMAGE_OPTIONAL_HEADER['SizeOfInitializedData'])}\n"
            + f"    Size of .bss section:\t\t{hex(self._IMAGE_OPTIONAL_HEADER['SizeOfUninitializedData'])}\n"
            + f"    Address of Entry Point:\t\t{hex(self._IMAGE_OPTIONAL_HEADER['AddressOfEntryPoint'])}\n"
            + f"    Address of .text section:\t\t{hex(self._IMAGE_OPTIONAL_HEADER['BaseOfCode'])}\n"
            + f"    Address of .data section:\t\t{hex(self._IMAGE_OPTIONAL_HEADER['BaseOfData'])}\n"
            + f"    Image Base:\t\t\t\t{hex(self._IMAGE_OPTIONAL_HEADER['ImageBase'])}\n"
            + f"    Section Alignment:\t\t\t{hex(self._IMAGE_OPTIONAL_HEADER['SectionAlignment'])}\n"
            + f"    File Alignment:\t\t\t{hex(self._IMAGE_OPTIONAL_HEADER['FileAlignment'])}\n"
            + f"    Operating System Version:\t\t{self._IMAGE_OPTIONAL_HEADER['MajorOperatingSystemVersion']}.{self._IMAGE_OPTIONAL_HEADER['MinorOperatingSystemVersion']}\n"
            + f"    Image Version:\t\t\t{self._IMAGE_OPTIONAL_HEADER['MajorImageVersion']}.{self._IMAGE_OPTIONAL_HEADER['MinorImageVersion']}\n"
            + f"    Subsystem Version:\t\t\t{self._IMAGE_OPTIONAL_HEADER['MajorSubsystemVersion']}.{self._IMAGE_OPTIONAL_HEADER['MinorSubsystemVersion']}\n"
            + f"    Win32 Version Value:\t\t{self._IMAGE_OPTIONAL_HEADER['Win32VersionValue']}\n"
            + f"    Size of Image:\t\t\t{hex(self._IMAGE_OPTIONAL_HEADER['SizeOfImage'])}\n"
            + f"    Size of Headers:\t\t\t{hex(self._IMAGE_OPTIONAL_HEADER['SizeOfHeaders'])}\n"
            + f"    Checksum:\t\t\t\t{hex(self._IMAGE_OPTIONAL_HEADER['Checksum'])}\n"
            + f"    Subsystem:\t\t\t\t{self._IMAGE_OPTIONAL_HEADER['Subsystem']} ({self._IMAGE_OPTIONAL_HEADER['SubsystemName']})\n"
            + f"    DLL Characteristics:\t\t{hex(self._IMAGE_OPTIONAL_HEADER['DllCharacteristics'])}"
        )
        # If DLLCharacteristics is not 0, print all DLL Characteristics
        if self._IMAGE_OPTIONAL_HEADER["DllCharacteristics"] != 0:
            for characteristic in self._IMAGE_OPTIONAL_HEADER["ListOfDllChars"]:
                print(f"       - {characteristic}")
        print(
            f"    Size of Stack Reserve:\t\t{hex(self._IMAGE_OPTIONAL_HEADER['SizeOfStackReserve'])}\n"
            + f"    Size of Stack Commit:\t\t{hex(self._IMAGE_OPTIONAL_HEADER['SizeOfStackCommit'])}\n"
            + f"    Size of Heap Reserve:\t\t{hex(self._IMAGE_OPTIONAL_HEADER['SizeOfHeapReserve'])}\n"
            + f"    Sizeof Heap Commit:\t\t\t{hex(self._IMAGE_OPTIONAL_HEADER['SizeOfHeapCommit'])}\n"
            + f"    Loader Flags:\t\t\t{hex(self._IMAGE_OPTIONAL_HEADER['LoaderFlags'])}\n"
            + f"    Number of RVA and Sizes:\t\t{self._IMAGE_OPTIONAL_HEADER['NumberOfRvaAndSizes']}\n"
            + f"\n"
            + f"DATA DIRECTORIES (_IMAGE_OPTIONAL_HEADER):"
        )
        # Create a list of DATA_DIRECTORY names from dictionary keys
        DATA_DIRECTORIES = list(self._IMAGE_DATA_DIRECTORY_TABLE.keys())
        for DATA_DIRECTORY in DATA_DIRECTORIES:
            infoDict = self._IMAGE_DATA_DIRECTORY_TABLE[DATA_DIRECTORY]
            print(
                f"    {DATA_DIRECTORY:<40}  {hex(infoDict['VirtualAddress'])} (Length: {hex(infoDict['Size'])})"
            )

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
        """Parse the _IMAGE_DOS_HEADER structure

        Returns:
            dict: dictionary of data parsed from the _IMAGE_DOS_HEADER structure
        """

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

            # Translate magic numbers into characters
            e_magicHexBytes = _IMAGE_DOS_HEADER["e_magic"].to_bytes(4, "little")
            _IMAGE_DOS_HEADER["e_magic_characters"] = e_magicHexBytes.decode("utf-8")

            return _IMAGE_DOS_HEADER

    def _read_IMAGE_FILE_HEADER(self) -> dict:
        """Parse the _IMAGE_FILE_HEADER structure

        Returns:
            dict: dictionary of data parsed from the _IMAGE_FILE_HEADER structure
        """

        _IMAGE_FILE_HEADER = {}
        with open(self.path, "rb") as file:
            # Jump to the _IMAGE_FILE_HEADER struct
            file.seek(self._IMAGE_DOS_HEADER["e_lfanew"], 0)
            file.seek(IMAGE_FILE_HEADER_OFFSET, 1)

            # Read Machine and translate
            (_IMAGE_FILE_HEADER["Machine"],) = struct.unpack(
                self.formatDict["WORD_F"], file.read(self.formatDict["WORD_S"])
            )
            if _IMAGE_FILE_HEADER["Machine"] in IMAGE_FILE_MACHINE_DICT:
                _IMAGE_FILE_HEADER["MachineName"] = IMAGE_FILE_MACHINE_DICT[
                    _IMAGE_FILE_HEADER["Machine"]
                ]
            else:
                _IMAGE_FILE_HEADER[
                    "MachineName"
                ] = f"{colors.FAIL}{colors.BOLD}ERROR{colors.ENDC}"
            # Read NumberOfSections
            (_IMAGE_FILE_HEADER["NumberOfSections"],) = struct.unpack(
                self.formatDict["WORD_F"], file.read(self.formatDict["WORD_S"])
            )
            # Read TimeDateStamp
            (_IMAGE_FILE_HEADER["TimeDateStamp"],) = struct.unpack(
                self.formatDict["DWORD_F"], file.read(self.formatDict["DWORD_S"])
            )
            # Read PointerToSymbolTable
            (_IMAGE_FILE_HEADER["PointerToSymbolTable"],) = struct.unpack(
                self.formatDict["DWORD_F"], file.read(self.formatDict["DWORD_S"])
            )
            # Read NumberOfSymbols
            (_IMAGE_FILE_HEADER["NumberOfSymbols"],) = struct.unpack(
                self.formatDict["DWORD_F"], file.read(self.formatDict["DWORD_S"])
            )
            # Read SizeOfOptionalHeader
            (_IMAGE_FILE_HEADER["SizeOfOptionalHeader"],) = struct.unpack(
                self.formatDict["WORD_F"], file.read(self.formatDict["WORD_S"])
            )
            # Read Characteristics and translate
            (_IMAGE_FILE_HEADER["Characteristics"],) = struct.unpack(
                self.formatDict["WORD_F"], file.read(self.formatDict["WORD_S"])
            )
            if _IMAGE_FILE_HEADER["Characteristics"] != 0x0:
                # Initialize a list to store all parsed DLL characteristics
                _IMAGE_FILE_HEADER["ListOfChars"] = []
                # Translate DLL Charachetistics value into a list of characteristics
                for charID in list(IMAGE_FILE_HEADER_CHARACTERISTICS_DICT.keys()):
                    if _IMAGE_FILE_HEADER["Characteristics"] & charID == charID:
                        _IMAGE_FILE_HEADER["ListOfChars"].append(
                            IMAGE_FILE_HEADER_CHARACTERISTICS_DICT[charID]
                        )

            return _IMAGE_FILE_HEADER

    def _read_IMAGE_OPTIONAL_HEADER(self) -> dict:
        """Parse the _IMAGE_OPTIONAL_HEADER structure

        Returns:
            dict: dictionary of data parsed from the _IMAGE_OPTIONAL_HEADER structure
        """

        _IMAGE_OPTIONAL_HEADER = {}
        with open(self.path, "rb") as file:
            # Jump to the _IMAGE_OPTIONAL_HEADER struct
            file.seek(self._IMAGE_DOS_HEADER["e_lfanew"], 0)
            file.seek(IMAGE_OPTIONAL_HEADER_OFFSET, 1)

            # Read Magic and translate
            (_IMAGE_OPTIONAL_HEADER["Magic"],) = struct.unpack(
                self.formatDict["WORD_F"], file.read(self.formatDict["WORD_S"])
            )
            if _IMAGE_OPTIONAL_HEADER["Magic"] in IMAGE_OPTIONAL_HEADER_MAGIC_DICT:
                _IMAGE_OPTIONAL_HEADER["MagicName"] = IMAGE_OPTIONAL_HEADER_MAGIC_DICT[
                    _IMAGE_OPTIONAL_HEADER["Magic"]
                ]
            else:
                _IMAGE_OPTIONAL_HEADER[
                    "MagicName"
                ] = f"{colors.FAIL}{colors.BOLD}ERROR{colors.ENDC}"
            # Read MajorLinkerVersion
            (_IMAGE_OPTIONAL_HEADER["MajorLinkerVersion"],) = struct.unpack(
                self.formatDict["BYTE_F"], file.read(self.formatDict["BYTE_S"])
            )
            # Read MinorLinkerVersion
            (_IMAGE_OPTIONAL_HEADER["MinorLinkerVersion"],) = struct.unpack(
                self.formatDict["BYTE_F"], file.read(self.formatDict["BYTE_S"])
            )
            # Read SizeOfCode
            (_IMAGE_OPTIONAL_HEADER["SizeOfCode"],) = struct.unpack(
                self.formatDict["DWORD_F"], file.read(self.formatDict["DWORD_S"])
            )
            # Read SizeOfInitializedData
            (_IMAGE_OPTIONAL_HEADER["SizeOfInitializedData"],) = struct.unpack(
                self.formatDict["DWORD_F"], file.read(self.formatDict["DWORD_S"])
            )
            # Read SizeOfUninitializedData
            (_IMAGE_OPTIONAL_HEADER["SizeOfUninitializedData"],) = struct.unpack(
                self.formatDict["DWORD_F"], file.read(self.formatDict["DWORD_S"])
            )
            # Read AddressOfEntryPoint
            (_IMAGE_OPTIONAL_HEADER["AddressOfEntryPoint"],) = struct.unpack(
                self.formatDict["DWORD_F"], file.read(self.formatDict["DWORD_S"])
            )
            # Read BaseOfCode
            (_IMAGE_OPTIONAL_HEADER["BaseOfCode"],) = struct.unpack(
                self.formatDict["DWORD_F"], file.read(self.formatDict["DWORD_S"])
            )
            # Read BaseOfData
            (_IMAGE_OPTIONAL_HEADER["BaseOfData"],) = struct.unpack(
                self.formatDict["DWORD_F"], file.read(self.formatDict["DWORD_S"])
            )
            # Read ImageBase
            (_IMAGE_OPTIONAL_HEADER["ImageBase"],) = struct.unpack(
                self.formatDict["DWORD_F"], file.read(self.formatDict["DWORD_S"])
            )
            # Read SectionAlignment
            (_IMAGE_OPTIONAL_HEADER["SectionAlignment"],) = struct.unpack(
                self.formatDict["DWORD_F"], file.read(self.formatDict["DWORD_S"])
            )
            # Read FileAlignment
            (_IMAGE_OPTIONAL_HEADER["FileAlignment"],) = struct.unpack(
                self.formatDict["DWORD_F"], file.read(self.formatDict["DWORD_S"])
            )
            # Read MajorOperatingSystemVersion
            (_IMAGE_OPTIONAL_HEADER["MajorOperatingSystemVersion"],) = struct.unpack(
                self.formatDict["WORD_F"], file.read(self.formatDict["WORD_S"])
            )
            # Read MinorOperatingSystemVersion
            (_IMAGE_OPTIONAL_HEADER["MinorOperatingSystemVersion"],) = struct.unpack(
                self.formatDict["WORD_F"], file.read(self.formatDict["WORD_S"])
            )
            # Read MajorImageVersion
            (_IMAGE_OPTIONAL_HEADER["MajorImageVersion"],) = struct.unpack(
                self.formatDict["WORD_F"], file.read(self.formatDict["WORD_S"])
            )
            # Read MinorImageVersion
            (_IMAGE_OPTIONAL_HEADER["MinorImageVersion"],) = struct.unpack(
                self.formatDict["WORD_F"], file.read(self.formatDict["WORD_S"])
            )
            # Read MajorSubsystemVersion
            (_IMAGE_OPTIONAL_HEADER["MajorSubsystemVersion"],) = struct.unpack(
                self.formatDict["WORD_F"], file.read(self.formatDict["WORD_S"])
            )
            # Read MinorSubsystemVersion
            (_IMAGE_OPTIONAL_HEADER["MinorSubsystemVersion"],) = struct.unpack(
                self.formatDict["WORD_F"], file.read(self.formatDict["WORD_S"])
            )
            # Read Win32VersionValue
            (_IMAGE_OPTIONAL_HEADER["Win32VersionValue"],) = struct.unpack(
                self.formatDict["DWORD_F"], file.read(self.formatDict["DWORD_S"])
            )
            # Read SizeOfImage
            (_IMAGE_OPTIONAL_HEADER["SizeOfImage"],) = struct.unpack(
                self.formatDict["DWORD_F"], file.read(self.formatDict["DWORD_S"])
            )
            # Read SizeOfHeaders
            (_IMAGE_OPTIONAL_HEADER["SizeOfHeaders"],) = struct.unpack(
                self.formatDict["DWORD_F"], file.read(self.formatDict["DWORD_S"])
            )
            # Read Checksum
            (_IMAGE_OPTIONAL_HEADER["Checksum"],) = struct.unpack(
                self.formatDict["DWORD_F"], file.read(self.formatDict["DWORD_S"])
            )
            # Read Subsystem and translate
            (_IMAGE_OPTIONAL_HEADER["Subsystem"],) = struct.unpack(
                self.formatDict["WORD_F"], file.read(self.formatDict["WORD_S"])
            )
            if (
                _IMAGE_OPTIONAL_HEADER["Subsystem"]
                in IMAGE_OPTIONAL_HEADER_SUBSYSTEM_DICT
            ):
                _IMAGE_OPTIONAL_HEADER[
                    "SubsystemName"
                ] = IMAGE_OPTIONAL_HEADER_SUBSYSTEM_DICT[
                    _IMAGE_OPTIONAL_HEADER["Subsystem"]
                ]
            else:
                _IMAGE_OPTIONAL_HEADER[
                    "SubsystemName"
                ] = f"{colors.FAIL}{colors.BOLD}ERROR{colors.ENDC}"
            # Read DllCharacteristics and translate
            (_IMAGE_OPTIONAL_HEADER["DllCharacteristics"],) = struct.unpack(
                self.formatDict["WORD_F"], file.read(self.formatDict["WORD_S"])
            )
            if _IMAGE_OPTIONAL_HEADER["DllCharacteristics"] != 0x0:
                # Initialize a list to store all parsed DLL characteristics
                _IMAGE_OPTIONAL_HEADER["ListOfDllChars"] = []
                # Translate DLL Charachetistics value into a list of characteristics
                for charID in list(
                    IMAGE_OPTIONAL_HEADER_DLLCHARACTERISTICS_DICT.keys()
                ):
                    if _IMAGE_OPTIONAL_HEADER["DllCharacteristics"] & charID == charID:
                        _IMAGE_OPTIONAL_HEADER["ListOfDllChars"].append(
                            IMAGE_OPTIONAL_HEADER_DLLCHARACTERISTICS_DICT[charID]
                        )
            # Read SizeOfStackReserve
            (_IMAGE_OPTIONAL_HEADER["SizeOfStackReserve"],) = struct.unpack(
                self.formatDict["DWORD_F"], file.read(self.formatDict["DWORD_S"])
            )
            # Read SizeOfStackCommit
            (_IMAGE_OPTIONAL_HEADER["SizeOfStackCommit"],) = struct.unpack(
                self.formatDict["DWORD_F"], file.read(self.formatDict["DWORD_S"])
            )
            # Read SizeOfHeapReserve
            (_IMAGE_OPTIONAL_HEADER["SizeOfHeapReserve"],) = struct.unpack(
                self.formatDict["DWORD_F"], file.read(self.formatDict["DWORD_S"])
            )
            # Read SizeOfHeapCommit
            (_IMAGE_OPTIONAL_HEADER["SizeOfHeapCommit"],) = struct.unpack(
                self.formatDict["DWORD_F"], file.read(self.formatDict["DWORD_S"])
            )
            # Read LoaderFlags
            (_IMAGE_OPTIONAL_HEADER["LoaderFlags"],) = struct.unpack(
                self.formatDict["DWORD_F"], file.read(self.formatDict["DWORD_S"])
            )
            # Read NumberOfRvaAndSizes
            (_IMAGE_OPTIONAL_HEADER["NumberOfRvaAndSizes"],) = struct.unpack(
                self.formatDict["DWORD_F"], file.read(self.formatDict["DWORD_S"])
            )

            return _IMAGE_OPTIONAL_HEADER

    def _read_IMAGE_DATA_DIRECTORY_array(self) -> dict:
        """Parses information about the existing data directories of the provided binary file

        Returns:
            dict: a dictionary of dictionaries, each containing the virtual address and size of a data dirtectory
        """

        _IMAGE_DATA_DIRECTORY_TABLE = {}
        with open(self.path, "rb") as file:
            # Jump to the _IMAGE_DATA_DIRECTORY table at the end of the _IMAGE_OPTIONAL_HEADER struct
            file.seek(self._IMAGE_DOS_HEADER["e_lfanew"], 0)
            file.seek(IMAGE_DATA_DIRECTORY_TABLE_OFFSET, 1)

            # Parse the _IMAGE_DATA_DIRECTORY table (NULL entries indicate that the data directory is not present)
            for IMAGE_DATA_DIRECTORY in IMAGE_DATA_DIRECTORY_DICT:
                DATA_DIRECTORY_ENTRY = {}
                (DATA_DIRECTORY_ENTRY["VirtualAddress"],) = struct.unpack(
                    self.formatDict["DWORD_F"], file.read(self.formatDict["DWORD_S"])
                )
                (DATA_DIRECTORY_ENTRY["Size"],) = struct.unpack(
                    self.formatDict["DWORD_F"], file.read(self.formatDict["DWORD_S"])
                )

                if (
                    DATA_DIRECTORY_ENTRY["VirtualAddress"] != 0
                    and DATA_DIRECTORY_ENTRY["Size"] != 0
                ):
                    # If the _IMAGE_DATA_DIRECTORY entry exists, add it to the dictionary of data directories
                    _IMAGE_DATA_DIRECTORY_TABLE[
                        IMAGE_DATA_DIRECTORY
                    ] = DATA_DIRECTORY_ENTRY
                else:
                    # If the _IMAGE_DATA_DIRECTORY entry is empty, the directory does not exist in the binary
                    pass

            return _IMAGE_DATA_DIRECTORY_TABLE

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
