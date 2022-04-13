"""
Description: This file defines the ELF32 class inheriting from the BinaryFile class.
"""

from platform import machine
from BinaryFile import BinaryFile
import struct


E_MACHINE_OFFSET = 0x5
E_IDENT_SIZE = 0x10
E_TYPE_DICT = {
    0x0000: "ET_NONE",
    0x0001: "ET_REL",
    0x0002: "ET_EXEC",
    0x0003: "ET_DYN",
    0x0004: "ET_CORE",
    0xFE00: "ET_LOOS",
    0xFEFF: "ET_HIOS",
    0xFF00: "ET_LOPROC",
    0xFFFF: "ET_HIPROC",
}
E_MACHINE_DICT = {
    0x0000: "No specific instruction set",
    0x0001: "AT&T WE 32100",
    0x0002: "SPARC",
    0x0003: "x86",
    0x0004: "Motorola 68000 (M68k)",
    0x0005: "Motorola 88000 (M88k)",
    0x0006: "Intel MCU",
    0x0007: "Intel 80860",
    0x0008: "MIPS",
    0x0009: "IBM System/370",
    0x000A: "MIPS RS3000 Little-endian",
    0x000E: "Hewlett-Packard PA-RISC",
    0x0013: "Intel 80960",
    0x0014: "PowerPC",
    0x0015: "PowerPC (64-bit)",
    0x0016: "S390, including S390x",
    0x0017: "IBM SPU/SPC",
    0x0024: "NEC V800",
    0x0025: "Fujitsu FR20",
    0x0026: "TRW RH-32",
    0x0027: "Motorola RCE",
    0x0028: "ARM (up to ARMv7/Aarch32)",
    0x0029: "Digital Alpha",
    0x002A: "SuperH",
    0x002B: "SPARC Version 9",
    0x002C: "Siemens TriCore embedded processor",
    0x002D: "Argonaut RISC Core",
    0x002E: "Hitachi H8/300",
    0x002F: "Hitachi H8/300H",
    0x0030: "Hitachi H8S",
    0x0031: "Hitachi H8/500",
    0x0032: "IA-64",
    0x0033: "Stanford MIPS-X",
    0x0034: "Motorola ColdFire",
    0x0035: "Motorola M68HC12",
    0x0036: "Fujitsu MMA Multimedia Accelerator",
    0x0037: "Siemens PCP",
    0x0038: "Sony nCPU embedded RISC processor",
    0x0039: "Denso NDR1 microprocessor",
    0x003A: "Motorola Star*Core processor",
    0x003B: "Toyota ME16 processor",
    0x003C: "STMicroelectronics ST100 processor",
    0x003D: "Advanced Logic Corp. TinyJ embedded processor family",
    0x003E: "AMD x86-64",
    0x008C: "TMS320C6000 Family",
    0x00AF: "MCST Elbrus e2k",
    0x00B7: "ARM 64-bits (ARMv8/Aarch64)",
    0x00F3: "RISC-V",
    0x00F7: "Berkeley Packet Filter",
    0x0101: "WDC 65C816",
}


class ELF32(BinaryFile):
    """Executable and Linkable Format (32-bit addressable)"""

    def __init__(self, path):
        """Initializes local variables and analyze the provided binary file

        Args:
            path (str): file path of the provided binary
        """
        self.path = path
        self.formatDict = None
        self._find_endianess()
        self.Elf32_Ehdr = self._read_Elf32_Ehdr()
        self.Elf32_Phdr = self._read_Elf32_Phdr()

    def print_file_type(self) -> None:
        """Display the file type of the provided binary file"""
        print(f"Executable and Linkable Format, 32-bit Addressable (ELF32)\n")

    def print_header_info(self) -> None:
        """Prints the header information parsed from the provided binary for the user to view"""

        print(
            f"ELF HEADER:\n"
            + f"e_ident Structure:\t\t{self.Elf32_Ehdr['e_ident']}\n"
            + f"Type:\t\t\t\t{hex(self.Elf32_Ehdr['e_type'])} ({self.Elf32_Ehdr['e_typeName']})\n"
            + f"Machine:\t\t\t{hex(self.Elf32_Ehdr['e_machine'])} ({self.Elf32_Ehdr['e_machineName']})\n"
            + f"Version:\t\t\t{self.Elf32_Ehdr['e_version']}\n"
            + f"Entry Point:\t\t\t{hex(self.Elf32_Ehdr['e_entry'])}\n"
            + f"Program Header Offset:\t\t{hex(self.Elf32_Ehdr['e_phoff'])}\n"
            + f"Section Header Offset:\t\t{hex(self.Elf32_Ehdr['e_shoff'])}\n"
            + f"Architecture Specific Flags:\t{hex(self.Elf32_Ehdr['e_flags'])}\n"
            + f"ELF Header Size:\t\t{hex(self.Elf32_Ehdr['e_ehsize'])}\n"
            + f"Program Header Entry Size:\t{hex(self.Elf32_Ehdr['e_phentsize'])}\n"
            + f"Number of Program Headers:\t{self.Elf32_Ehdr['e_phnum']}\n"
            + f"Section Header Entry Size:\t{hex(self.Elf32_Ehdr['e_shentsize'])}\n"
            + f"Number of Section Headers:\t{self.Elf32_Ehdr['e_shnum']}\n"
            + f"Section Name String Table:\t{hex(self.Elf32_Ehdr['e_shstrndx'])}\n"
        )

    def _find_endianess(self) -> None:
        """ELF files contain a flag in the file header which denotes the endianness of the file"""

        with open(self.path, "rb") as file:
            # Jump past the magic bytes at the beginning of the file header
            file.seek(E_MACHINE_OFFSET, 0)
            (e_machineTag,) = struct.unpack("<b", file.read(1))
            if e_machineTag == 1:
                # The binary is little endian formatted
                self.formatDict = {
                    "Elf32_Half_F": "<H",
                    "Elf32_Half_S": 2,
                    "Elf32_Addr_F": "<L",
                    "Elf32_Addr_S": 4,
                    "Elf32_Off_F": "<L",
                    "Elf32_Off_S": 4,
                    "Elf32_Word_F": "<L",
                    "Elf32_Word_S": 4,
                    "Elf32_Hashelt_F": "<L",
                    "Elf32_Hashelt_S": 4,
                    "Elf32_Size_F": "<L",
                    "Elf32_Size_S": 4,
                    "Elf32_Sword_F": "<l",
                    "Elf32_Sword_S": 4,
                    "Elf32_Ssize_F": "<l",
                    "Elf32_Ssize_S": 4,
                    "Elf32_Lword_F": "<Q",
                    "Elf32_Lword_S": 8,
                }
            else:
                # The binary is big endian formatted
                self.formatDict = {
                    "Elf32_Half_F": ">H",
                    "Elf32_Half_S": 2,
                    "Elf32_Addr_F": ">L",
                    "Elf32_Addr_F": 4,
                    "Elf32_Off_F": ">L",
                    "Elf32_Off_S": 4,
                    "Elf32_Word_F": ">L",
                    "Elf32_Word_S": 4,
                    "Elf32_Hashelt_F": ">L",
                    "Elf32_Hashelt_S": 4,
                    "Elf32_Size_F": ">L",
                    "Elf32_Size_S": 4,
                    "Elf32_Sword_F": ">l",
                    "Elf32_Sword_S": 4,
                    "Elf32_Ssize_F": ">l",
                    "Elf32_Ssize_S": 4,
                    "Elf32_Lword_F": ">Q",
                    "Elf32_Lword_S": 8,
                }

    def _read_Elf32_Ehdr(self) -> dict:
        """Parses information from the ELF Header (Elf32_Ehdr structure)

        Returns:
            dict: a dictionary of data parsed from the ELF header
        """
        _Elf32_Ehdr = {}
        with open(self.path, "rb") as file:
            _Elf32_Ehdr["e_ident"] = file.read(E_IDENT_SIZE)
            (_Elf32_Ehdr["e_type"],) = struct.unpack(
                self.formatDict["Elf32_Half_F"],
                file.read(self.formatDict["Elf32_Half_S"]),
            )
            # Translate type flag into name
            _Elf32_Ehdr["e_typeName"] = E_TYPE_DICT[_Elf32_Ehdr["e_type"]]
            (_Elf32_Ehdr["e_machine"],) = struct.unpack(
                self.formatDict["Elf32_Half_F"],
                file.read(self.formatDict["Elf32_Half_S"]),
            )
            # Translate type flag into name
            _Elf32_Ehdr["e_machineName"] = E_MACHINE_DICT[_Elf32_Ehdr["e_machine"]]
            (_Elf32_Ehdr["e_version"],) = struct.unpack(
                self.formatDict["Elf32_Word_F"],
                file.read(self.formatDict["Elf32_Word_S"]),
            )
            (_Elf32_Ehdr["e_entry"],) = struct.unpack(
                self.formatDict["Elf32_Addr_F"],
                file.read(self.formatDict["Elf32_Addr_S"]),
            )
            (_Elf32_Ehdr["e_phoff"],) = struct.unpack(
                self.formatDict["Elf32_Off_F"],
                file.read(self.formatDict["Elf32_Off_S"]),
            )
            (_Elf32_Ehdr["e_shoff"],) = struct.unpack(
                self.formatDict["Elf32_Off_F"],
                file.read(self.formatDict["Elf32_Off_S"]),
            )
            (_Elf32_Ehdr["e_flags"],) = struct.unpack(
                self.formatDict["Elf32_Word_F"],
                file.read(self.formatDict["Elf32_Word_S"]),
            )
            (_Elf32_Ehdr["e_ehsize"],) = struct.unpack(
                self.formatDict["Elf32_Half_F"],
                file.read(self.formatDict["Elf32_Half_S"]),
            )
            (_Elf32_Ehdr["e_phentsize"],) = struct.unpack(
                self.formatDict["Elf32_Half_F"],
                file.read(self.formatDict["Elf32_Half_S"]),
            )
            (_Elf32_Ehdr["e_phnum"],) = struct.unpack(
                self.formatDict["Elf32_Half_F"],
                file.read(self.formatDict["Elf32_Half_S"]),
            )
            (_Elf32_Ehdr["e_shentsize"],) = struct.unpack(
                self.formatDict["Elf32_Half_F"],
                file.read(self.formatDict["Elf32_Half_S"]),
            )
            (_Elf32_Ehdr["e_shnum"],) = struct.unpack(
                self.formatDict["Elf32_Half_F"],
                file.read(self.formatDict["Elf32_Half_S"]),
            )
            (_Elf32_Ehdr["e_shstrndx"],) = struct.unpack(
                self.formatDict["Elf32_Half_F"],
                file.read(self.formatDict["Elf32_Half_S"]),
            )

            return _Elf32_Ehdr

    def _read_Elf32_Phdr(self) -> dict:
        """Parses information from the Program Header (Elf32_Phdr structure)

        Returns:
            dict: a dictionary of data parsed from the program header
        """
        _Elf32_Phdr = {}
        with open(self.path, "rb") as file:
            (_Elf32_Phdr["p_type"],) = struct.unpack(
                self.formatDict["Elf32_Word_F"],
                file.read(self.formatDict["Elf32_Word_S"]),
            )
            (_Elf32_Phdr["p_offset"],) = struct.unpack(
                self.formatDict["Elf32_Off_F"],
                file.read(self.formatDict["Elf32_Off_S"]),
            )
            (_Elf32_Phdr["p_vaddr"],) = struct.unpack(
                self.formatDict["Elf32_Addr_F"],
                file.read(self.formatDict["Elf32_Addr_S"]),
            )
            (_Elf32_Phdr["p_paddr"],) = struct.unpack(
                self.formatDict["Elf32_Addr_F"],
                file.read(self.formatDict["Elf32_Addr_S"]),
            )
            (_Elf32_Phdr["p_filesz"],) = struct.unpack(
                self.formatDict["Elf32_Word_F"],
                file.read(self.formatDict["Elf32_Word_S"]),
            )
            (_Elf32_Phdr["p_memsz"],) = struct.unpack(
                self.formatDict["Elf32_Word_F"],
                file.read(self.formatDict["Elf32_Word_S"]),
            )
            (_Elf32_Phdr["p_flags"],) = struct.unpack(
                self.formatDict["Elf32_Word_F"],
                file.read(self.formatDict["Elf32_Word_S"]),
            )
            (_Elf32_Phdr["p_align"],) = struct.unpack(
                self.formatDict["Elf32_Word_F"],
                file.read(self.formatDict["Elf32_Word_S"]),
            )

            return _Elf32_Phdr
