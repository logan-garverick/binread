"""
Description: This file defines the ELF64 class inheriting from the BinaryFile class.
"""


from BinaryFile import BinaryFile
from bcolors import colors
import struct


E_MACHINE_OFFSET = 0x5
E_IDENT_SIZE = 0x10
EI_CLASS_DICT = {
    b"\x01": "32-Bit",
    b"\x02": "64-Bit",
}
EI_DATA_DICT = {
    b"\x01": "Little Endian",
    b"\x02": "Big Endian",
}
EI_OSABI_DICT = {
    b"\x00": "System V",
    b"\x01": "HP-UX",
    b"\x02": "NetBSD",
    b"\x03": "Linux",
    b"\x04": "GNU Hurd",
    b"\x06": "Solaris",
    b"\x07": "AIX (Monterey)",
    b"\x08": "IRIX",
    b"\x09": "FreeBSD",
    b"\x0A": "Tru64",
    b"\x0B": "Novell Modesto",
    b"\x0C": "OpenBSD",
    b"\x0D": "OpenVMS",
    b"\x0E": "NonStop Kernel",
    b"\x0F": "AROS",
    b"\x10": "FenixOS",
    b"\x11": "Nuxi CloudABI",
    b"\x12": "Stratus Technologies OpenVOS",
}
E_TYPE_DICT = {
    0x0000: "ET_NONE",
    0x0001: "ET_REL",
    0x0002: "ET_EXEC",
    0x0003: "ET_DYN",
    0x0004: "ET_CORE",
}
ET_LOOS = 0xFE00
ET_HIOS = 0xFEFF
ET_LOPROC = 0xFF00
ET_HIPROC = 0xFFFF
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
E_PHDR_TYPE_DICT = {
    0x00000000: "PT_NULL",
    0x00000001: "PT_LOAD",
    0x00000002: "PT_DYNAMIC",
    0x00000003: "PT_INTERP",
    0x00000004: "PT_NOTE",
    0x00000005: "PT_SHLIB",
    0x00000006: "PT_PHDR",
    0x00000007: "PT_TLS",
}
PT_LOOS = 0x60000000
PT_HIOS = 0x6FFFFFFF
PT_LOPROC = 0x70000000
PT_HIPROC = 0x7FFFFFFF
E_PHDR_FLAGS_DICT = {
    0x04: "R",
    0x02: "W",
    0x01: "X",
}
E_SHDR_TYPE_DICT = {
    0x00000000: "SHT_NULL",
    0x00000001: "SHT_PROGBITS",
    0x00000002: "SHT_SYMTAB",
    0x00000003: "SHT_STRTAB",
    0x00000004: "SHT_RELA",
    0x00000005: "SHT_HASH",
    0x00000006: "SHT_DYNAMIC",
    0x00000007: "SHT_NOTE",
    0x00000008: "SHT_NOBITS",
    0x00000009: "SHT_REL",
    0x0000000A: "SHT_SHLIB",
    0x0000000B: "SHT_DYNSYM",
    0x0000000E: "SHT_INIT_ARRAY",
    0x0000000F: "SHT_FINI_ARRAY",
    0x00000010: "SHT_PREINIT_ARRAY",
    0x00000011: "SHT_GROUP",
    0x00000012: "SHT_SYMTAB_SHNDX",
    0x00000013: "SHT_NUM",
}
SHT_LOOS = 0x60000000
E_SHDR_FLAGS_DICT = {
    0x00000001: "SHF_WRITE",
    0x00000002: "SHF_ALLOC",
    0x00000004: "SHF_EXECINSTR",
    0x00000010: "SHF_MERGE",
    0x00000020: "SHF_STRINGS",
    0x00000040: "SHF_INFO_LINK",
    0x00000080: "SHF_LINK_ORDER",
    0x00000100: "SHF_OS_NONCONFORMING",
    0x00000200: "SHF_GROUP",
    0x00000400: "SHF_TLS",
    0x0FF00000: "SHF_MASKOS",
    0xF0000000: "SHF_MASKPROC",
    0x40000000: "SHF_ORDERED",
    0x80000000: "SHF_EXCLUDE",
}


class ELF64(BinaryFile):
    """Executable and Linkable Format (64-bit addressable)"""

    def __init__(self, path):
        """Initializes local variables and analyze the provided binary file

        Args:
            path (str): file path of the provided binary
        """
        self.path = path
        self.formatDict = None
        self._find_endianess()
        self.Elf64_Ehdr_e_ident = self._read_Elf64_Ehdr_e_ident()
        self.Elf64_Ehdr = self._read_Elf64_Ehdr()
        self.Elf64_Phdr_table = self._read_Elf64_Phdr_table()
        self.Elf64_Shdr_table = self._read_Elf64_Shdr_table()

    def print_file_type(self) -> None:
        """Display the file type of the provided binary file"""
        print(
            f"\n{colors.HEADER}{colors.BOLD}Executable and Linkable Format, 64-bit Addressable (ELF64){colors.ENDC}\n"
        )

    def print_header_info(self) -> None:
        """Prints the header information parsed from the provided binary for the user to view"""

        print(
            f"{colors.BOLD}{colors.OKBLUE}ELF HEADER:{colors.ENDC}\n"
            + f"\te_ident Structure:\t\t\t{self.Elf64_Ehdr['e_ident'].hex(' ')}\n"
            + f"\t\tMagic:\t\t\t\t{self.Elf64_Ehdr_e_ident['EI_MAG'].hex(' ')} ({self.Elf64_Ehdr_e_ident['EI_MAG']})\n"
            + f"\t\tClass (Bitness):\t\t{self.Elf64_Ehdr_e_ident['EI_CLASS'].hex(' ')} ({self.Elf64_Ehdr_e_ident['EI_CLASSName']})\n"
            + f"\t\tType (Endianness):\t\t{self.Elf64_Ehdr_e_ident['EI_DATA'].hex(' ')} ({self.Elf64_Ehdr_e_ident['EI_DATAName']})\n"
            + f"\t\tVersion:\t\t\t{self.Elf64_Ehdr_e_ident['EI_VERSION'].hex(' ')}\n"
            + f"\t\tABI:\t\t\t\t{self.Elf64_Ehdr_e_ident['EI_OSABI'].hex(' ')} ({self.Elf64_Ehdr_e_ident['EI_OSABIName']})\n"
            + f"\t\tABI Version:\t\t\t{self.Elf64_Ehdr_e_ident['EI_ABIVERSION'].hex(' ')}\n"
            + f"\tType:\t\t\t\t\t{hex(self.Elf64_Ehdr['e_type'])} ({self.Elf64_Ehdr['e_typeName']})\n"
            + f"\tMachine:\t\t\t\t{hex(self.Elf64_Ehdr['e_machine'])} ({self.Elf64_Ehdr['e_machineName']})\n"
            + f"\tVersion:\t\t\t\t{self.Elf64_Ehdr['e_version']}\n"
            + f"\tEntry Point:\t\t\t\t{hex(self.Elf64_Ehdr['e_entry'])}\n"
            + f"\tProgram Header Offset:\t\t\t{hex(self.Elf64_Ehdr['e_phoff'])}\n"
            + f"\tSection Header Offset:\t\t\t{hex(self.Elf64_Ehdr['e_shoff'])}\n"
            + f"\tArchitecture Specific Flags:\t\t{hex(self.Elf64_Ehdr['e_flags'])}\n"
            + f"\tELF Header Size:\t\t\t{hex(self.Elf64_Ehdr['e_ehsize'])}\n"
            + f"\tProgram Header Entry Size:\t\t{hex(self.Elf64_Ehdr['e_phentsize'])}\n"
            + f"\tNumber of Program Headers:\t\t{self.Elf64_Ehdr['e_phnum']}\n"
            + f"\tSection Header Entry Size:\t\t{hex(self.Elf64_Ehdr['e_shentsize'])}\n"
            + f"\tNumber of Section Headers:\t\t{self.Elf64_Ehdr['e_shnum']}\n"
            + f"\tSection Name String Table:\t\t{hex(self.Elf64_Ehdr['e_shstrndx'])}\n"
        )
        # Print the data parsed from the program headers
        print(f"{colors.BOLD}{colors.OKBLUE}PROGRAM HEADERS:{colors.ENDC}")
        for idx, Elf64_Phdr in enumerate(self.Elf64_Phdr_table):
            print(
                f"\t{colors.BOLD}{colors.OKCYAN}PROGRAM HEADER [{idx}]:{colors.ENDC}\n"
                + f"\t\tType:\t\t\t\t{hex(Elf64_Phdr['p_type'])} ({Elf64_Phdr['p_typeName']})\n"
                + f"\t\tFlags:\t\t\t\t{hex(Elf64_Phdr['p_flags'])}",
                end="",
            )
            if len(Elf64_Phdr["p_flags_list"]) != 0:
                print(" (", end="")
                for flag in Elf64_Phdr["p_flags_list"]:
                    print(f"{flag}", end="")
            print(
                f")\n\t\tOffset:\t\t\t\t{hex(Elf64_Phdr['p_offset'])}\n"
                + f"\t\tVirtual Address:\t\t{hex(Elf64_Phdr['p_vaddr'])}\n"
                + f"\t\tPhysical Address:\t\t{hex(Elf64_Phdr['p_paddr'])}\n"
                + f"\t\tPhysical Size:\t\t\t{hex(Elf64_Phdr['p_filesz'])}\n"
                + f"\t\tVirtual Size:\t\t\t{hex(Elf64_Phdr['p_memsz'])}\n"
                + f"\t\tAlignment:\t\t\t{hex(Elf64_Phdr['p_align'])}"
            )
        print("\n", end="")

    def print_compressed_header_info(self) -> None:
        """Prints a compressed version of the header information parsed from the provided binary for the user to view"""

        print(
            f"{colors.BOLD}{colors.OKBLUE}ELF HEADER INFORMATION:{colors.ENDC}\n"
            + f"\tClass (Bitness):\t{self.Elf64_Ehdr_e_ident['EI_CLASSName']}\n"
            + f"\tType (Endianness):\t{self.Elf64_Ehdr_e_ident['EI_DATAName']}\n"
            + f"\tFile Type:\t\t{hex(self.Elf64_Ehdr['e_type'])} ({self.Elf64_Ehdr['e_typeName']})\n"
            + f"\tMachine:\t\t{hex(self.Elf64_Ehdr['e_machine'])} ({self.Elf64_Ehdr['e_machineName']})\n"
            + f"\tEntry Point:\t\t{hex(self.Elf64_Ehdr['e_entry'])}\n"
        )
        print(f"{colors.BOLD}{colors.OKBLUE}PROGRAM HEADER INFORMATION:{colors.ENDC}")
        print(
            f"\t|{colors.BOLD}{colors.OKCYAN} [Nr] {colors.ENDC}|"
            + f"{colors.BOLD}{colors.OKCYAN}      Type      {colors.ENDC}|"
            + f"{colors.BOLD}{colors.OKCYAN} Flags {colors.ENDC}|"
            + f"{colors.BOLD}{colors.OKCYAN}   Address (V)   {colors.ENDC}|"
            + f"{colors.BOLD}{colors.OKCYAN}    Size (V)    {colors.ENDC}|"
            + f"{colors.BOLD}{colors.OKCYAN}   Address (P)   {colors.ENDC}|"
            + f"{colors.BOLD}{colors.OKCYAN}    Size (P)    {colors.ENDC}|\n"
            + f"\t-------------------------------------------------------------------------------------------------------"
        )
        for idx, Elf64_Phdr in enumerate(self.Elf64_Phdr_table):
            # Get Program Header Flag Translation
            p_flags_str = ""
            if len(Elf64_Phdr["p_flags_list"]) != 0:
                for flag in Elf64_Phdr["p_flags_list"]:
                    p_flags_str += flag
            print(
                "\t| [{:>2}] |{:^16}|{:^7}|{:^17}|{:^16}|{:^17}|{:^16}|".format(
                    idx,
                    Elf64_Phdr["p_typeName"],
                    p_flags_str,
                    hex(Elf64_Phdr["p_vaddr"]),
                    hex(Elf64_Phdr["p_memsz"]),
                    hex(Elf64_Phdr["p_paddr"]),
                    hex(Elf64_Phdr["p_filesz"]),
                ),
            )
        print("\n", end="")

    def print_section_info(self) -> None:
        """Prints the section header information parsed from the provided binary for the user to view"""

        print(f"{colors.BOLD}{colors.OKBLUE}SECTION HEADERS:{colors.ENDC}")
        for idx, Elf64_Shdr in enumerate(self.Elf64_Shdr_table):
            print(
                f"\t{colors.BOLD}{colors.OKCYAN}SECTION HEADER [{idx}]:{colors.ENDC}\n"
                + f"\t\tSection Name:\t\t\t{Elf64_Shdr['sh_nameStr']} (.shstrtab Index: {hex(Elf64_Shdr['sh_nameIdx'])})\n"
                + f"\t\tType:\t\t\t\t{hex(Elf64_Shdr['sh_type'])} ({Elf64_Shdr['sh_typeName']})\n"
                + f"\t\tFlags:\t\t\t\t{hex(Elf64_Shdr['sh_flags'])}",
                end="",
            )
            if Elf64_Shdr["sh_flags"] != 0:
                print(f" ({', '.join(Elf64_Shdr['sh_flags_list'])})")
            else:
                print(f" (N/A)")
            print(
                f"\t\tVirtual Address:\t\t{hex(Elf64_Shdr['sh_addr'])}\n"
                + f"\t\tPhysical Address:\t\t{hex(Elf64_Shdr['sh_offset'])}\n"
                + f"\t\tPhysical Size:\t\t\t{hex(Elf64_Shdr['sh_size'])}\n"
                + f"\t\tLink:\t\t\t\t{hex(Elf64_Shdr['sh_link'])}\n"
                + f"\t\tInfo (Section Specific):\t{hex(Elf64_Shdr['sh_info'])}\n"
                + f"\t\tAlignment:\t\t\t{hex(Elf64_Shdr['sh_addralign'])}\n"
            )
        print("\n", end="")

    def print_compressed_section_info(self) -> None:
        """Prints a compressed version of the section header information parsed from the provided binary for the user to view"""

        print(f"{colors.BOLD}{colors.OKBLUE}SECTION INFORMATION:{colors.ENDC}")
        print(
            f"\t|{colors.BOLD}{colors.OKCYAN} [Nr] {colors.ENDC}|"
            + f"{colors.BOLD}{colors.OKCYAN}        Name        {colors.ENDC}|"
            + f"{colors.BOLD}{colors.OKCYAN}        Type        {colors.ENDC}|"
            + f"{colors.BOLD}{colors.OKCYAN}     Address     {colors.ENDC}|"
            + f"{colors.BOLD}{colors.OKCYAN}     Offset     {colors.ENDC}|"
            + f"{colors.BOLD}{colors.OKCYAN}      Size      {colors.ENDC}|"
            + f"{colors.BOLD}{colors.OKCYAN}   Flags   {colors.ENDC}|\n"
            + f"\t------------------------------------------------------------------------------------------------------------------"
        )
        for idx, Elf64_Shdr in enumerate(self.Elf64_Shdr_table):
            print(
                "\t| [{:>2}] |{:^20}|{:^20}|{:^17}|{:^16}|{:^16}|{:^11}|".format(
                    idx,
                    Elf64_Shdr["sh_nameStr"],
                    Elf64_Shdr["sh_typeName"],
                    hex(Elf64_Shdr["sh_addr"]),
                    hex(Elf64_Shdr["sh_offset"]),
                    hex(Elf64_Shdr["sh_size"]),
                    hex(Elf64_Shdr["sh_flags"]),
                ),
            )
        print("\n", end="")

    def _find_endianess(self) -> None:
        """ELF files contain a flag in the file header which denotes the endianness of the file"""

        with open(self.path, "rb") as file:
            # Jump past the magic bytes at the beginning of the file header
            file.seek(E_MACHINE_OFFSET, 0)
            (e_machineTag,) = struct.unpack("<b", file.read(1))
            if e_machineTag == 1:
                # The binary is little endian formatted
                self.formatDict = {
                    "Elf64_Half_F": "<H",
                    "Elf64_Half_S": 2,
                    "Elf64_Sword_F": "<l",
                    "Elf64_Sword_S": 4,
                    "Elf64_Word_F": "<L",
                    "Elf64_Word_S": 4,
                    "Elf64_Hashelt_F": "<L",
                    "Elf64_Hashelt_S": 4,
                    "Elf64_Ssize_F": "<q",
                    "Elf64_Ssize_S": 8,
                    "Elf64_Sxword_F": "<q",
                    "Elf64_Sxword_S": 8,
                    "Elf64_Size_F": "<Q",
                    "Elf64_Size_S": 8,
                    "Elf64_Addr_F": "<Q",
                    "Elf64_Addr_S": 8,
                    "Elf64_Off_F": "<Q",
                    "Elf64_Off_S": 8,
                    "Elf64_Lword_F": "<Q",
                    "Elf64_Lword_S": 8,
                    "Elf64_Xword_F": "<Q",
                    "Elf64_Xword_S": 8,
                }
            else:
                # The binary is big endian formatted
                self.formatDict = {
                    "Elf64_Half_F": ">H",
                    "Elf64_Half_S": 2,
                    "Elf64_Sword_F": ">l",
                    "Elf64_Sword_S": 4,
                    "Elf64_Word_F": ">L",
                    "Elf64_Word_S": 4,
                    "Elf64_Hashelt_F": ">L",
                    "Elf64_Hashelt_S": 4,
                    "Elf64_Ssize_F": ">q",
                    "Elf64_Ssize_S": 8,
                    "Elf64_Sxword_F": ">q",
                    "Elf64_Sxword_S": 8,
                    "Elf64_Size_F": ">Q",
                    "Elf64_Size_S": 8,
                    "Elf64_Addr_F": ">Q",
                    "Elf64_Addr_S": 8,
                    "Elf64_Off_F": ">Q",
                    "Elf64_Off_S": 8,
                    "Elf64_Lword_F": ">Q",
                    "Elf64_Lword_S": 8,
                    "Elf64_Xword_F": ">Q",
                    "Elf64_Xword_S": 8,
                }

    def _read_Elf64_Ehdr_e_ident(self) -> dict:
        """Parses information from the e_ident structure in the ELF Header

        Returns:
            dict: a dictionary of data parsed from the e_ident structure (in ELF header)
        """

        e_ident = {}
        with open(self.path, "rb") as file:
            # Read magic characters
            e_ident["EI_MAG"] = file.read(4)
            # Read and translate EI_CLASS
            e_ident["EI_CLASS"] = file.read(1)
            if e_ident["EI_CLASS"] in EI_CLASS_DICT:
                e_ident["EI_CLASSName"] = EI_CLASS_DICT[e_ident["EI_CLASS"]]
            else:
                e_ident[
                    "EI_CLASSName"
                ] = f"{colors.FAIL}{colors.BOLD}ERROR{colors.ENDC}"
            # Read and translate EI_DATA
            e_ident["EI_DATA"] = file.read(1)
            if e_ident["EI_DATA"] in EI_DATA_DICT:
                e_ident["EI_DATAName"] = EI_DATA_DICT[e_ident["EI_DATA"]]
            else:
                e_ident["EI_DATAName"] = f"{colors.FAIL}{colors.BOLD}ERROR{colors.ENDC}"
            # Read EI_VERSION
            e_ident["EI_VERSION"] = file.read(1)
            # Read and translate EI_OSABI
            e_ident["EI_OSABI"] = file.read(1)
            if e_ident["EI_OSABI"] in EI_OSABI_DICT:
                e_ident["EI_OSABIName"] = EI_OSABI_DICT[e_ident["EI_OSABI"]]
            else:
                e_ident[
                    "EI_OSABIName"
                ] = f"{colors.FAIL}{colors.BOLD}ERROR{colors.ENDC}"
            # Read EI_ABIVERSION
            e_ident["EI_ABIVERSION"] = file.read(1)

            return e_ident

    def _read_Elf64_Ehdr(self) -> dict:
        """Parses information from the ELF Header (Elf64_Ehdr structure)

        Returns:
            dict: a dictionary of data parsed from the ELF header
        """
        _Elf64_Ehdr = {}
        with open(self.path, "rb") as file:
            # Jump past the e_ident data structure
            _Elf64_Ehdr["e_ident"] = file.read(E_IDENT_SIZE)

            # Read e_type and translate into name
            (_Elf64_Ehdr["e_type"],) = struct.unpack(
                self.formatDict["Elf64_Half_F"],
                file.read(self.formatDict["Elf64_Half_S"]),
            )
            if _Elf64_Ehdr["e_type"] in E_TYPE_DICT:
                _Elf64_Ehdr["e_typeName"] = E_TYPE_DICT[_Elf64_Ehdr["e_type"]]
            elif _Elf64_Ehdr["e_type"] > ET_LOOS and _Elf64_Ehdr["e_type"] < ET_HIOS:
                _Elf64_Ehdr["e_typeName"] = "OS Specific"
            elif (
                _Elf64_Ehdr["e_type"] > ET_LOPROC and _Elf64_Ehdr["e_type"] < ET_HIPROC
            ):
                _Elf64_Ehdr["e_typeName"] = "Processor Specific"
            else:
                _Elf64_Ehdr[
                    "e_typeName"
                ] = f"{colors.FAIL}{colors.BOLD}ERROR{colors.ENDC}"
            # Read e_machine and translate into name
            (_Elf64_Ehdr["e_machine"],) = struct.unpack(
                self.formatDict["Elf64_Half_F"],
                file.read(self.formatDict["Elf64_Half_S"]),
            )
            if _Elf64_Ehdr["e_machine"] in E_MACHINE_DICT:
                _Elf64_Ehdr["e_machineName"] = E_MACHINE_DICT[_Elf64_Ehdr["e_machine"]]
            else:
                _Elf64_Ehdr[
                    "e_machineName"
                ] = f"{colors.FAIL}{colors.BOLD}ERROR{colors.ENDC}"
            # Read e_version
            (_Elf64_Ehdr["e_version"],) = struct.unpack(
                self.formatDict["Elf64_Word_F"],
                file.read(self.formatDict["Elf64_Word_S"]),
            )
            # Read e_entry
            (_Elf64_Ehdr["e_entry"],) = struct.unpack(
                self.formatDict["Elf64_Addr_F"],
                file.read(self.formatDict["Elf64_Addr_S"]),
            )
            # Read e_phoff
            (_Elf64_Ehdr["e_phoff"],) = struct.unpack(
                self.formatDict["Elf64_Off_F"],
                file.read(self.formatDict["Elf64_Off_S"]),
            )
            # Read e_shoff
            (_Elf64_Ehdr["e_shoff"],) = struct.unpack(
                self.formatDict["Elf64_Off_F"],
                file.read(self.formatDict["Elf64_Off_S"]),
            )
            # Read e_flags
            (_Elf64_Ehdr["e_flags"],) = struct.unpack(
                self.formatDict["Elf64_Word_F"],
                file.read(self.formatDict["Elf64_Word_S"]),
            )
            # Read e_ehsize
            (_Elf64_Ehdr["e_ehsize"],) = struct.unpack(
                self.formatDict["Elf64_Half_F"],
                file.read(self.formatDict["Elf64_Half_S"]),
            )
            # Read e_phentsize
            (_Elf64_Ehdr["e_phentsize"],) = struct.unpack(
                self.formatDict["Elf64_Half_F"],
                file.read(self.formatDict["Elf64_Half_S"]),
            )
            # Read e_phnum
            (_Elf64_Ehdr["e_phnum"],) = struct.unpack(
                self.formatDict["Elf64_Half_F"],
                file.read(self.formatDict["Elf64_Half_S"]),
            )
            # Read e_shentsize
            (_Elf64_Ehdr["e_shentsize"],) = struct.unpack(
                self.formatDict["Elf64_Half_F"],
                file.read(self.formatDict["Elf64_Half_S"]),
            )
            # Read e_shnum
            (_Elf64_Ehdr["e_shnum"],) = struct.unpack(
                self.formatDict["Elf64_Half_F"],
                file.read(self.formatDict["Elf64_Half_S"]),
            )
            # Read e_shstrndx
            (_Elf64_Ehdr["e_shstrndx"],) = struct.unpack(
                self.formatDict["Elf64_Half_F"],
                file.read(self.formatDict["Elf64_Half_S"]),
            )

            return _Elf64_Ehdr

    def _read_Elf64_Phdr_table(self) -> list:
        """Parses information from the Program Headers (Elf64_Phdr structures)

        Returns:
            list: a list of dictionaries of data parsed from the program header
        """
        with open(self.path, "rb") as file:

            # Jump to the beginning of the program header table
            file.seek(self.Elf64_Ehdr["e_ehsize"], 0)

            # Initialize a list to hold parsed data from program header entries
            _Elf64_Phdr_table = []

            # Iterate over the Elf64_Phdr structures
            for _idx in range(self.Elf64_Ehdr["e_phnum"]):
                # Refresh Program Header Entry dictionary
                _Elf64_Phdr = {}
                # Read p_type and translate into name
                (_Elf64_Phdr["p_type"],) = struct.unpack(
                    self.formatDict["Elf64_Word_F"],
                    file.read(self.formatDict["Elf64_Word_S"]),
                )
                if _Elf64_Phdr["p_type"] in E_PHDR_TYPE_DICT:
                    _Elf64_Phdr["p_typeName"] = E_PHDR_TYPE_DICT[_Elf64_Phdr["p_type"]]
                elif (
                    _Elf64_Phdr["p_type"] > PT_LOOS and _Elf64_Phdr["p_type"] < PT_HIOS
                ):
                    _Elf64_Phdr["p_typeName"] = "OS Specific"
                elif (
                    _Elf64_Phdr["p_type"] > PT_LOPROC
                    and _Elf64_Phdr["p_type"] < PT_HIPROC
                ):
                    _Elf64_Phdr["p_typeName"] = "Processor Specific"
                else:
                    _Elf64_Phdr[
                        "p_typeName"
                    ] = f"{colors.FAIL}{colors.BOLD}ERROR{colors.ENDC}"
                # Read p_flags
                (_Elf64_Phdr["p_flags"],) = struct.unpack(
                    self.formatDict["Elf64_Word_F"],
                    file.read(self.formatDict["Elf64_Word_S"]),
                )
                if _Elf64_Phdr["p_flags"] != 0x0:
                    # Initialize a list to store parsed flags
                    _Elf64_Phdr["p_flags_list"] = []
                    # Translate flag values into a list of flags
                    for flag in list(E_PHDR_FLAGS_DICT.keys()):
                        if _Elf64_Phdr["p_flags"] & flag == flag:
                            _Elf64_Phdr["p_flags_list"].append(E_PHDR_FLAGS_DICT[flag])
                # Read p_offset
                (_Elf64_Phdr["p_offset"],) = struct.unpack(
                    self.formatDict["Elf64_Off_F"],
                    file.read(self.formatDict["Elf64_Off_S"]),
                )
                # Read p_vaddr
                (_Elf64_Phdr["p_vaddr"],) = struct.unpack(
                    self.formatDict["Elf64_Addr_F"],
                    file.read(self.formatDict["Elf64_Addr_S"]),
                )
                # Read p_paddr
                (_Elf64_Phdr["p_paddr"],) = struct.unpack(
                    self.formatDict["Elf64_Addr_F"],
                    file.read(self.formatDict["Elf64_Addr_S"]),
                )
                # Read p_filesz
                (_Elf64_Phdr["p_filesz"],) = struct.unpack(
                    self.formatDict["Elf64_Xword_F"],
                    file.read(self.formatDict["Elf64_Xword_S"]),
                )
                # Read p_memsz
                (_Elf64_Phdr["p_memsz"],) = struct.unpack(
                    self.formatDict["Elf64_Xword_F"],
                    file.read(self.formatDict["Elf64_Xword_S"]),
                )
                # Read p_align
                (_Elf64_Phdr["p_align"],) = struct.unpack(
                    self.formatDict["Elf64_Xword_F"],
                    file.read(self.formatDict["Elf64_Xword_S"]),
                )

                # Append the parsed program header to the list
                _Elf64_Phdr_table.append(_Elf64_Phdr)

            return _Elf64_Phdr_table

    def _read_Elf64_Shdr_table(self) -> list:
        """Parses information from the Section Headers (Elf64_Shdr structures)

        Returns:
            list: a list of dictionaries of data parsed from the section header
        """
        # Jump to the beginning of the section header table
        with open(self.path, "rb") as file:
            file.seek(self.Elf64_Ehdr["e_shoff"], 0)

            # Initialize a list to hold the Elf64_Shdr entries
            Elf64_Shdr_table = []

            # Iterate through _IMAGE_SECTION_HEADER entries
            for _idx in range(self.Elf64_Ehdr["e_shnum"]):

                # Refresh the Elf64_Shdr dictionary
                Elf64_Shdr = {}

                # Read sh_name string table index
                (Elf64_Shdr["sh_nameIdx"],) = struct.unpack(
                    self.formatDict["Elf64_Word_F"],
                    file.read(self.formatDict["Elf64_Word_S"]),
                )
                # Read sh_type and translate
                (Elf64_Shdr["sh_type"],) = struct.unpack(
                    self.formatDict["Elf64_Word_F"],
                    file.read(self.formatDict["Elf64_Word_S"]),
                )
                if Elf64_Shdr["sh_type"] in E_SHDR_TYPE_DICT:
                    Elf64_Shdr["sh_typeName"] = E_SHDR_TYPE_DICT[Elf64_Shdr["sh_type"]]
                elif Elf64_Shdr["sh_type"] >= SHT_LOOS:
                    Elf64_Shdr["sh_typeName"] = "OS Specific"
                else:
                    Elf64_Shdr[
                        "sh_typeName"
                    ] = f"{colors.FAIL}{colors.BOLD}ERROR{colors.ENDC}"
                # Read sh_flags and translate
                (Elf64_Shdr["sh_flags"],) = struct.unpack(
                    self.formatDict["Elf64_Xword_F"],
                    file.read(self.formatDict["Elf64_Xword_S"]),
                )
                if Elf64_Shdr["sh_flags"] != 0x0:
                    # Initialize a list to store parsed flags
                    Elf64_Shdr["sh_flags_list"] = []
                    # Translate flag values into a list of flags
                    for flag in list(E_SHDR_FLAGS_DICT.keys()):
                        if Elf64_Shdr["sh_flags"] & flag == flag:
                            Elf64_Shdr["sh_flags_list"].append(E_SHDR_FLAGS_DICT[flag])
                # Read sh_addr
                (Elf64_Shdr["sh_addr"],) = struct.unpack(
                    self.formatDict["Elf64_Addr_F"],
                    file.read(self.formatDict["Elf64_Addr_S"]),
                )
                # Read sh_offset
                (Elf64_Shdr["sh_offset"],) = struct.unpack(
                    self.formatDict["Elf64_Off_F"],
                    file.read(self.formatDict["Elf64_Off_S"]),
                )
                # Read sh_size
                (Elf64_Shdr["sh_size"],) = struct.unpack(
                    self.formatDict["Elf64_Xword_F"],
                    file.read(self.formatDict["Elf64_Xword_S"]),
                )
                # Read sh_link
                (Elf64_Shdr["sh_link"],) = struct.unpack(
                    self.formatDict["Elf64_Word_F"],
                    file.read(self.formatDict["Elf64_Word_S"]),
                )
                # Read sh_info
                (Elf64_Shdr["sh_info"],) = struct.unpack(
                    self.formatDict["Elf64_Word_F"],
                    file.read(self.formatDict["Elf64_Word_S"]),
                )
                # Read sh_addralign
                (Elf64_Shdr["sh_addralign"],) = struct.unpack(
                    self.formatDict["Elf64_Xword_F"],
                    file.read(self.formatDict["Elf64_Xword_S"]),
                )
                # Read sh_entsize
                (Elf64_Shdr["sh_entsize"],) = struct.unpack(
                    self.formatDict["Elf64_Xword_F"],
                    file.read(self.formatDict["Elf64_Xword_S"]),
                )

                # Append the Section Header entry to the list
                Elf64_Shdr_table.append(Elf64_Shdr)

            # Retrieve the file offset of the .shstrtab section
            shstrtab_base = self._read_shstrtab_offset(Elf64_Shdr_table)
            # Translate the .shstrtab name indexes into name strings
            self._convert_shstrtab_idx_to_name(shstrtab_base, Elf64_Shdr_table)

            return Elf64_Shdr_table

    def _read_shstrtab_offset(self, Elf64_Shdr_table) -> int:
        """Retrieves the offset of the .shstrtab section which contains null terminated names of sections

        Args:
            Elf64_Shdr_table (list): a list of dictionaries of data parsed from the section headers

        Returns:
            int: file offset of the .shstrtab section in the file
        """
        # Retrieve the section header entry for .shstrtab
        Elf64_Shdr_shstrtab = Elf64_Shdr_table[self.Elf64_Ehdr["e_shstrndx"]]
        # Return the offset of the retrieved section
        return Elf64_Shdr_shstrtab["sh_offset"]

    def _convert_shstrtab_idx_to_name(self, shstrtab_base, Elf64_Shdr_table) -> None:
        """Converts an index (offset) in the .shstrtab section into the corresponding string

        Args:
            shstrtab_base (int): file offset of the .shstrtab section in the file
            Elf64_Shdr_table (list): a list of dictionaries of data parsed from the section headers
        """

        # Iterate through parsed section headers and convert .shstrtab index to name string
        for Elf64_Shdr in Elf64_Shdr_table:
            # Retrieve the .shstrtab index from Elf64_Shdr
            shstrtab_idx = Elf64_Shdr["sh_nameIdx"]
            # Retrieve name string from .shstrtab section
            Elf64_Shdr["sh_nameStr"] = self._read_string_from_offset(
                shstrtab_base + shstrtab_idx
            )

    def _read_string_from_offset(self, stringOffset) -> str:
        """Parses the null terminated string starting at the provided address

        Args:
            stringOffset (int): file address of string to read

        Returns:
            str: null terminated string parsed from provided address
        """

        with open(self.path, "rb") as file:
            # Jump to provided offset of string
            file.seek(stringOffset)
            # Read character-by-character until null terminator
            parsedString = "".join(iter(lambda: file.read(1).decode("ascii"), "\x00"))
            # Return the parsed string
            return parsedString
