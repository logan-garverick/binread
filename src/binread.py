"""
Description: Main execution point for the BinRead tool. 
"""

import argparse
import errno
from os.path import exists
from sys import exit
from BinaryFileFactory import BinaryFileFactory
from BinaryFile import BinaryFile
from bcolors import *


def configure_parser() -> None:
    """Configures the argparse parser to interpret command line arguments."""

    mutuallyExclusiveGroup = parser.add_mutually_exclusive_group()

    parser.add_argument(
        "BINARY",
        action="store",
        type=str,
        help="path to the binary to analyze",
    )
    mutuallyExclusiveGroup.add_argument(
        "-A",
        dest="ALL_DEFAULT",
        default=False,
        action="store_true",
        help="display full details collected from provided file (extended format) (default)",
    )
    mutuallyExclusiveGroup.add_argument(
        "-a",
        dest="ALL_COMPRESSED",
        default=False,
        action="store_true",
        help="display full details collected from provided file (compressed format)",
    )
    mutuallyExclusiveGroup.add_argument(
        "-S",
        dest="SECTIONS_DEFAULT",
        default=False,
        action="store_true",
        help="display details collected only from the section headers (extended format)",
    )
    mutuallyExclusiveGroup.add_argument(
        "-s",
        dest="SECTIONS_COMPRESSED",
        default=False,
        action="store_true",
        help="display details collected only from the section headers (compressed format)",
    )
    mutuallyExclusiveGroup.add_argument(
        "-F",
        dest="HEADERS_DEFAULT",
        default=False,
        action="store_true",
        help="display details collected only from the file header (extended format)",
    )
    mutuallyExclusiveGroup.add_argument(
        "-f",
        dest="HEADERS_COMPRESSED",
        default=False,
        action="store_true",
        help="display details collected only from the file header (compressed format)",
    )
    mutuallyExclusiveGroup.add_argument(
        "-i",
        dest="FILE",
        default=False,
        action="store_true",
        help="only display details about the file format",
    )


def get_BinaryFile_from_path(path) -> BinaryFile:
    """Verifies that the provided binary exists and retrieves the appropriate BinaryFile instance based on the detected file format

    Args:
        path (str): file path of the provided binary

    Raises:
        FileNotFoundError: raised of the proivided binary file does not exist

    Returns:
        BinaryFile: a BinaryFile instance corresponding to the determined file format
    """

    try:
        # Verify that provided binary exists
        if exists(args.BINARY):

            # Attempt to create a BinaryFile object
            fac = BinaryFileFactory()
            bf = fac.get_BinaryFile_instance(args.BINARY)
            if bf is not None:
                return bf
            else:
                print(
                    f"\t{colors.FAIL}ERROR{colors.ENDC}:Unable to determine binary format. Stopping analysis."
                )
                exit(1)
        else:
            raise FileNotFoundError
    except FileNotFoundError:
        print(f"\t{colors.FAIL}ERROR:{colors.ENDC}{args.BINARY} was not found.")
        exit(1)


def display_file_info(binary) -> None:
    """Outputs information parsed from the provided binary with the requested format

    Args:
        binary (BinaryFile): the BinaryFile instance descriping the provided binary file
    """

    if args.ALL_COMPRESSED:
        binary.print_file_type()
        binary.print_compressed_header_info()
        binary.print_compressed_section_info()
    elif args.SECTIONS_DEFAULT:
        binary.print_file_type()
        binary.print_section_info()
    elif args.SECTIONS_COMPRESSED:
        binary.print_file_type()
        binary.print_compressed_section_info()
    elif args.HEADERS_DEFAULT:
        binary.print_file_type()
        binary.print_header_info()
    elif args.HEADERS_COMPRESSED:
        binary.print_file_type()
        binary.print_compressed_header_info()
    elif args.FILE:
        binary.print_file_type()
    else:
        binary.print_file_type()
        binary.print_header_info()
        binary.print_section_info()


def binread() -> None:
    """Main function of execution for the binread tool"""

    binary = get_BinaryFile_from_path(args.BINARY)
    display_file_info(binary)


if __name__ == "__main__":
    # Initialize parser object
    parser = argparse.ArgumentParser(
        description="Analyze a provided binary file and display information collected from it."
    )
    configure_parser()
    args = parser.parse_args()
    # Begin analysis
    binread()
