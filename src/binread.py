"""
Description: Main execution point for the BinRead tool. 
"""

import argparse
from os.path import exists
from BinaryFileFactory import BinaryFileFactory
from BinaryFile import BinaryFile
from bcolors import *


def configure_parser() -> None:
    """Configures the argparse parser to interpret command line arguments."""

    parser.add_argument(
        "BINARY",
        action="store",
        type=str,
        help="path to the binary to analyze",
    )
    parser.add_argument(
        "-a",
        "--all",
        dest="ALL",
        default=False,
        action="store_true",
        help="display full details collected from provided file",
    )
    parser.add_argument(
        "-s",
        "--sections-only",
        dest="SECTION",
        default=False,
        action="store_true",
        help="display details collected only from the section headers",
    )
    parser.add_argument(
        "-f",
        "--file-only",
        dest="FILE",
        default=False,
        action="store_true",
        help="display details collected only from the file header",
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
        print(f"\t{colors.FAIL}ERROR:{colors.ENDC}{args.binary} was not found.")
        exit(1)


def binread() -> None:
    """Main function of execution for the binread tool"""

    binary = get_BinaryFile_from_path(args.BINARY)
    print(f"DEBUG: type(binary) --> {type(binary)}\n")


if __name__ == "__main__":
    # Initialize parser object
    parser = argparse.ArgumentParser(
        description="Analyze a provided binary file and display information collected from it."
    )
    configure_parser()
    args = parser.parse_args()
    # Begin analysis
    binread()
