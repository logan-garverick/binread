"""
Description: Main execution point for the BinRead tool. 
"""

import argparse
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


def binread() -> None:
    pass


if __name__ == "__main__":
    # Initialize parser object
    parser = argparse.ArgumentParser(
        description="Analyze a provided binary file and display information collected from it."
    )
    configure_parser()
    args = parser.parse_args()
    # Begin analysis
    binread()
