![Logo](/images/logo_dark.jpg#gh-dark-mode-only)

# binread <!-- omit in toc -->

- [Description](#description)
- [Installation from Source](#installation-from-source)
- [Usage](#usage)
- [Examples](#examples)

## Description
Binary analyzer used to parse information from a provided executable binary file.

## Installation from Source
To build a single binary file of the Binread tool using PyInstaller, follow these steps:
1. Clone the repository.
   ```
   git clone https://github.com/logan-garverick/binread.git
   ```
2. Ensure that your system is up-to-date.
   ```
   sudo apt-get -y update && sudo apt-get -y upgrade
   ```
3. Install Python3 package installer (pip).
   ```
   sudo apt install python3-pip
   ```
4. Install PyInstaller.
   ```
   sudo pip3 install --upgrade --force-reinstall pyinstaller
   ```
5. Run the `build.sh` bash script.
   ```
   ./build.sh
   ```
6. The `binread` binary is now found in the parent directory of the project folder.

## Usage
Optional commands for the binread tool can be seen below:
```
  -h, --help  show this help message and exit
  -A          display full details collected from provided file (extended format) (default)
  -a          display full details collected from provided file (compressed format)
  -S          display details collected only from the section headers (extended format)
  -s          display details collected only from the section headers (compressed format)
  -F          display details collected only from the file header (extended format)
  -f          display details collected only from the file header (compressed format)
  -i          only display details about the file format
```

## Examples
1. Find the file format of a binary file:
   ```
   binread -i [FILE]
   ```
2. Display all information parsed from a binary file:
   ```
   binread [FILE]

   binread -A [FILE]
   ``` 
3. Display only section information in the compact layout:
   ```
   binread -s [FILE]
   ```