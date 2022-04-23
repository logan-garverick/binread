#! /bin/bash

# Install required python modules
pip3 install -r requirements.txt

# Run PyInstaller to create 
pyinstaller -F --clean --paths src/ --distpath ./ src/binread.py
rm -r ./build
rm binread.spec