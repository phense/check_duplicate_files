# Readme

## Description

Finds all duplicate files in given directories using a hash-algorithm.

After scanning the file-system for possible duplicate files, all files with a unique
file-size are dismissed. All candidate duplicate files are hashed. Through pre-filtering, this little app is extremely fast on larger file-sets.

- [x] filter out 0-byte files
- [x] multicore hashing
- [x] complete re-write


## Installation

Required dependencies are in the requirements.txt.

Currently, that should only be tqdm. 

The app should probably run with Python 3.4 (untested), but I’d use 3.10 to be on the safe side (mostly because of typing features).


## Usage
```
usage: check_duplicate_files.py [-h] -i PATH [-f FORMAT] -o OUTPUT_FILE

Check duplicate files.

options:
  -h, --help      show this help message and exit
  -i PATH         Input directory
  -f FORMAT       select output format (text (default), json, bash_rm, win_del)
  -o OUTPUT_FILE  output file for found duplicates
```

## NOTES

You can for duplicates between multiple folders and their subfolders:

`check_cuplicate_files.py -i /path/to/folder1 -i /path/to/folder2 ./output.log`

This tool requires a console with UTF-8 support. If you are using the
Windows Command Shell, please set the code-page accordingly via
'chcp 65001'