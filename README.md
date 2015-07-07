README
-----------


# Description

Finds all duplicate files in given directories using a hash-algorithm.

After scanning the filesystem for possible duplicate files (all files with a unique
filesize are dismissed, except for Images when selecting the perceptual hash
algorithm). All candidate duplicate files are hashed. Through pre-filtering,
this module is extremely fast on large file-sets since only a handful of files
need to actually be hashed.

The perceptual hashing algorithm is a difference hashing algorithm which computes
the brightness between adjacent pixels, identifying the relative gradient direction.


# Installation

Use python3's pip to install the dependencies from requirements.txt:

`python3 -m pip install tqdm`
`python3 -m pip install Pillow`


# Usage
```
usage: check_duplicate_files.py [-h] [-i DIR] [--hash HASHTYPE] [-p]
                                [-o OUTFORMAT] [--version]
                                outfile

Check Duplicate Files

positional arguments:
  outfile               output file for found duplicates

optional arguments:
  -h, --help            show this help message and exit
  -i DIR                add directory to list for duplicate search
  --hash HASHTYPE       select hash-type (md5 (default), sha1, sha224, sha256,
                        sha384, sha512)
  -p, --perceptive-hashing
                        enables perceptive hashing of images
  -o OUTFORMAT, --output-format OUTFORMAT
                        select output format (text, json, bash_rm, bash_link,
                        win_del, win_link)
  --version             show program's version number and exit
```

# NOTES

You can for duplicates between multiple folders:

`check_cuplicate_files.py -i /path/to/folder1 -i /path/to/folder2 ./output.log`

This tool requires a console with UTF-8 support. If you are using the
Windows Command Shell, please set the codepage accordingly via
'chcp 65001'