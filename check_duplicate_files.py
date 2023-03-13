#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
check_duplicate_files.py

Finds all duplicate files in given directories (and subdirectories) using a hash-algorithm.

Usage: check_duplicate_files.py -i <input_dir> [-f <format>] -o <output_file>
"""

__status__ = "Development Status :: 4 - Beta"
__version__ = "0.9"
__doc__ = "Check duplicate files."

import argparse
import concurrent.futures
import datetime
import json
import os
import signal
import sys
from stat import S_ISREG
from tqdm import tqdm


def main() -> None:
    """Main function"""
    filelist: list[str] = []
    read_errors: list[str] = []
    dict_file_hashes: dict[str, list[str]] = {}
    
    signal.signal(signal.SIGINT, _signalHandler)
    signal.signal(signal.SIGTERM, _signalHandler)
    start_time = datetime.datetime.now()
    
    parser: argparse.ArgumentParser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-i', action = 'append', dest = 'path',
                        type = _validPath, help = 'Input directory', required = True)
    parser.add_argument('-f', action = 'store', dest = 'format', default = 'text',
                        help = 'select output format (text (default), json, bash_rm, win_del)')
    parser.add_argument('-o', action = 'store', dest = 'output_file', required = True, help = 'output file for found duplicates')
    args = parser.parse_args()

    # Scan all directories and subdirectories for files
    filelist, read_errors = scanDirectories(args.path)
    
    print(f"Found {len(filelist)} files that need to be checked for duplicates.\n")
    
    # generate hashes for all files in filelist
    dict_file_hashes = hashingFilesToDict(filelist)
        
    # remove elements from dict_file_hashes that only have one item in the list
    dict_file_hashes = {k: fl for k, fl in dict_file_hashes.items() if len(fl) > 1}
    
    # write output file
    writeOutputFile(dict_file_hashes, args.output_file, args.format)
        
    # print read errors
    if len(read_errors) > 0:
        print(f"\nErrors reading files:")
        for error in read_errors:
            print(f"\n\t{error}")
    
    # print execution time
    end_time = datetime.datetime.now()
    time_diff = end_time - start_time
    minutes, seconds = divmod(time_diff.total_seconds(), 60)
    print(f"\nExecution time: {minutes:.0f}m {seconds:.2f}s")    


def scanDirectories(directories: list[str]) -> tuple[list[str], list[str]]:
    """Scan all directories and subdirectories for files. 
    Returns a list of files that are non-unique in their file-sizes, excluding any
    any 0-byte files, and a list of files that could not be accessed."""
    filelist: list[str] = []
    read_errors: list[str] = []
    dict_file_sizes: dict[int, list[str]] = {}
    
    for directory in directories:
        for path, _, files in os.walk(directory):
            for file in files:
                filename_with_path = os.path.join(path, file)
                try:
                    # access status of file
                    stat_result = os.stat(filename_with_path)
                    # is it a regular file?
                    if S_ISREG(stat_result.st_mode):
                        # determine file size
                        file_size = stat_result.st_size
                        # abort this loop cycle if file is empty
                        if file_size == 0:
                            continue
                        # add file to list of files with same size
                        if file_size in dict_file_sizes:
                            dict_file_sizes[file_size].append(filename_with_path)
                        else:
                            dict_file_sizes[file_size] = [filename_with_path]
                except:
                    read_errors.append(filename_with_path)
      
    # iterate over the dictionary and check if there is more than one element in 
    # the list of files with the same size
    for file_size in dict_file_sizes:
        if len(dict_file_sizes[file_size]) > 1:
            filelist.extend(dict_file_sizes[file_size])
            
    # delete the dictionary to free up memory
    dict_file_sizes.clear()
     
    return filelist, read_errors

    
def hashingFilesToDict(filelist: list[str]) -> dict[str, list[str]]:
    """Generate file hashes from a list of files very fast and appends 
    them to a dictionary using multiprocessing"""
    dict_file_hashes: dict[str, list[str]] = {}
    num_of_cores = os.cpu_count()
    if num_of_cores is None:
        num_of_cores = 1
    # start the process pool executor, which will spawn a new process for each CPU core
    # and run the function _calculate_hash in parallel. Each process will have its own
    # signal handler.
    
    with concurrent.futures.ProcessPoolExecutor(max_workers=num_of_cores, initializer=_passSignalsToAllCores) as executor:
      results = list(tqdm(executor.map(_calculateHash, filelist), total=len(filelist)))
    
    for file, hash in zip(filelist, results):
      if hash in dict_file_hashes:
        dict_file_hashes[hash].append(file)
      else:
        dict_file_hashes[hash] = [file]
    """ old code:
    with concurrent.futures.ProcessPoolExecutor(max_workers=num_of_cores, initializer=_processPoolExecuterInit) as executor:
        for file, hash in zip(filelist, executor.map(_calculateHash, filelist)):
            if hash in dict_file_hashes:
                dict_file_hashes[hash].append(file)
            else:
                dict_file_hashes[hash] = [file]
    """
    return dict_file_hashes

  
def writeOutputFile(dict_file_hashes: dict[str, list[str]], output_file: str, format: str) -> None:
    """Write the output file"""  
    try:
      with open(output_file, 'w') as outfile:
        if format == 'text':
          for key in dict_file_hashes:        
            outfile.write(f"\n\nFiles with hash {key}:")
            for file in dict_file_hashes[key]:
              outfile.writelines(f"\n{file}")
        elif format == 'json':
          json.dump(dict_file_hashes, outfile, indent=4)
        elif format == 'bash_rm':
          for key in dict_file_hashes:
            first_file = True
            for file in dict_file_hashes[key]:
              # skip the first file in the list, because we want to keep at least one file
              if first_file:
                first_file = False
              else:
               outfile.write(f"\nrm \"{file}\"")
        elif format == 'win_del':
          for key in dict_file_hashes:
            first_file = True
            for file in dict_file_hashes[key]:
              # skip the first file in the list, because we want to keep at least one file
              if first_file:
                first_file = False
              else:
                outfile.write(f"\ndel \"{file}\"")
    except:
      print(f"Error writing output file: {output_file}")


def _validPath(prospective_path: str) -> str:
    """Checks if a given string is a valid path on the file-system"""
    if not os.path.isdir(prospective_path):
        raise argparse.ArgumentTypeError('readable_dir:{0} is not a valid path'.format(prospective_path))
    if os.access(prospective_path, os.R_OK):
        return prospective_path
    else:
        raise argparse.ArgumentTypeError('readable_dir:{0} is not a readable path'.format(prospective_path))


def _calculateHash(filename: str) -> str:
    """Calculate hash for a given file"""
    import hashlib
    try:
        with open(filename, 'rb') as file:
            file_hash = hashlib.sha256()
            while chunk := file.read(8192):
                file_hash.update(chunk)
            return file_hash.hexdigest()
    except:
        return ""


def _signalHandler(signal, frame) -> None:
    sys.exit('Aborting...')


def _passSignalsToAllCores() -> None:    
    signal.signal(signal.SIGINT, _signalHandler)    


if __name__ == '__main__':
    main()
