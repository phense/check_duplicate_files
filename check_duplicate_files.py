#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Output is utf-8: If you use a windows command shell, please set it correctly
                 using 'chcp 65001'
"""

#TODO(zyrkon): implement perceptive hashing

__author__      = 'Peter Hense (peter.hense@gmail.com)'
__copyright__   = 'Copyright (c) 2015, Peter Hense'
__credits__     = ''        # ['List', 'of', 'programmers']
__status__      = 'Development'     # Prototype / Development / Production
__version__     = '0.5b'

import codecs
import hashlib
import os
import signal
import sys
from argparse import ArgumentParser
from argparse import ArgumentTypeError
from collections import defaultdict
from stat import *
from time import time


def generate_hashes(d_set_filesize, hash):
    mark_for_delete = []
    d_set_hash = defaultdict(set)
    errorlist = set()

    print('Creating filehashes...\n')
    for key in d_set_filesize:
        for file_path in d_set_filesize[key]:
            _hash(file_path, d_set_hash, hash, errorlist)

    # Cleanup
    d_set_filesize.clear()

    for key in d_set_hash:
        if d_set_hash[key].__len__() == 1:
            mark_for_delete.append(key)

    for i in mark_for_delete:
        del d_set_hash[i]

    return d_set_hash, errorlist


def _hash (file_path, d_set_hash, hash, errorlist):
    print('hashing: %s' % file_path)
    try:
        digest = open(file_path, 'rb').read()

        if hash.lower() == 'sha1':
            digest = hashlib.sha1(digest).hexdigest()
        elif hash.lower() == 'sha224':
            digest = hashlib.sha224(digest).hexdigest()
        elif hash.lower() == 'sha256':
            digest = hashlib.sha256(digest).hexdigest()
        elif hash.lower() == 'sha384':
            digest = hashlib.sha384(digest).hexdigest()
        elif hash.lower() == 'sha512':
            digest = hashlib.sha512(digest).hexdigest()
        else:
            digest = hashlib.md5(digest).hexdigest()

        d_set_hash[digest].add(file_path)
    except:
        errorlist.add(file_path)
    return


def scan_directories(directories, d_set_filesize, pHash):
    extensions = ('.jpg', 'jpeg', '.png', '.bmp')
    mark_for_delete = []

    print('Scanning directories...')

    for root_dir in directories:
        for path, subdirList, fileList in os.walk(root_dir):
            for fname in fileList:
                qualified_filename = os.path.join(path, fname)
                try:            # possible denied permission for os.stat
                    st = os.stat(qualified_filename)
                    if S_ISREG(st.st_mode):
                        d_set_filesize[st.st_size].add(qualified_filename)
                except:
                    pass

    # Statistic
    count = 0
    for key in d_set_filesize:
        count += d_set_filesize[key].__len__()
    print('\nFiles found: %s' % count)

    # Cleanup (delete all files with unique silesize)
    for key in d_set_filesize:
        if d_set_filesize[key].__len__() == 1:
            mark_for_delete.append(key)

    for i in mark_for_delete:
        del d_set_filesize[i]

    # Statistic
    count = 0
    for key in d_set_filesize:
        count += d_set_filesize[key].__len__()
    print('Possible candidates: %s\n' % count)

    return


def write_output(d_set_hash, outfile, start_time, errorlist):
    end_time = round(time() - start_time, 2)
    try:
        with codecs.open(outfile, 'a', encoding="utf-8-sig") as f:
            f.write('\nThe Following File-Duplicates where found:')
            f.write('\n==========================================\n')
            for key in d_set_hash:
                f.write('Hash: %s\n' %key)
                for file_path in d_set_hash[key]:
                    f.write('%s \n' % file_path)
                f.write('-------------------\n')
            if errorlist.__len__() > 0:
                f.write('\nThe Following Files could not be accessed:')
                f.write('\n==========================================\n')
                for error in errorlist:
                    f.write('%s\n' % error)
            f.write('\nExecution Time: %s seconds' % end_time)

    except:                 #IOError, UnicodeEncodeError
        print('Error: Could not open Output File.\n')
        print('The Following File-Duplicates where found:')
        print('==========================================\n')
        for key in d_set_hash:
            for file_paths in d_set_hash[key]:
                print(file_paths)
            print('--------------------')
        if errorlist.__len__() > 0:
            print('\nThe Following Files could not be accessed:')
            print('==========================================\n')
            for error in errorlist:
                print('%s\n' % error)
    print('\nExecution Time: %s seconds' % end_time)
    return


def signal_handler(signal, frame):
    sys.exit(1)


def readable_dir(prospective_dir):
    if not os.path.isdir(prospective_dir):
        raise ArgumentTypeError("readable_dir:{0} is not a valid path".format(prospective_dir))
    if os.access(prospective_dir, os.R_OK):
        return prospective_dir
    else:
        raise ArgumentTypeError("readable_dir:{0} is not a readable dir".format(prospective_dir))


def main():
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    start_time = time()

    d_set_filesize = defaultdict(set)
    d_set_hash = defaultdict(set)
    errorlist = set()

    parser = ArgumentParser(description = 'Dublicate Checker')
    parser.add_argument('-i', action = 'append', dest = 'dir',
                        type = readable_dir,
                        help = 'add directory to list for duplicate search')

    parser.add_argument('--hash', action = 'store', dest = 'hash',
                        default = 'md5',
                        help = 'select hash-type (md5 (default), sha1, sha224, sha256, sha384, sha512)')

    parser.add_argument('--disable-pHash', action = 'store', dest = 'pHash',
                        default = False,
                        help = 'disables perceptive hashing on images')

    parser.add_argument('outfile', nargs='?',
                        help = 'output file for found duplicates')

    parser.add_argument('--version', action='version',
                        version='%(prog)s {version}'.format(version=__version__))

    args = parser.parse_args()
    scan_directories(args.dir, d_set_filesize, args.pHash)
    d_set_hash, errorlist = generate_hashes(d_set_filesize, args.hash)
    write_output(d_set_hash, args.outfile, start_time, errorlist)


if __name__ == '__main__':
    main()