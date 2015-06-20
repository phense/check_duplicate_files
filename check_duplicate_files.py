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
import datetime
import hashlib
import os
import signal
import sys
from argparse import ArgumentParser
from argparse import ArgumentTypeError
from collections import defaultdict
from stat import *


FILEREADERROR = 255


def generate_hashes(d_set_filesize, hashtype):
    mark_for_delete = list()
    d_set_hash = defaultdict(set)
    errorlist = list()

    print('Creating filehashes...\n')
    for key in d_set_filesize:
        for file_path in d_set_filesize[key]:
            hash = _hash(file_path, hashtype)
            if hash != FILEREADERROR:
                d_set_hash[hash].add(file_path)
            else:
                errorlist.append(file_path)

    # Cleanup
    d_set_filesize.clear()

    for key in d_set_hash:
        if d_set_hash[key].__len__() == 1:
            mark_for_delete.append(key)

    for i in mark_for_delete:
        del d_set_hash[i]

    return d_set_hash, errorlist


def scan_directories(directories, d_set_filesize, pHash):
    extensions = ('.jpg', 'jpeg', '.png', '.bmp')
    mark_for_delete = list()
    errorlist = list()
    count = 0

    print('Scanning directories...')

    for root_dir in directories:
        for path, subdirList, fileList in os.walk(root_dir):
            for fname in fileList:
                qualified_filename = os.path.join(path, fname)
                try:            # possible denied permission for os.stat
                    st = os.stat(qualified_filename)
                    if S_ISREG(st.st_mode):
                        d_set_filesize[st.st_size].add(qualified_filename)
                        count += 1
                except:
                    errorlist.append(qualified_filename)

    # Statistic
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

    return errorlist


def write_output(d_set_hash, outfile, exec_time, errorlist):
    write_errorlist = list()

    try:
        with codecs.open(outfile, 'w', encoding="utf-8") as f:
            f.write('\nThe Following File-Duplicates where found:')
            f.write('\n==========================================\n')
            for key in d_set_hash:
                f.write('Hash: %s\n' %key)
                for file_path in d_set_hash[key]:
                    try:
                        f.write('%s \n' % file_path)
                    except:
                        write_errorlist.append(file_path)
                f.write('-------------------\n')

            if errorlist.__len__() > 0:
                f.write('\nThe Following Files could not be accessed:')
                f.write('\n==========================================\n')
                for error in errorlist:
                    try:
                        f.write('%s\n' % error)
                    except:
                        write_errorlist.append(error)

            f.flush()
            f.write('\nExecution Time: %s.%s seconds' % (exec_time.seconds, exec_time.microseconds))

    except:                 #IOError, UnicodeEncodeError
        print('- Error - Could not open Output File.\n')
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
                print('%s' % error)

    if write_errorlist.__len__() > 0:
        print('- Error - These files could not be written to output file:\n')
        for write_error in write_errorlist:
            print('%s\n' % write_error)
        print('(Please check your filesystem encoding)\n')

    print('Execution Time: %s.%s seconds' % (exec_time.seconds, exec_time.microseconds))
    return


def _hash (file_path, hashtype):
    print('hashing: %s' % file_path)
    try:
        digest = open(file_path, 'rb').read()

        if hashtype.lower() == 'sha1':
            return hashlib.sha1(digest).hexdigest()
        elif hashtype.lower() == 'sha224':
            return hashlib.sha224(digest).hexdigest()
        elif hashtype.lower() == 'sha256':
            return hashlib.sha256(digest).hexdigest()
        elif hashtype.lower() == 'sha384':
            return hashlib.sha384(digest).hexdigest()
        elif hashtype.lower() == 'sha512':
            return hashlib.sha512(digest).hexdigest()
        else:
            return hashlib.md5(digest).hexdigest()
    except:
        return FILEREADERROR


def _query_yes_no(question, default="yes"):
    valid = {"yes": True, "y": True, "ye": True,
             "no": False, "n": False}
    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        sys.stdout.write(question + prompt)
        choice = input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' "
                             "(or 'y' or 'n').\n")


def _signal_handler(signal, frame):
    sys.exit(1)


def _readable_dir(prospective_dir):
    if not os.path.isdir(prospective_dir):
        raise ArgumentTypeError("readable_dir:{0} is not a valid path".format(prospective_dir))
    if os.access(prospective_dir, os.R_OK):
        return prospective_dir
    else:
        raise ArgumentTypeError("readable_dir:{0} is not a readable dir".format(prospective_dir))


def main():
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)
    start_time = datetime.datetime.now()

    d_set_filesize = defaultdict(set)
    d_set_hash = defaultdict(set)

    parser = ArgumentParser(description = 'Dublicate Checker')
    parser.add_argument('-i', action = 'append', dest = 'dir',
                        type = _readable_dir,
                        help = 'add directory to list for duplicate search')

    parser.add_argument('--hash', action = 'store', dest = 'hashtype',
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
    read_errors = scan_directories(args.dir, d_set_filesize, args.pHash)

    time_query = datetime.datetime.now()
    if not _query_yes_no('Do you want to continue?', 'yes'):
        sys.exit(0)
    timedelta_query = datetime.datetime.now() - time_query     # timedelta

    d_set_hash, read_errors2 = generate_hashes(d_set_filesize, args.hashtype)
    read_errors.extend(read_errors2)

    execution_time = datetime.datetime.now() - start_time         #timedelta
    execution_time -= timedelta_query

    write_output(d_set_hash, args.outfile, execution_time, read_errors)
    sys.exit(0)


if __name__ == '__main__':
    main()