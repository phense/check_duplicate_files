#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Output is utf-8: If you use a windows command shell, please set it correctly
                 using 'chcp 65001'
"""

# TODO(zyrkon): implement multiprocessor for hashing

__author__      = 'Peter Hense (peter.hense@gmail.com)'
__copyright__   = 'Copyright (c) 2015, Peter Hense'
__credits__     = ''        # ['List', 'of', 'programmers']
__status__      = 'Development'     # Prototype / Development / Production
__version__     = '0.5b'


import codecs
import datetime
import hashlib
import operator
import os
import signal
import sys
from argparse import ArgumentParser
from argparse import ArgumentTypeError
from collections import defaultdict
from tqdm import *
from stat import *
try:
    from PIL import Image                   # Pillow (modern PIL fork)
except ImportError:
    IMG_LIB_ERROR = True
else:
    IMG_LIB_ERROR = False


FILEREADERROR = 255


def generate_hashes(d_set_filesize, image_list, hashtype, pHash):
    mark_for_delete = list()
    d_set_hash = defaultdict(set)
    errorlist = list()

    for key in tqdm(d_set_filesize, 'hashing'):
        for file_path in d_set_filesize[key]:
            hash = _hash(file_path, hashtype)
            if hash != FILEREADERROR:
                d_set_hash[hash].add(file_path)
            else:
                errorlist.append(file_path)


    if pHash:            # perceptive image hashing
        d_set_hash_img = defaultdict(set)

        for file_path in tqdm(image_list, 'img hashing:'):
            hash = _perceptive_hash(file_path)
            if hash != FILEREADERROR:
                 d_set_hash_img[hash].add(file_path)
            else:
                errorlist.append(file_path)

        # calculate hamming-distance between all image-hashes to find
        # outliners (hamming distance of two perceptive hashes < 4 means the images
        # are basically the same)
        index_list = [key for key in d_set_hash_img]
        deleted_index_keys = []

        for hash1 in tqdm(index_list, 'calculating'):
            if hash1 in deleted_index_keys:
                continue

            for hash2 in index_list:
                if hash1 == hash2:
                    continue            # same entry in list
                if hash2 in deleted_index_keys:
                    continue

                if _hamming_distance(hash1, hash2) < 4:
                    d_set_hash_img[hash1].update(d_set_hash_img[hash2])
                    del d_set_hash_img[hash2]
                    deleted_index_keys.append(hash2)

    # Cleanup
    d_set_filesize.clear()
    _delete_unique_entries(d_set_hash)

    if pHash:
        _delete_unique_entries(d_set_hash_img)
        d_set_hash.update(d_set_hash_img)

    return d_set_hash, errorlist


def _perceptive_hash(file_path, hash_size = 8):
    # if memory consumption is to high for many images, it is posisble to use
    # with open (file_path, 'rb') as f:
    #   image = Image.open(f)
    #   ...
    #   del image
    try:
        image = Image.open(file_path)
    except:
        return FILEREADERROR

    # Grayscale and shrink the image in one step
    image = image.convert('L').resize((hash_size + 1, hash_size), Image.ANTIALIAS)
    pixels = list(image.getdata())

    # Compage adjacent pixels
    difference = []
    for row in range(hash_size):
        for col in range(hash_size):
            pixel_left = image.getpixel((col, row))
            pixel_right = image.getpixel((col +1, row))
            difference.append(pixel_left > pixel_right)

    # Convert binary array to hexadecimal string
    decimal_value = 0
    hex_string = []
    for index, value in enumerate(difference):
        if value:
            decimal_value += 2**(index % 8)
        if (index % 8) == 7:
            hex_string.append(hex(decimal_value)[2:].rjust(2, '0'))
            decimal_value = 0

    return ''.join(hex_string)


def _hash(file_path, hashtype):
    try:
        with open(file_path, 'rb') as f:
            contents = f.read()
    except:
        return FILEREADERROR
    hasher = getattr(hashlib, hashtype.lower(), hashlib.md5)
    return hasher(contents).hexdigest()


def _hamming_distance(string1, string2):
    assert len(string1) == len(string2)
    ne = operator.ne        # faster than '!=' and 'str.__ne__'
    return sum(map(ne, string1, string2))


def scan_directories(directories, pHash):
    extensions = ('.jpg', '.jpeg', '.png', '.bmp')
    d_set_filesize = defaultdict(set)
    images = list()
    errorlist = list()
    count = 0

    print('Scanning directories...')

    # code could be a lot smaller with `if pHash` inside the innermost loop
    # obviously, it would also be much slower

    if not pHash:        # use normal hash on all files
        for root_dir in directories:
            for path, subdirList, fileList in os.walk(root_dir):
                for fname in fileList:
                    qualified_filename = os.path.join(path, fname)
                    try:            # denied permission for os.stat
                        st = os.stat(qualified_filename)
                        if S_ISREG(st.st_mode):
                            d_set_filesize[st.st_size].add(qualified_filename)
                            count += 1
                    except:
                        errorlist.append(qualified_filename)
                        count += 1
    else:       # split list of normal- and image-files
        for root_dir in directories:
            for path, subdirList, fileList in os.walk(root_dir):
                for fname in fileList:
                    qualified_filename = os.path.join(path, fname)
                    if fname.endswith(extensions):
                        images.append(qualified_filename)
                        count += 1
                    else:
                        try:
                            st = os.stat(qualified_filename)
                            if S_ISREG(st.st_mode):
                                d_set_filesize[st.st_size].add(qualified_filename)
                                count += 1
                        except:
                            errorlist.append(qualified_filename)
                            count += 1

    # Statistic
    print('\nFiles found: %s' % count)

    # delete all files with unique filesize
    _delete_unique_entries(d_set_filesize)

    # Statistic
    count = 0
    for key in d_set_filesize:
        count += d_set_filesize[key].__len__()

    # at this point, all images are possible canidates
    count += images.__len__()
    print('Possible candidates: %s\n' % count)
    return d_set_filesize, images, errorlist


def _delete_unique_entries(dictionary):
    mark_for_delete = list()

    for key in dictionary:
        if dictionary[key].__len__() == 1:
            mark_for_delete.append(key)

    for i in mark_for_delete:
        del dictionary[i]

    return


def write_output(d_set_hash, outfile, exec_time, errorlist):
    write_errorlist = list()

    try:
        with codecs.open(outfile, 'w', encoding='utf-8') as f:
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
            print('Hash: %s' % key)
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
    sys.exit('Aborting...')


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

    parser.add_argument('--disable-pHash', action = 'store_true', dest = 'no_pHash',
                        default = False,
                        help = 'disables perceptive hashing of images')

    parser.add_argument('outfile', nargs='?',
                        help = 'output file for found duplicates')

    parser.add_argument('--version', action='version',
                        version='%(prog)s {version}'.format(version=__version__))

    args = parser.parse_args()

    # disable perceptive hashing (normal hashes on all files) when PIL LIB could
    # not be loaded or the flag is manually set
    pHash = not (IMG_LIB_ERROR or args.no_pHash)

    if not pHash:
        print('(Perceptive Image Scan disabled)')

    # Scan all directories and find duplicates by filesize
    d_set_filesize, images, read_errors = scan_directories(args.dir, pHash)

    # Ask the user if he wants to continue, now that he knows how
    # many files need to be hashed. Exclude the query-time from
    # execution time
    time_query = datetime.datetime.now()
    if not _query_yes_no('Do you want to continue?', 'yes'):
        sys.exit(0)
    timedelta_query = datetime.datetime.now() - time_query     # timedelta

    # generate the hashed and calculate the execution time
    # append possible new read-errors to the general error-list
    d_set_hash, read_errors2 = generate_hashes(d_set_filesize, images, args.hashtype, pHash)
    read_errors.extend(read_errors2)

    execution_time = datetime.datetime.now() - start_time       # timedelta
    execution_time -= timedelta_query                           # timedelta

    # write output to file/console
    write_output(d_set_hash, args.outfile, execution_time, read_errors)

    # done
    sys.exit(0)


if __name__ == '__main__':
    main()