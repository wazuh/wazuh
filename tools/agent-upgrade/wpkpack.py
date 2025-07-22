#!/usr/bin/env python
# Tool to build and compress the WPK package
# Wazuh package generator
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Import required modules for file handling, compression, cryptography, and path operations
from io import SEEK_SET, SEEK_END
from sys import argv, stderr, exit
from tempfile import mkstemp
from os import listdir, remove, close
from os.path import isfile, isdir
import gzip
from shutil import copyfileobj
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.hazmat.primitives import serialization, hashes

# Define constants for package magic bytes, hashing algorithm, padding scheme, and buffer size
MAGIC = b'WPK256\0'
HASH = hashes.SHA256()
PADDING = padding.PKCS1v15()
BUFLEN = 4096

# Create a new merged file and optionally write a tag as the first line
def mergecreate(path, tag = None):
    with open(path, 'w') as f:
        if tag:
            f.write('#{0}\n'.format(tag))

# Append the contents of each source file to the merged file in binary mode
def mergeappend(merged, sources):
    with open(merged, 'ab') as f:
        for s in sources:
            _mergeappend(f, s)

# Recursively append file contents or directory contents to the merged file, adding headers with size and path
def _mergeappend(fm, source):
    if isfile(source):
        with open(source, 'rb') as fs:
            fs.seek(0, SEEK_END)
            size = fs.tell()
            fs.seek(0, SEEK_SET)
            fm.write('!{0} {1}\n'.format(size, source).encode())
            copyfileobj(fs, fm)
    elif isdir(source):
        for d in listdir(source):
            _mergeappend(fm, '{0}/{1}'.format(source, d))
    else:
        raise Exception

# Compress the source file into the target file using gzip
def compress(source, target):
    with open(source, 'rb') as fin:
        with gzip.open(target, 'wb') as fout:
            copyfileobj(fin, fout)

# Digitally sign the source file and write output to target with cert and signature
def sign(source_path, target_path, cert_path, priv_path):
    hasher = hashes.Hash(HASH, default_backend())

    # Load the public certificate for verification
    with open(priv_path, 'rb') as fkey:
        key = serialization.load_pem_private_key(fkey.read(), password=None, backend=default_backend())

    # Read the source file in chunks, update the hash, and prepare to sign it
    with open(source_path, 'rb') as filein:
        buf = filein.read(BUFLEN)

        # Update the hash with the file content
        while buf:
            hasher.update(buf)
            buf = filein.read(BUFLEN)

        # Finalize the hash and sign it with the private key
        digest = hasher.finalize()
        signature = key.sign(digest, PADDING, utils.Prehashed(HASH))

        # Write the WPK magic, certificate, and signature to the target file
        with open(target_path, 'wb') as fileout:
            fileout.write(MAGIC)

            with open(cert_path, 'rb') as filecert:
                copyfileobj(filecert, fileout)

            fileout.write(b'\0' + signature)
            filein.seek(0, SEEK_SET)
            copyfileobj(filein, fileout)

# Main function to create a WPK package by merging, compressing, and signing files
if __name__ == '__main__':
    if len(argv) < 4:
        stderr.write('Syntax: {0} <pack> <cert> <key> <content> [ <content> ... ]\n'.format(argv[0]))
        exit(1)

    # Check if the specified pack file already exists
    pack = argv[1]
    fd, merged = mkstemp()
    close(fd)

    # Create the merged file with an optional tag
    try:
        mergecreate(merged, pack)
        mergeappend(merged, argv[4:])
    except Exception as error:
        remove(merged)
        raise error

    # Compress the merged file into a temporary zipped file
    fd, zipped = mkstemp()
    close(fd)
    compress(merged, zipped)
    remove(merged)

    # Sign the compressed file and write the final WPK package
    try:
        sign(zipped, pack, argv[2], argv[3])
    finally:
        remove(zipped)
