#!/usr/bin/env python
# Copyright (C) 2015-2019, Wazuh Inc.
# July 23, 2017

from sys import argv, stderr, exit
from tempfile import mkstemp
from os import makedirs, remove, close
from os.path import dirname
from errno import EEXIST
import gzip
from shutil import copyfileobj
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature

MAGIC = b'WPK256\0'
HASH = hashes.SHA256()
PADDING = padding.PKCS1v15()
SIGLEN = 2048 // 8
BUFLEN = 4096


class FormatError(Exception):
    pass


def unsign(source, target):
    hasher = hashes.Hash(HASH, default_backend())

    with open(source, 'rb') as filein:
        if filein.read(len(MAGIC)) != MAGIC:
            raise FormatError

        strcert = filein.read(1)

        while strcert[-1] != b'\0':
            strcert += filein.read(1)

        cert = x509.load_pem_x509_certificate(strcert, default_backend())
        signature = filein.read(SIGLEN)

        if len(signature) < SIGLEN:
            raise FormatError

        pos = filein.tell()
        buf = filein.read(BUFLEN)

        while buf:
            hasher.update(buf)
            buf = filein.read(BUFLEN)

        digest = hasher.finalize()
        cert.public_key().verify(signature, digest, PADDING, utils.Prehashed(HASH))
        filein.seek(pos)

        with open(target, 'wb') as fileout:
            copyfileobj(filein, fileout)


def uncompress(source, target):
    with gzip.open(source, 'rb') as fin:
        with open(target, 'wb') as fout:
            copyfileobj(fin, fout)


def unmerge(source, target):
    with open(source, 'rb') as filein:
        head = filein.readline().decode()

        while head:
            if head[0] != '!':
                head = filein.readline().decode()
                continue

            size, path = head[1:-1].split(' ', 1)
            size = int(size)
            path = '{0}/{1}'.format(target, path)

            try:
                makedirs(dirname(path))
            except OSError as error:
                if error.errno != EEXIST:
                    raise error

            with open(path, 'wb') as fileout:
                while size:
                    n = size if size < BUFLEN else BUFLEN
                    fileout.write(filein.read(n))
                    size -= n

            head = filein.readline().decode()


if __name__ == '__main__':
    if len(argv) < 3:
        stderr.write('Syntax: {0} <wpk> <dest>\n'.format(argv[0]))
        exit(1)

    pack = argv[1]
    dest = argv[2]
    force = False
    pubkey = None

    fd, zipped = mkstemp()
    close(fd)

    try:
        unsign(pack, zipped)
    except InvalidSignature as error:
        if force:
            stderr.write('WARN: Invalid public key. Forcing...\n')
            unsign(pack, zipped)
        else:
            raise error
    except Exception as error:
        remove(zipped)
        raise error

    fd, merged = mkstemp()
    close(fd)
    uncompress(zipped, merged)
    remove(zipped)

    try:
        unmerge(merged, dest)
    finally:
        remove(merged)
