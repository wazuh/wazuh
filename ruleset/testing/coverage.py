#!/usr/bin/env python
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation

import argparse
import re
import errno
from os import path as Path
from os import strerror
from os import listdir


def check_dir(path):
    """
    Check if given path is a directory.

    Parameters
    ----------
    path : str
        The path to be checked.

    Raises
    ------
    FileNotFoundError
        If path doesn't exists.

    NotADirectoryError
        If path is not a directory.
    """
    if not Path.exists(path):
        raise FileNotFoundError(errno.ENOENT, strerror(errno.ENOENT), path)

    if not Path.isdir(path):
        raise NotADirectoryError(errno.ENOTDIR, strerror(errno.ENOTDIR), path)


def get_rule_ids(rules_path):
    """
    Get a set with all rule ids found on given directory path.

    Parameters
    ----------
    rulesPath : str
        Path of the directory with rule files.

    Returns
    -------
    set
        Set with all rule ids found. Empty set if none found.

    Raises
    ------
    FileNotFoundError
        If path doesn't exists.

    NotADirectoryError
        If path is not a directory.
    """
    check_dir(rules_path)

    rule_set = set()

    rule_start_pattern = re.compile(r'^\s*<rule\sid="(\d+)"', re.MULTILINE)

    for filename in listdir(rules_path):
        if Path.isfile(rules_path + filename):
            with open(rules_path + filename, 'r') as rule_file:
                rule_set.update({match for match in re.findall(rule_start_pattern, rule_file.read())})

    return rule_set


def get_parent_decoder_names(decoders_path):
    """
    Get a set with all parent decoder names found on given directory path.

    Parameters
    ----------
    decodersPath : str
        Path of the directory with decoder files.

    Returns
    -------
    set
        Set with all parent decoder names found. Empty set if none found.

    Raises
    ------
    FileNotFoundError
        If path doesn't exists.

    NotADirectoryError
        If path is not a directory.
    """
    check_dir(decoders_path)

    decoder_set = set()
    decoder_start_pattern = re.compile(r'^\s*<decoder\sname="(.+)">')
    decoder_end_pattern = re.compile(r'^\s*</decoder>')
    parent_decoder_pattern = re.compile(r'^\s*<parent>')

    for filename in listdir(decoders_path):
        if Path.isfile(decoders_path + filename):
            with open(decoders_path + filename, 'r') as decoder_file:
                inside_decoder = False
                parent_found = False
                decoder_name = None
                for line in decoder_file:
                    if not inside_decoder:
                        decoder_name = re.match(decoder_start_pattern, line)
                        if decoder_name:
                            inside_decoder = True
                            decoder_name = decoder_name.group(1)
                    elif not parent_found and re.match(parent_decoder_pattern, line):
                        parent_found = True
                    elif re.match(decoder_end_pattern, line):
                        if not parent_found:
                            decoder_set.add(decoder_name)
                        else:
                            parent_found = False

                        inside_decoder = False

    return decoder_set
