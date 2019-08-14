import sys
from getopt import getopt, GetoptError
import database

# Upgrade utility for Wazuh HIDS.
# Copyright (C) 2015-2019, Wazuh Inc. <info@wazuh.com>
# June 30, 2016.
# This program is a free software, you can redistribute it
# and/or modify it under the terms of GPLv2.

versions = ['1.0', '1.0.1', '1.0.2', '1.0.3', '1.0.4', '1.1', '1.1.1', '2.0']

def print_help():
    print '''
    Upgrade utility for Wazuh HIDS

    Usage: upgrade.py [-d <inst path>] <old version>

    Copyright 2016 Wazuh, Inc. <info@wazuh.com>
    '''

if __name__ == '__main__':
    old_version = None
    ossec_dir = database._ossec_path

    try:
        opts = getopt(sys.argv[1:], 'd:')
    except GetoptError as error:
        sys.stderr.write("ERROR: {0}.\n".format(error.msg))
        _print_help()
        sys.exit(1)

    for opt in opts[0]:
        if opt[0] == '-d':
            ossec_dir = opt[1]

    if len(opts[1]) < 1:
        sys.stderr.write("ERROR: Version not specified.\n")
        print_help()
        sys.exit(1)

    old_version = opts[1][0][1:] if opts[1][0][0] == 'v' else opts[1][0]

    if old_version not in versions:
        sys.stderr.write("ERROR: Version not supported.\n")
        sys.exit(0)

    dbpath = ossec_dir + '/var/db'

    if versions.index(old_version) < len(versions) - 1:
        print("Upgrading database")

        database.insert_fim(dbpath)
        database.insert_pm(dbpath)
