#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
import logging
import argparse

sys.path.insert(0, os.path.abspath('..'))
from wazuh.cluster import internal_socket

if __name__ == '__main__':
    # Parse args
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', help="Enable debug messages", action='store_true')
    parser.add_argument('-n', help="Number of MB to transfer", type=int, required=True)
    args = parser.parse_args()

    logger = logging.getLogger(__name__)
    logging.basicConfig(level=logging.INFO)

    response = internal_socket.execute('transfertest {}'.format(args.n))
    print(response)
