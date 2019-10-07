#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute
# it and/or modify it under the terms of GPLv2

"""Framework tests for Mitre module."""

import os
from sqlite3 import connect

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

json_keys = ['external_references', 'object_marking_refs',
             'x_mitre_contributors', 'x_mitre_data_sources', 'modified',
             'x_mitre_detection', 'created_by_ref', 'x_mitre_platforms',
             'kill_chain_phases', 'x_mitre_defense_bypassed', 'description'
             'id', 'name', 'created', 'x_mitre_version',
             'x_mitre_remote_support', 'type', 'x_mitre_permissions_required',
             'x_mitre_system_requirements']


def get_fake_mitre_db(sql_file):
    """Return a test database for Mitre."""
    def create_memory_db(*args, **kwargs):
        s3_db = connect(':memory:')
        cur = s3_db.cursor()
        with open(os.path.join(test_data_path, sql_file)) as f:
            cur.executescript(f.read())

        return s3_db

    return create_memory_db
