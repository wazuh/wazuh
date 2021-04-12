#!/usr/bin/env python
# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
from unittest.mock import patch

with patch('wazuh.common.ossec_uid'):
    with patch('wazuh.common.ossec_gid'):
        import wazuh.rbac.decorators

        from wazuh.tests.util import get_fake_database_data, RBAC_bypasser, InitWDBSocketMock

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        from wazuh import mitre

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')


# Tests

@patch('wazuh.core.utils.WazuhDBConnection', return_value=InitWDBSocketMock(sql_schema_file='schema_mitre_test.sql'))
def test_get_mitre_metadata(mock_mitre_db):
    """Check MITRE metadata
    """
    result = mitre.mitre_metadata()
    cur = get_fake_database_data('schema_mitre_test.sql').cursor()
    cur.execute("SELECT * FROM metadata")
    rows = cur.fetchall()

    assert result.affected_items[0]['key'] == rows[0][0]
    assert result.affected_items[1]['key'] == rows[1][0]
    assert result.affected_items[0]['value'] == rows[0][1]
    assert result.affected_items[1]['value'] == rows[1][1]
