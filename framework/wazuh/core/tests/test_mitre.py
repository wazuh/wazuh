#!/usr/bin/env python
# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch

from wazuh.tests.util import InitWDBSocketMock

with patch('wazuh.core.common.ossec_uid'):
    with patch('wazuh.core.common.ossec_gid'):
        from wazuh.core.mitre import *


# Tests

def test_WazuhDBQueryMitre_metadata():
    """Verify that the method connects correctly to the database and returns the correct type."""
    with patch('wazuh.core.utils.WazuhDBConnection') as mock_wdb:
        mock_wdb.return_value = InitWDBSocketMock(sql_schema_file='schema_mitre_test.sql')
        db_query = WazuhDBQueryMitreMetadata()
        data = db_query.run()

        assert isinstance(db_query, WazuhDBQueryMitre) and isinstance(data, dict)
