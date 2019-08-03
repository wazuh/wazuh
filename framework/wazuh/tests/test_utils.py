# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from os.path import join, exists
from tempfile import TemporaryDirectory, NamedTemporaryFile
from unittest.mock import patch

import pytest

from wazuh.utils import safe_move


@patch('wazuh.utils.chown')
@patch('wazuh.utils.chmod')
@patch('wazuh.utils.utime')
@pytest.mark.parametrize('ownership, time, permissions',
    [((1000, 1000), None, None),
     ((1000, 1000), (12345, 12345), None),
     ((1000, 1000), None, 0o660),
     ((1000, 1000), (12345, 12345), 0o660)
     ]
)
def test_safe_move(mock_utime, mock_chmod, mock_chown, ownership, time, permissions):
    """Tests safe_move function works"""

    with TemporaryDirectory() as tmpdirname:
        tmp_file = NamedTemporaryFile(dir=tmpdirname, delete=False)
        target_file = join(tmpdirname, 'target')
        safe_move(tmp_file.name, target_file, ownership=ownership, time=time, permissions=permissions)
        assert(exists(target_file))
        mock_chown.assert_called_once_with(target_file, *ownership)
        if time is not None:
            mock_utime.assert_called_once_with(target_file, time)
        if permissions is not None:
            mock_chmod.assert_called_once_with(target_file, permissions)
