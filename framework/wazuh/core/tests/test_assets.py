#!/usr/bin/env python
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import shutil
import pytest

from unittest.mock import patch

from wazuh import WazuhError, WazuhInternalError
from wazuh.core.assets import (
    generate_asset_filename,
    generate_asset_file_path,
    save_asset_file,
    DEFAULT_PERMISSIONS
)
from wazuh.core.engine.models.policies import PolicyType
from wazuh.core.engine.models.resources import ResourceType


@pytest.mark.parametrize(
    "original,expected",
    [
        ("simple", "simple"),
        ("/leading/slash", "leading_slash"),
        ("nested/dirs/file", "nested_dirs_file"),
        ("trailing/slash/", "trailing_slash"),
        ("spaces in name", "spaces_in_name"),
        ("already_safe.json", "already_safe.json"),
    ]
)
def test_generate_asset_filename(original, expected):
    """Test `generate_asset_filename` sanitizes input strings correctly."""
    assert generate_asset_filename(original) == expected


@pytest.mark.parametrize(
    "filename,has_ext",
    [
        ("my_asset", False),
        ("already.json", True),
        ("dir/name with spaces", False),
        ("nested/path/item.json", True),
    ]
)
def test_generate_asset_file_path(filename, has_ext):
    """Test `generate_asset_file_path` builds a proper JSON filepath for assets."""
    base_path = "/tmp/test_assets_base"
    with patch('wazuh.core.common.USER_ASSETS_PATH', base_path), \
         patch.object(PolicyType.TESTING, "dirname", return_value="testing"), \
         patch.object(ResourceType.DECODER, "dirname", return_value="rules"):
        result = generate_asset_file_path(filename, PolicyType.TESTING, ResourceType.DECODER)
    assert result.startswith(base_path + os.sep)
    if has_ext:
        assert result.endswith(".json")
    else:
        assert result.endswith(".json")
        assert not result[:-5].endswith(".json")  # only one extension


def test_save_asset_file(tmp_path):
    """Test `save_asset_file` writes content atomically and sets permissions."""
    dest_dir = tmp_path / "dest"
    dest_dir.mkdir()
    dest_file = dest_dir / "asset_ok.json"
    content = '{"key": "value"}'
    written = {}

    def safe_move_side_effect(src, dst, ownership=None, permissions=None):
        with open(src, 'r') as rfp, open(dst, 'w') as wfp:
            data = rfp.read()
            wfp.write(data)
        os.chmod(dst, permissions or DEFAULT_PERMISSIONS)
        written['content'] = data

    with patch('wazuh.core.common.OSSEC_TMP_PATH', str(tmp_path)), \
         patch('wazuh.core.assets.utils.safe_move', side_effect=safe_move_side_effect), \
         patch('wazuh.core.assets.common.wazuh_uid', return_value=0), \
         patch('wazuh.core.assets.common.wazuh_gid', return_value=0):
        result = save_asset_file(str(dest_file), content)

    print(result)
    assert result.dikt['message'] == 'File was successfully updated'
    assert dest_file.exists()
    assert written['content'] == content
    mode = dest_file.stat().st_mode & 0o777
    assert mode == DEFAULT_PERMISSIONS


def test_save_asset_file_io_error(tmp_path):
    """Test `save_asset_file` raises WazuhInternalError(1005) on write IOError."""
    with patch('wazuh.core.common.OSSEC_TMP_PATH', str(tmp_path)), \
         patch("wazuh.core.assets.tempfile.mkstemp", return_value=(1, str(tmp_path / "tmpfile.tmp"))), \
         patch("builtins.open", side_effect=IOError("disk error")):
        with pytest.raises(WazuhInternalError) as exc:
            save_asset_file(str(tmp_path / "dest.json"), "{}")
        assert exc.value.code == 1005


def test_save_asset_file_permission_error(tmp_path):
    """Test `save_asset_file` raises WazuhError(1006) on PermissionError during move."""
    with patch('wazuh.core.common.OSSEC_TMP_PATH', str(tmp_path)), \
         patch('wazuh.core.assets.utils.safe_move', side_effect=PermissionError), \
         patch('wazuh.core.assets.common.wazuh_uid', return_value=0), \
         patch('wazuh.core.assets.common.wazuh_gid', return_value=0):
        with pytest.raises(WazuhError) as exc:
            save_asset_file(str(tmp_path / "dest_perm.json"), "{}")
        assert exc.value.code == 1006


def test_save_asset_file_shutil_error(tmp_path):
    """Test `save_asset_file` raises WazuhInternalError(1016) on shutil.Error during move."""
    with patch('wazuh.core.common.OSSEC_TMP_PATH', str(tmp_path)), \
         patch('wazuh.core.assets.utils.safe_move', side_effect=shutil.Error("move failed")), \
         patch('wazuh.core.assets.common.wazuh_uid', return_value=0), \
         patch('wazuh.core.assets.common.wazuh_gid', return_value=0):
        with pytest.raises(WazuhInternalError) as exc:
            save_asset_file(str(tmp_path / "dest_err.json"), "{}")
