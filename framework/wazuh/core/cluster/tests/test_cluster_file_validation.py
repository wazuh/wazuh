# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
import tempfile
from unittest.mock import patch, MagicMock

import pytest

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators

        del sys.modules['wazuh.rbac.orm']
        from wazuh.tests.util import RBAC_bypasser

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        import wazuh.core.cluster.cluster as cluster
        from wazuh import WazuhException


class TestClusterMergedFileValidation:
    """Tests for merged file parameter validation in cluster operations."""

    @pytest.mark.parametrize('merge_type, merge_name, header_name, should_reject', [
        ("../etc", "payload.merged", "ossec.conf", True),
        ("..\\etc", "payload.merged", "ossec.conf", True),
        (".hidden", "payload.merged", "ossec.conf", True),
        ("valid", "../payload.merged", "ossec.conf", True),
        ("valid", "..\\payload.merged", "ossec.conf", True),
        ("valid", "payload.merged", "../../../etc/ossec.conf", False),
        ("valid", "payload.merged", "..\\..\\..\\etc\\ossec.conf", False),
        ("valid", "payload.merged", ".hidden_file", False),
        ("valid", "payload.merged", "subdir/file.txt", False),
        ("shared", "payload.merged", "validfile.txt", False),
    ])
    def test_merge_parameter_validation(self, merge_type, merge_name, header_name, should_reject):
        """Test validation of merge parameters and header names."""
        with tempfile.TemporaryDirectory() as tmpdir:
            merged_file = os.path.join(tmpdir, merge_name)

            file_content = b"test_content"
            header = f"{len(file_content)} {header_name} 2099-01-01 00:00:00.000000+0000\n"
            merged_content = header.encode() + file_content

            with open(merged_file, 'wb') as f:
                f.write(merged_content)

            with patch('wazuh.core.cluster.cluster.stat') as stat_mock:
                stat_mock.return_value.st_size = len(merged_content)

                if should_reject:
                    with pytest.raises(WazuhException, match='3052'):
                        list(cluster.unmerge_info(merge_type, tmpdir, merge_name))
                else:
                    results = list(cluster.unmerge_info(merge_type, tmpdir, merge_name))
                    for path_result, _, _ in results:
                        basename = os.path.basename(path_result)
                        assert '/' not in basename
                        assert '\\' not in basename

    def test_filename_normalization(self):
        """Test that filenames are properly normalized."""
        with tempfile.TemporaryDirectory() as tmpdir:
            merged_file = os.path.join(tmpdir, "payload.merged")

            test_paths = [
                "dir/../../../etc/ossec.conf",
                "valid/./../../../etc/ossec.conf",
            ]

            for test_path in test_paths:
                file_content = b"test"
                header = f"{len(file_content)} {test_path} 2099-01-01 00:00:00+0000\n"
                merged_content = header.encode() + file_content

                with open(merged_file, 'wb') as f:
                    f.write(merged_content)

                with patch('wazuh.core.cluster.cluster.stat') as stat_mock:
                    stat_mock.return_value.st_size = len(merged_content)

                    results = list(cluster.unmerge_info("valid", tmpdir, "payload.merged"))
                    for path_result, _, _ in results:
                        assert "queue/valid/" in path_result

    def test_multiple_file_processing(self):
        """Test processing multiple files with various filenames."""
        with tempfile.TemporaryDirectory() as tmpdir:
            merged_file = os.path.join(tmpdir, "payload.merged")

            files = [
                ("valid_file1.txt", b"content1"),
                ("../../../etc/testfile", b"content2"),
                ("valid_file2.txt", b"content3"),
                (".hidden_file", b"content4"),
                ("good_file.conf", b"content5"),
            ]

            merged_content = b""
            for filename, content in files:
                header = f"{len(content)} {filename} 2099-01-01 00:00:00+0000\n"
                merged_content += header.encode() + content

            with open(merged_file, 'wb') as f:
                f.write(merged_content)

            with patch('wazuh.core.cluster.cluster.stat') as stat_mock:
                stat_mock.return_value.st_size = len(merged_content)

                with patch('wazuh.core.cluster.cluster.logger') as logger_mock:
                    results = list(cluster.unmerge_info("valid", tmpdir, "payload.merged"))

                    assert len(results) == 4
                    for path_result, _, _ in results:
                        basename = os.path.basename(path_result)
                        assert not basename.startswith('.')

                    assert logger_mock.warning.call_count == 1
