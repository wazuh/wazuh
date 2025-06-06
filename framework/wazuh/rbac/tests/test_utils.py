
import glob
import os
from unittest.mock import patch

from wazuh.core.utils import common
from wazuh.rbac.utils import RESOURCES_CACHE, expand_decoders, expand_lists, expand_rules

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
test_files_path = os.path.join(test_data_path, 'utils')


@patch('wazuh.core.utils.common.RULES_PATH', new=test_files_path)
@patch('wazuh.core.utils.common.USER_RULES_PATH', new=test_files_path)
def test_expand_rules():
    RESOURCES_CACHE.clear()
    rules = expand_rules()
    assert rules == set(map(os.path.basename, glob.glob(os.path.join(test_files_path,
                                                                     f'*{common.RULES_EXTENSION}'))))


@patch('wazuh.core.utils.common.DECODERS_PATH', new=test_files_path)
@patch('wazuh.core.utils.common.USER_DECODERS_PATH', new=test_files_path)
def test_expand_decoders():
    RESOURCES_CACHE.clear()
    decoders = expand_decoders()
    assert decoders == set(map(os.path.basename, glob.glob(os.path.join(test_files_path,
                                                                        f'*{common.DECODERS_EXTENSION}'))))


@patch('wazuh.core.utils.common.LISTS_PATH', new=test_files_path)
@patch('wazuh.core.utils.common.USER_LISTS_PATH', new=test_files_path)
def test_expand_lists():
    RESOURCES_CACHE.clear()
    lists = expand_lists()
    assert lists == set(filter(lambda x: len(x.split('.')) == 1, map(os.path.basename, glob.glob(os.path.join(
        test_files_path, f'*{common.LISTS_EXTENSION}')))))
