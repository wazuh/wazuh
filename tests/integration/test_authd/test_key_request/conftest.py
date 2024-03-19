"""
Copyright (C) 2015-2024, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import shutil
import pytest
import os

from wazuh_testing import logger


@pytest.fixture()
def copy_tmp_script(request):
    """
    Copy the script named 'script_filename' and found in 'script_path' to a temporary folder for use in the test.
    """
    try:
        script_filename = getattr(request.module, 'script_filename')
    except AttributeError as script_filename_not_set:
        logger.debug('script_filename is not set')
        raise script_filename_not_set

    try:
        script_path = getattr(request.module, 'script_path')
    except AttributeError as script_path_not_set:
        logger.debug('script_path is not set')
        raise script_path_not_set

    shutil.copy(os.path.join(script_path, script_filename), os.path.join("/tmp", script_filename))
