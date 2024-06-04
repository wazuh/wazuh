# Copyright (C) 2015-2024, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import pytest
import subprocess

from pathlib import Path

from wazuh_testing.constants.paths.binaries import ACTIVE_RESPONSE_BIN_PATH
from wazuh_testing.utils import file


@pytest.fixture(scope='module')
def prepare_ar_files(request: pytest.FixtureRequest) -> None:
    """
    Fixture for preparing AR (Active Response) files.

    This fixture performs the necessary setup for AR files required for testing. It checks if the module
    defining the fixture has the necessary attributes, writes files, sets file permissions, and cleans up
    the files after the test.

    Args:
        request (FixtureRequest): The request object representing the fixture.

    Raises:
        AttributeError: If the `custom_ar_script` attribute is not defined in the module.
        AttributeError: If the `monitored_file` attribute is not defined in the module.
    """
    if not hasattr(request.module, 'custom_ar_script'):
        raise AttributeError('No `custom_ar_script` defined in module.')
    if not hasattr(request.module, 'monitored_file'):
        raise AttributeError('No `monitored_file` defined in module.')

    monitored_file = getattr(request.module, 'monitored_file')
    file.write_file(monitored_file, '')

    ar_script = getattr(request.module, 'custom_ar_script')
    destination_ar_script = Path(ACTIVE_RESPONSE_BIN_PATH, 'custom-ar.sh')

    script_data = file.read_file(ar_script)
    file.write_file(destination_ar_script, script_data)
    os.chmod(destination_ar_script, 0o777)

    yield

    file.remove_file(destination_ar_script)
    file.remove_file(monitored_file)


@pytest.fixture()
def fill_monitored_file(request: pytest.FixtureRequest, test_metadata: dict) -> None:
    """
    Fixture for filling the monitored file with test data.

    This fixture validates the input and necessary attributes, appends the test input to the monitored file,
    and cleans up the file after the test.

    Args:
        request (pytest.FixtureRequest): The request object representing the fixture.
        test_metadata (dict): Metadata containing the test input.

    Raises:
        AttributeError: If the `input` key is missing in the `test_metadata`.
        AttributeError: If the `monitored_file` attribute is not defined in the module.
        AttributeError: If the `file_created_by_script` attribute is not defined in the module.
    """
    if test_metadata.get('input') is None:
        raise AttributeError('No `input` key in `test_metadata`.')
    if not hasattr(request.module, 'monitored_file'):
        raise AttributeError('No `monitored_file` defined in module.')
    if not hasattr(request.module, 'file_created_by_script'):
        raise AttributeError('No `file_created_by_script` defined in module.')

    input = test_metadata['input']
    monitored_file = getattr(request.module, 'monitored_file')

    subprocess.Popen(f"echo '{input}' >> {monitored_file}", shell=True)

    yield

    file.remove_file(getattr(request.module, 'file_created_by_script'))
