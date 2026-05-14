"""
Copyright (C) 2015-2024, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import pytest
import os

from wazuh_testing.constants.paths.configurations import DEFAULT_AUTHD_PASS_PATH
from wazuh_testing.utils import file


@pytest.fixture()
def set_authd_pass(test_metadata):
    """
    Configure the file 'authd.pass' as needed for the test.
    """
    # Write the content in the authd.pass file.
    file.write_file(DEFAULT_AUTHD_PASS_PATH, test_metadata['password'])

    yield

    # Delete the file as by default if it doesn't exist.
    file.remove_file(DEFAULT_AUTHD_PASS_PATH)


@pytest.fixture()
def reset_password(test_metadata):
    """
    Write the password file.
    """
    DEFAULT_TEST_PASSWORD = 'TopSecret'
    set_password = None
    try:
        if test_metadata['use_password'] == 'yes':
            set_password = 'defined'
            if test_metadata['random_pass'] == 'yes':
                set_password = 'random'
        else:
            set_password = 'undefined'
    except KeyError:
        pass

    # in case of random pass, remove /etc/authd.pass
    if set_password == 'random' or set_password == 'undefined':
        try:
            os.remove(DEFAULT_AUTHD_PASS_PATH)
        except FileNotFoundError:
            pass
        except IOError:
            raise
    # in case of defined pass, set predefined pass in  /etc/authd.pass
    elif set_password == 'defined':
        # Write authd.pass
        try:
            with open(DEFAULT_AUTHD_PASS_PATH, 'w') as pass_file:
                pass_file.write(DEFAULT_TEST_PASSWORD)
                pass_file.close()
        except IOError as exception:
            raise
