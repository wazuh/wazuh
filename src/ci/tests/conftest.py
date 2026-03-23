"""
Copyright (C) 2015, Wazuh Inc.
April 1, 2022.

This program is free software; you can redistribute it
and/or modify it under the terms of the GNU General Public
License (version 2) as published by the FSF - Free Software
Foundation.
"""

import logging
import pytest


def pytest_addoption(parser):
    parser.addoption(
        "--moduleName",
        action="store",
        default=None,
        type=str,
        help="run test for a specific module")


@pytest.fixture(scope="session")
def getModuleName(request):
    return request.config.getoption("--moduleName")
