# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import glob
import pytest

@pytest.fixture
def run_on_end(request):
    """
    Fixture to copy the logs of the test at the end of a test run. The 'qa_logs' folder will be created
    in the GITHUB_WORKSPACE directory and the log.out file will be copied there.

    Args:
        request: The pytest request object.

    Returns:
        None
    """
    yield
    # Read the location of the log
    if 'GITHUB_WORKSPACE' not in os.environ:
        print("GITHUB_WORKSPACE is not defined")
        return
    path = os.environ['GITHUB_WORKSPACE']
    os.system(f"mkdir -p {path}/qa_logs")
    # Search for the log.out file in path variable
    for file_path in glob.glob(f'{path}/**/log.out', recursive=True):
        # Copy the file found to another directory
        print(f"Copying {file_path} to {path}/qa_logs/log.out.{request.node.name}")
        os.system(f"cp {file_path} {path}/qa_logs/log.out.{request.node.name}")
        break
