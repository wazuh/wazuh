# Copyright (C) 2015-2024, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
from pathlib import Path

import pytest

from wazuh_testing.utils import file


@pytest.fixture()
def symlink_target(test_metadata: dict) -> str:
    path = test_metadata.get('symlink_target')
    if file.exists(path):
        file.remove_file(path)

    if not '.' in path:
        file.recursive_directory_creation(path)
    else:
        file.write_file(path)

    yield Path(path)

    file.remove_file(path)


@pytest.fixture()
def symlink(symlink_target: Path, test_metadata: dict) -> str:
    symlink_path = test_metadata.get('symlink')
    if file.exists(symlink_path):
        file.remove_file(symlink_path)

    Path(symlink_path).symlink_to(symlink_target)

    yield Path(symlink_path)

    file.remove_file(symlink_path)


@pytest.fixture()
def symlink_new_target(test_metadata: dict) -> Path:
    path = test_metadata.get('symlink_new_target')
    if file.exists(path):
        file.remove_file(path)

    if not '\\.' in path:
        file.recursive_directory_creation(path)
    else:
        file.write_file(path)

    yield Path(path)

    file.remove_file(path)
