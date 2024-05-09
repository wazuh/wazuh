# Copyright (C) 2015-2024, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
from pathlib import Path

import pytest

from wazuh_testing.utils import file


@pytest.fixture()
def create_paths_files(test_metadata: dict) -> str:
    to_edit = test_metadata.get('path_or_files_to_create')

    if not isinstance(to_edit, list):
        raise TypeError(f"`files` should be a 'list', not a '{type(to_edit)}'")

    created_files = []
    for item in to_edit:
        item_path = Path(item)
        if item_path.exists():
            raise FileExistsError(f"`{item_path}` already exists.")

        # If file does not have suffixes, consider it a directory
        if item_path.suffixes == []:
            # Add a dummy file to the target directory to create the directory
            created_files.extend(file.create_parent_directories(
                Path(item_path).joinpath('dummy.file')))
        else:
            created_files.extend(file.create_parent_directories(item_path))

            file.write_file(file_path=item_path, data='')
            created_files.append(item_path)

    yield to_edit

    for item in to_edit:
        item_path = Path(item)
        file.delete_path_recursively(item_path)
