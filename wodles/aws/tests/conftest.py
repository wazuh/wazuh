# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest
import sqlite3

@pytest.fixture()
def custom_database():
    """Create a custom database in memory without cache."""
    memory_db = sqlite3.connect(':memory:')
    yield memory_db

    # List tables
    table_list = memory_db.execute(
        "SELECT name FROM sqlite_master WHERE type ='table' AND name NOT LIKE 'sqlite_%';").fetchall()

    # Drop tables
    for table in [table[0] for table in table_list]:
        memory_db.execute(f"DROP TABLE {table};")
    memory_db.close()
