# Copyright (C) 2015-2024, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""Database helpers for the container_images integration tests."""
import os
import sqlite3

from wazuh_testing.constants.paths import WAZUH_PATH

CONTAINER_IMAGES_DB_PATH = os.path.join(WAZUH_PATH, 'queue', 'container_images', 'db', 'container_images.db')

REFERENCES_TABLE = 'dbsync_container_image_references'
PACKAGES_TABLE = 'dbsync_container_image_packages'


def query_table(table: str) -> list:
    """Return all rows of a module table as a list of dicts, or [] if the DB/table is absent."""
    if not os.path.exists(CONTAINER_IMAGES_DB_PATH):
        return []

    conn = sqlite3.connect(CONTAINER_IMAGES_DB_PATH)
    try:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        try:
            cursor.execute(f'SELECT * FROM {table}')
        except sqlite3.OperationalError:
            return []
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()
