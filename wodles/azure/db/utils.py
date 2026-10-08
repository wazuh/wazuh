#!/usr/bin/env python3
#
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

import logging
import sys
from datetime import datetime
from hashlib import md5
from os.path import abspath, dirname
from typing import Optional

from dateutil.parser import parse

sys.path.insert(0, dirname(dirname(abspath(__file__))))

from azure_utils import DATETIME_MASK, offset_to_datetime
from db import orm


def update_row_object(
    table: orm.Base, md5_hash: str, new_min: str, new_max: str, query: str = None
):
    """Update the database with the specified values if applicable.

    Parameters
    ----------
    table : orm.Base
        Database table reference for the service.
    md5_hash : str
        md5 value used to search the query in the file containing the dates.
    new_min : str
        Value to compare with the current min value stored.
    new_max : str
        Value to compare with the current max value stored.
    query : str
        Query value before applying the md5 hash transformation.
    """
    try:
        row = orm.get_row(table=table, md5=md5_hash)
        old_min_str = row.min_processed_date
        old_max_str = row.max_processed_date
    except (orm.AzureORMError, AttributeError) as e:
        logging.error(
            f'Error trying to obtain row object from "{table.__tablename__}" using md5="{md5}": {e}'
        )
        sys.exit(1)
    old_min_date = parse(old_min_str, fuzzy=True)
    old_max_date = parse(old_max_str, fuzzy=True)
    # "parse" adds compatibility with "last_dates_files" from previous releases as the format wasn't localized
    # It also handles any datetime with more than 6 digits for the microseconds value provided by Azure
    new_min_date = parse(new_min, fuzzy=True)
    new_max_date = parse(new_max, fuzzy=True)
    if new_min_date < old_min_date or new_max_date > old_max_date:
        min_ = new_min if new_min_date < old_min_date else old_min_str
        max_ = new_max if new_max_date > old_max_date else old_max_str
        logging.debug(
            f'Attempting to update a {table.__tablename__} row object. '
            f'MD5: "{md5_hash}", min_date: "{min_}", max_date: "{max_}"'
        )
        try:
            orm.update_row(
                table=table, md5=md5_hash, min_date=min_, max_date=max_, query=query
            )
        except orm.AzureORMError as e:
            logging.error(f'Error updating row object from {table.__tablename__}: {e}')
            sys.exit(1)


def create_new_row(table: orm.Base, md5_hash: str, query: str, offset: str) -> orm.Base:
    """Create a new row object for the given table, insert it into the database and return it.

    Parameters
    ----------
    table : orm.Base
        Database table reference for the service.
    md5_hash : str
        md5 value used as the key for the table.
    query : str
        The query value before applying the md5 transformation.
    offset : str
        Value used to determine the desired datetime.

    Returns
    -------
    orm.Base
        A copy of the inserted row object.
    """
    logging.info(
        f'{md5_hash} was not found in the database for {table.__tablename__}. Adding it.'
    )
    desired_datetime = (
        offset_to_datetime(offset)
        if offset
        else datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    )
    desired_str = desired_datetime.strftime(DATETIME_MASK)
    item = table(
        md5=md5_hash,
        query=query,
        min_processed_date=desired_str,
        max_processed_date=desired_str,
    )
    logging.debug(
        f'Attempting to insert row object into {table.__tablename__} with md5="{md5_hash}", '
        f'min_date="{desired_str}", max_date="{desired_str}"'
    )
    try:
        orm.add_row(row=item)
    except orm.AzureORMError as e:
        logging.error(f'Error inserting row object into {table.__tablename__}: {e}')
        sys.exit(1)
    return item


def get_processed_bytes(md5_hash: str, container: str, blob: str, creation_time: str) -> Optional[int]:
    """Get the number of bytes already processed from a blob.

    Parameters
    ----------
    md5_hash : str
        md5 value of the storage account name.
    container : str
        Name of the container holding the blob.
    blob : str
        Name of the blob.
    creation_time : str
        Creation time of the blob.

    Returns
    -------
    Optional[int]
        The number of bytes processed, 0 if the blob was created again after storing its offset, or None if the blob
        has no offset stored.
    """
    try:
        row = orm.get_blob_offset(md5=md5_hash, container=container, blob=blob)
    except orm.AzureORMError as e:
        logging.error(f'Error trying to obtain the offset of blob "{blob}" from {orm.StorageBlobOffset.__tablename__}: {e}')
        sys.exit(1)
    if row is None:
        return None
    return row.processed_bytes if row.creation_time == creation_time else 0


def save_processed_bytes(md5_hash: str, container: str, blob: str, creation_time: str, processed_bytes: int):
    """Store the number of bytes already processed from a blob.

    Parameters
    ----------
    md5_hash : str
        md5 value of the storage account name.
    container : str
        Name of the container holding the blob.
    blob : str
        Name of the blob.
    creation_time : str
        Creation time of the blob.
    processed_bytes : int
        Number of bytes processed.
    """
    logging.debug(f'Storing {processed_bytes} processed bytes for blob "{blob}" of container "{container}"')
    try:
        orm.set_blob_offset(
            md5=md5_hash, container=container, blob=blob, creation_time=creation_time, processed_bytes=processed_bytes
        )
    except orm.AzureORMError as e:
        logging.error(f'Error storing the offset of blob "{blob}" into {orm.StorageBlobOffset.__tablename__}: {e}')
        sys.exit(1)


def remove_stale_offsets(md5_hash: str, container: str, prefix: Optional[str], keep: set):
    """Remove the offsets of the blobs under the prefix that are no longer in the container.

    Parameters
    ----------
    md5_hash : str
        md5 value of the storage account name.
    container : str
        Name of the container holding the blobs.
    prefix : Optional[str]
        Only offsets of blobs whose name starts with this prefix are considered.
    keep : set
        Names of the blobs present in the container.
    """
    try:
        orm.delete_blob_offsets(md5=md5_hash, container=container, prefix=prefix, keep=keep)
    except orm.AzureORMError as e:
        logging.error(f'Error removing stale offsets from {orm.StorageBlobOffset.__tablename__}: {e}')
        sys.exit(1)
