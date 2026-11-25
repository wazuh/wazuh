#!/usr/bin/env python3
#
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

import logging
import re
import sys
from datetime import datetime, timedelta, timezone
from hashlib import md5
from json import dumps, loads
from os.path import abspath, dirname
from typing import Optional

from azure.core.exceptions import AzureError, ClientAuthenticationError, HttpResponseError, ResourceExistsError, \
    ResourceModifiedError
from azure.storage.blob import BlobServiceClient, BlobType
from dateutil.parser import parse

sys.path.insert(0, dirname(dirname(abspath(__file__))))

from azure_utils import (
    CREDENTIALS_URL,
    DEPRECATED_MESSAGE,
    offset_to_datetime,
    read_auth_file,
    send_message,
    DEFAULT_PATH_LOOKBACK,
    DEFAULT_PATH_MAX_FOLDERS,
    arg_valid_time_length,
)
from db import orm
from db.utils import (
    create_new_row,
    get_processed_bytes,
    remove_stale_offsets,
    save_processed_bytes,
    update_row_object,
)

# Date fields that <path> can include, with the step to go through their folders and how long each folder covers.
# How far back the folders are listed and how many of them is set with <path_lookback> and <path_max_folders>
# (see DEFAULT_PATH_LOOKBACK and DEFAULT_PATH_MAX_FOLDERS in azure_utils).
PREFIX_DATE_FIELDS = {
    'H': (timedelta(hours=1), timedelta(hours=1)),
    'd': (timedelta(days=1), timedelta(days=1)),
    'j': (timedelta(days=1), timedelta(days=1)),
    'm': (timedelta(days=1), timedelta(days=31)),
    'y': (timedelta(days=1), timedelta(days=366)),
    'Y': (timedelta(days=1), timedelta(days=366)),
}
# Read from left to right as strftime does: '%%' stands for one '%' and any other '%' is part of the name
PREFIX_DATE_FIELD_REGEX = re.compile(f'%([%{"".join(PREFIX_DATE_FIELDS)}])')


def get_prefix_date_fields(prefix: Optional[str]) -> set:
    """Get the date fields of a prefix. '%%' stands for one '%' and any other '%' is part of the name.

    Parameters
    ----------
    prefix : Optional[str]
        Prefix of the blobs, as set in <path>.

    Returns
    -------
    set
        The date fields found in the prefix, without the '%'.
    """
    return set(PREFIX_DATE_FIELD_REGEX.findall(prefix or '')) - {'%'}


def render_prefix(prefix: str, date: datetime) -> str:
    """Replace the date fields of a prefix with the given date and each '%%' with one '%'.

    Parameters
    ----------
    prefix : str
        Prefix of the blobs, as set in <path>.
    date : datetime
        Date of the folder.

    Returns
    -------
    str
        The prefix of the folder of that date.
    """
    return PREFIX_DATE_FIELD_REGEX.sub(
        lambda field: '%' if field.group(1) == '%' else date.strftime(field.group(0)), prefix
    )


def expand_prefix(prefix: Optional[str], since: datetime, lookback: timedelta = None,
                  max_folders: int = DEFAULT_PATH_MAX_FOLDERS) -> list:
    """Get the prefixes to list, one for each date folder from the lookback before the given date until now.

    A prefix without date fields is returned with each '%%' as one '%'. The dates are UTC.

    Parameters
    ----------
    prefix : Optional[str]
        Prefix of the blobs, as set in <path>.
    since : datetime
        Oldest last modified date of the blobs to send.
    lookback : timedelta
        How late a blob can be written to its date folder and still be listed. DEFAULT_PATH_LOOKBACK if not set.
    max_folders : int
        Most folders listed, the most recent ones. A warning is logged when older ones are left out.

    Returns
    -------
    list
        The prefixes, oldest first and without repetitions.
    """
    fields = get_prefix_date_fields(prefix)
    if not fields:
        return [render_prefix(prefix, since) if prefix else prefix]

    if lookback is None:
        lookback = arg_valid_time_length(DEFAULT_PATH_LOOKBACK)
    step = min(PREFIX_DATE_FIELDS[field][0] for field in fields)
    folder_length = min(PREFIX_DATE_FIELDS[field][1] for field in fields)
    now = datetime.now(timezone.utc)
    # The folder of the start date is listed whole, so the lookback only has to cover how late a blob can be written
    start = min(subtract(as_utc(since), lookback), now)
    # Folders older than the most that can be listed are not even rendered
    oldest = subtract(now, folder_length, max_folders)
    truncated = start < oldest
    current = max(start, oldest)

    prefixes = {}
    while True:
        prefixes[render_prefix(prefix, current)] = None
        if current >= now:
            break
        current = min(current + step, now)

    prefixes = list(prefixes)
    if truncated or len(prefixes) > max_folders:
        prefixes = prefixes[-max_folders:]
        logging.warning(
            f'Storage: Listing only the last {len(prefixes)} folders of path "{prefix}", '
            f'the older folders of the time window are not read.'
        )
    return prefixes


def subtract(date: datetime, length: timedelta, times: int = 1) -> datetime:
    """Subtract a length of time from a date, stopping at the oldest date that can be represented.

    Parameters
    ----------
    date : datetime
        Date to subtract from.
    length : timedelta
        Length of time to subtract.
    times : int
        Times the length is subtracted.

    Returns
    -------
    datetime
        The resulting date, in UTC.
    """
    try:
        return date - length * times
    except OverflowError:
        return datetime.min.replace(tzinfo=timezone.utc)


def as_utc(date: datetime) -> datetime:
    """Get a date with the UTC time zone if it has none.

    Parameters
    ----------
    date : datetime
        Date to check.

    Returns
    -------
    datetime
        The date, in UTC if it had no time zone.
    """
    return date.replace(tzinfo=timezone.utc) if date.tzinfo is None else date


def is_nested(blob_name: str, prefix: str) -> bool:
    """Check if a blob is under a subfolder of the folder the prefix points to.

    Parameters
    ----------
    blob_name : str
        Name of the blob.
    prefix : str
        Prefix used to list the blob.

    Returns
    -------
    bool
        True if the blob has more folders in its name than the prefix, taken as a folder.
    """
    # The prefix is a folder, with or without the trailing slash
    return blob_name.count('/') > prefix.rstrip('/').count('/') + 1


def start_storage(args):
    """Get access and content of the storage accounts."""
    logging.info('Azure Storage starting.')

    # Read credentials
    logging.info('Storage: Authenticating.')
    if args.storage_auth_path:
        logging.debug(f"Storage: Using path {args.storage_auth_path} for authentication")
        name, key = read_auth_file(
            auth_path=args.storage_auth_path, fields=('account_name', 'account_key')
        )
    elif args.account_name and args.account_key:
        logging.debug(f"Storage: Using path account name and account key for authentication")
        logging.warning(
            DEPRECATED_MESSAGE.format(
                name='account_name and account_key', release='4.4', url=CREDENTIALS_URL
            )
        )
        name = args.account_name
        key = args.account_key
    else:
        logging.error('Storage: No parameters have been provided for authentication.')
        sys.exit(1)

    service_client = BlobServiceClient(
        account_url=f"https://{name}.blob.core.windows.net/",
        credential={"account_name": name, "account_key": key}
    )

    # Verify if the credentials grant access to the specified container
    if args.container != '*':
        try:
            container_client = service_client.get_container_client(container=args.container)
            if not container_client.exists():
                logging.error(
                    f'Storage: The "{args.container}" container does not exists.'
                )
                sys.exit(1)
            logging.info(f"Storage: Getting the specified containers: {args.container}")
            containers = [args.container]
        except ClientAuthenticationError:
            logging.error(
                f'Storage: Invalid credentials for accessing the "{args.container}" container.'
            )
            sys.exit(1)
    else:
        try:
            logging.info("Storage: Getting all containers.")
            containers = [container.name for container in service_client.list_containers()]
        except ClientAuthenticationError:
            logging.error("Storage: Unable to list the containers. Invalid credentials.")
            sys.exit(1)
        except AzureError as e:
            logging.error(f"Storage: The containers could not be listed: '{e}'.")
            sys.exit(1)

    logging.info('Storage: Authenticated.')

    # The offsets of the append blobs already include the container, so they keep the key of the storage account,
    # except the ones of a block with date fields in its path (see get_blobs)
    account_md5_hash = md5(name.encode()).hexdigest()

    # Get the blobs
    for container in containers:
        # Blocks of the same container with another path or blob extension keep their own bookmark
        md5_hash = orm.create_pk(account=name, container=container, prefix=args.prefix, blobs=args.blobs)
        offset = args.storage_time_offset
        try:
            item = orm.get_row(orm.Storage, md5=md5_hash)
            if item is None:
                item = create_new_row(
                    table=orm.Storage, query=container, md5_hash=md5_hash, offset=offset
                )
        except orm.AzureORMError as e:
            logging.error(
                f'Error trying to obtain row object from "{orm.Storage.__tablename__}" using md5="{md5}": {e}'
            )
            sys.exit(1)

        min_datetime = parse(item.min_processed_date, fuzzy=True)
        max_datetime = parse(item.max_processed_date, fuzzy=True)
        desired_datetime = offset_to_datetime(offset) if offset else max_datetime
        get_blobs(
            container_name=container,
            prefix=args.prefix,
            service_client=service_client,
            md5_hash=md5_hash,
            account_md5_hash=account_md5_hash,
            min_datetime=min_datetime,
            max_datetime=max_datetime,
            desired_datetime=desired_datetime,
            tag=args.storage_tag,
            reparse=args.reparse,
            json_file=args.json_file,
            json_inline=args.json_inline,
            blob_extension=args.blobs,
            path_lookback=args.storage_path_lookback,
            path_max_folders=args.storage_path_max_folders,
        )
    logging.info('Storage: End')


def list_blobs(container_client, container_name: str, prefixes: list):
    """List the blobs under each prefix.

    Parameters
    ----------
    container_client : ContainerClient
        Client of the container to list.
    container_name : str
        Name of the container.
    prefixes : list
        Prefixes to list, None to list the whole container.

    Yields
    ------
    tuple
        The prefix used to list the blob and the blob properties.

    Raises
    ------
    AzureError
        If it was not possible to list the blobs for the given container.
    """
    for listing_prefix in prefixes:
        try:
            # The pages are requested while iterating
            for blob in container_client.list_blobs(name_starts_with=listing_prefix):
                yield listing_prefix, blob
        except AzureError as e:
            logging.error(f'Storage: Error getting blobs from "{container_name}": "{e}".')
            raise e


def get_blobs(
    container_name: str,
    service_client: BlobServiceClient,
    md5_hash: str,
    account_md5_hash: str,
    min_datetime: datetime,
    max_datetime: datetime,
    desired_datetime: datetime,
    tag: str,
    reparse: bool,
    json_file: bool,  # CHECKME
    json_inline: bool,  # CHECKME
    blob_extension: str,
    prefix: str = None,
    path_lookback: timedelta = None,
    path_max_folders: int = DEFAULT_PATH_MAX_FOLDERS,
):
    """Get the blobs from a container and send their content.

    Parameters
    ----------
    container_name : str
        Name of container to read the blobs from.
    service_client : BlobServiceClient
        Client used to obtain the blobs.
    min_datetime : datetime
        Value to compare with the blobs last modified times.
    max_datetime : datetime
        Value to compare with the blobs last modified times.
    desired_datetime : datetime
        Value to compare with the blobs last modified times.
    md5_hash : str
        md5 value used to search the container in the file containing the dates.
    account_md5_hash : str
        md5 value of the storage account name, used to store the offsets of the append blobs. With date fields in the
        prefix, md5_hash is used instead.
    prefix : str, optional
        Prefix value to search blobs that match with it. Its date fields are expanded to one prefix for each date
        folder between the desired date and now.
    path_lookback : timedelta, optional
        With date fields in the prefix, how late a blob can be written to its date folder and still be listed.
    path_max_folders : int, optional
        With date fields in the prefix, most date folders listed.

    Raises
    ------
    AzureError
        If it was not possible to list the blobs for the given container.
    """
    try:
        # Get the blob list
        logging.info(f"Storage: Getting blobs from container {container_name}.")
        container_client = service_client.get_container_client(container_name)
        since = desired_datetime
        if reparse and get_prefix_date_fields(prefix):
            # A reparse sends again every blob processed before, so it lists the folders since the oldest one
            since = min(as_utc(min_datetime), as_utc(desired_datetime))
        prefixes = expand_prefix(prefix, since, lookback=path_lookback, max_folders=path_max_folders)
        blobs = list_blobs(container_client, container_name, prefixes)
    except AzureError as e:
        logging.error(f'Storage: Error getting blobs from "{container_name}": "{e}".')
        raise e
    else:

        logging.info(
            f'Storage: The search starts from the date: {desired_datetime} for blobs in '
            f'container: "{container_name}" and prefix: "/{prefix if prefix is not None else ""}"'
        )
        # With date fields, the folders that leave the time window are not listed again, so their offsets can only be
        # removed by the block itself. Its offsets are kept apart from the ones of other blocks of the container.
        offsets_md5_hash = md5_hash if get_prefix_date_fields(prefix) else account_md5_hash
        append_blobs = {}
        for listing_prefix, blob in blobs:
            if blob.blob_type == BlobType.APPENDBLOB:
                append_blobs.setdefault(listing_prefix, set()).add(blob.name)
            # Skip if the blob is empty
            if blob.size == 0:
                logging.debug(f'Empty blob {blob.name}, skipping')
                continue
            # Skip the blob if nested under the set prefix
            if listing_prefix is not None and is_nested(blob.name, listing_prefix):
                logging.debug(
                    f'Skipped blob {blob.name}, nested under set prefix {listing_prefix}'
                )
                continue
            # Skip the blob if its name has not the expected format
            if blob_extension and blob_extension not in blob.name:
                logging.debug(
                    f'Skipped blob, name {blob.name} does not match with the format "{blob_extension}"'
                )
                continue

            # Append blobs only grow, so track the bytes already sent and read only what was appended since.
            # Blobs holding a single JSON document can't be parsed in parts and are always read whole.
            track_offset = blob.blob_type == BlobType.APPENDBLOB and not json_file
            creation_time = str(blob.creation_time)
            processed_bytes = None
            if track_offset and not reparse:
                processed_bytes = get_processed_bytes(offsets_md5_hash, container_name, blob.name, creation_time)
                if processed_bytes is None and offsets_md5_hash != account_md5_hash:
                    # A block that starts using date fields goes on from the offset it shared with other blocks
                    processed_bytes = get_processed_bytes(account_md5_hash, container_name, blob.name, creation_time)

            # Skip the blob if already processed
            last_modified = blob.last_modified
            if processed_bytes is not None:
                if blob.size < processed_bytes:
                    # The blob was replaced with less data than already processed
                    processed_bytes = 0
                already_processed = blob.size == processed_bytes
            else:
                already_processed = not reparse and (
                    last_modified < desired_datetime
                    or (min_datetime <= last_modified <= max_datetime)
                )
            if already_processed:
                logging.info(f"Storage: Skipping blob {blob.name} due to being already processed")
                continue

            # Get the blob data
            try:
                content, downloaded_bytes = download_blob(container_client, blob, offset=processed_bytes or None)
            except ResourceModifiedError as e:
                logging.error(f'Storage: Error downloading blob "{blob.name}" after multiple retries: {e}')
                continue
            except (ValueError, AzureError, HttpResponseError) as e:
                logging.error(f'Storage: Error reading the blob data: "{e}".')
                continue
            else:
                # Process the data as a JSON
                if json_file:
                    try:
                        content_list = loads(content)
                        records = content_list['records']
                    except (ValueError, TypeError, RecursionError) as e:
                        logging.error(
                            f'Storage: Error reading the contents of the blob: "{e}".'
                        )
                        continue
                    except KeyError as e:
                        logging.error(
                            f'Storage: No records found in the blob\'s contents: "{e}".'
                        )
                        continue
                    else:
                        if not isinstance(records, list):
                            logging.error(f'Storage: The records of the blob "{blob.name}" are not a list.')
                            continue
                        skipped_records = 0
                        for log_record in records:
                            if not isinstance(log_record, dict):
                                skipped_records += 1
                                continue
                            # Add azure tags
                            log_record['azure_tag'] = 'azure-storage'
                            if tag:
                                log_record['azure_storage_tag'] = tag
                            logging.info('Storage: Sending event by socket.')
                            send_message(dumps(log_record))
                        if skipped_records:
                            logging.warning(
                                f'Storage: Skipped records of the blob "{blob.name}" that are not JSON objects: '
                                f'{skipped_records}.'
                            )
                # Process the data as plain text
                else:
                    for line in [s for s in str(content).splitlines() if s]:
                        if json_inline:
                            msg = '{"azure_tag": "azure-storage"'
                            if tag:
                                msg = f'{msg}, "azure_storage_tag": "{tag}"'
                            msg = f'{msg}, {line[1:]}'
                        else:
                            msg = 'azure_tag: azure-storage.'
                            if tag:
                                msg = f'{msg} azure_storage_tag: {tag}.'
                            msg = f'{msg} {line}'
                        logging.info('Storage: Sending event by socket.')
                        send_message(msg)
                if track_offset:
                    save_processed_bytes(
                        offsets_md5_hash, container_name, blob.name, creation_time,
                        (processed_bytes or 0) + downloaded_bytes
                    )
            update_row_object(
                table=orm.Storage,
                md5_hash=md5_hash,
                query=container_name,
                new_min=last_modified.strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
                new_max=last_modified.strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
            )

        if get_prefix_date_fields(prefix):
            # Only the blobs of the folders listed are read again, so the offsets of any other blob are removed
            remove_stale_offsets(offsets_md5_hash, container_name, None, set().union(*append_blobs.values()))
        elif append_blobs:
            remove_stale_offsets(account_md5_hash, container_name, prefixes[0], append_blobs[prefixes[0]])


def download_blob(container_client, blob, offset=None, number_of_retries=3):
    """
    Download a blob from Azure Storage with retry logic on ResourceModifiedError.

    Parameters
    ----------
    container_client: BlobServiceClient
        The Azure container client instance.
    blob: BlobProperties
        The blob object or name to download.
    offset: int
        Byte to start downloading from. The whole blob is downloaded if not set.
    number_of_retries: int
        Maximum number of retry attempts (default: 3).

    Returns
    -------
    tuple
        The blob contents and the number of bytes downloaded.

    Raises
    ------
        ResourceModifiedError
            If the blob keeps being modified after all retries.
        ValueError, AzureError, HttpResponseError
            For other download errors.
    """
    attempt = 1

    while attempt <= number_of_retries:
        try:
            logging.info(f"Getting data from blob {blob.name}{f' from byte {offset}' if offset else ''}")
            data = container_client.download_blob(blob, offset=offset, encoding="UTF-8", max_concurrency=2)
            # Large blobs are read in chunks, which also fail if the blob changes meanwhile
            return data.readall(), data.size
        except ResourceModifiedError as e:
            if attempt == number_of_retries:
                raise e
            logging.info(f"Blob {blob.name} was modified while downloading, retrying download.")
            attempt += 1

        except (ValueError, AzureError, HttpResponseError) as e:
            raise e
