#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
#
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

import logging
import sqlite3
from sys import exit, path
from datetime import datetime, timezone
from json import dumps, JSONDecodeError
from os.path import join, dirname, realpath

path.append(join(dirname(realpath(__file__)), '..', '..'))  # noqa: E501
import utils
import exceptions
import tools
from integration import WazuhGCloudIntegration

try:
    from google.cloud import storage
    from google.api_core import exceptions as google_exceptions
    import pytz
except ImportError as e:
    raise exceptions.WazuhIntegrationException(errcode=1003, package=e.name)


class WazuhGCloudBucket(WazuhGCloudIntegration):
    """Class for getting Google Cloud Storage Bucket logs"""

    def __init__(self, credentials_file: str, logger: logging.Logger, bucket_name: str, prefix: str = None,
            delete_file: bool = False, only_logs_after: datetime = None, reparse : bool = False):
        """Class constructor.

        Parameters
        ----------
        credentials_file : str
            Path to credentials file.
        logger : logging.Logger
            Logger to use.
        bucket_name : str
            Name of the bucket to read the logs from.
        prefix : prefix
            Expected prefix for the logs. It can be used to specify the relative path where the logs are stored.
        delete_file : bool
            Indicate whether blobs should be deleted after being processed.
        only_logs_after : datetime
            Date after which obtain logs.
        reparse : bool
            Whether to parse already parsed logs or not

        Raises
        ------
        exceptions.GCloudError
            If the credentials file doesn't exist or doesn't have the required
            structure.
        """
        super().__init__(logger)
        self.bucket_name = bucket_name
        self.bucket = None

        if credentials_file:
            # If a credentials file path is provided, use it to create the client.
            try:
                self.client = storage.client.Client.from_service_account_json(credentials_file)
            except JSONDecodeError as error:
                raise exceptions.GCloudError(1000, credentials_file=credentials_file) from error
            except FileNotFoundError as error:
                raise exceptions.GCloudError(1001, credentials_file=credentials_file) from error
        else:
            # If no credentials file is provided, instantiate the client directly.
            # This will attempt to use Application Default Credentials (ADC).
            self.client = storage.client.Client()

        self.project_id = self.client.project
        self.prefix = prefix if not prefix or prefix[-1] == '/' else f'{prefix}/'
        self.delete_file = delete_file
        self.only_logs_after = only_logs_after
        self.default_date = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        self.db_path = join(utils.find_wazuh_path(), "wodles/gcloud/gcloud.db")
        self.db_connector = None
        self.db_table_name = None
        self.datetime_format = "%Y-%m-%d %H:%M:%S.%f%z"
        self.reparse = reparse

        self.sql_create_table = """
            CREATE TABLE
                {table_name} (
                project_id 'text' NOT NULL,
                bucket_name 'text' NOT NULL,
                prefix 'text' NULL,
                blob_name 'text' NOT NULL,
                creation_time 'text' NOT NULL,
                PRIMARY KEY (project_id, bucket_name, prefix, blob_name));"""
        self.sql_delete_processed_files = """
            DELETE FROM
                {table_name}
            WHERE
                project_id=:project_id AND
                bucket_name=:bucket_name AND
                prefix=:prefix;"""
        self.sql_insert_processed_file = """
            INSERT INTO {table_name} (
                project_id,
                bucket_name,
                prefix,
                blob_name,
                creation_time)
            VALUES
                (:project_id,
                :bucket_name,
                :prefix,
                :blob_name,
                :creation_time);"""
        self.sql_find_last_creation_time = """
            SELECT
                creation_time
            FROM
                {table_name}
            WHERE
                project_id=:project_id AND
                bucket_name=:bucket_name AND
                prefix =:prefix
            ORDER BY
                creation_time DESC
            LIMIT 1;"""
        self.sql_find_processed_files = """
            SELECT
                blob_name
            FROM
                {table_name}
            WHERE
                project_id=:project_id AND
                bucket_name=:bucket_name AND
                prefix =:prefix
            ORDER BY
                blob_name;"""

    def _get_last_processed_files(self):
        """Get the names of the blobs processed during the last execution.

        Returns
        -------
        List of str
            List with the filenames of all the previously processed blobs.
        """
        processed_files = self.db_connector.execute(
            self.sql_find_processed_files.format(table_name=self.db_table_name), {
                'project_id': self.project_id,
                'bucket_name': self.bucket_name,
                'prefix': self.prefix
            })
        return [p[0] for p in processed_files.fetchall()]

    def _update_last_processed_files(self, processed_files: list):
        """Remove the records for the previous execution and store the new values from the current one.

        Parameters
        ----------
        processed_files : List of storage.blob
            List with all the blobs successfully processed by the module.
        """
        if processed_files:
            self.logger.info('Updating previously processed files.')
            try:
                self.db_connector.execute(self.sql_delete_processed_files.format(table_name=self.db_table_name), {
                    'project_id': self.project_id,
                    'bucket_name': self.bucket_name,
                    'prefix': self.prefix
                })
            except sqlite3.OperationalError:
                pass

            for blob in processed_files:
                creation_time = datetime.strftime(blob.time_created, self.datetime_format)
                self.db_connector.execute(self.sql_insert_processed_file.format(table_name=self.db_table_name), {
                    'project_id': self.project_id,
                    'bucket_name': self.bucket_name,
                    'prefix': self.prefix,
                    'blob_name': blob.name,
                    'creation_time': creation_time
                })

    def _get_last_creation_time(self):
        """Get the latest creation time value stored in the database for the given project, bucket_name and
        prefix.

        Returns
        -------
        datetime or None
            The datetime of the last log parsed or None if no log have been parsed yet for that bucket.
        """
        creation_time = datetime.min.replace(tzinfo=pytz.UTC)
        query_creation_time = self.db_connector.execute(
            self.sql_find_last_creation_time.format(table_name=self.db_table_name), {
                'project_id': self.project_id,
                'bucket_name': self.bucket_name,
                'prefix': self.prefix
            })
        try:
            creation_time_result = query_creation_time.fetchone()[0]
            creation_time = datetime.strptime(creation_time_result, self.datetime_format)
        except (TypeError, IndexError):
            pass
        return creation_time

    def check_permissions(self):
        """
        Check if the Service Account has access to the bucket.

        Raises
        ------
        exceptions.GCloudError
            If the specified bucket doesn't exist or the client doesn't
            have permissions to access it.
        """
        try:
            self.bucket = self.client.get_bucket(self.bucket_name)
        except google_exceptions.NotFound:
            raise exceptions.GCloudError(1100, bucket_name=self.bucket_name)
        except google_exceptions.Forbidden:
            raise exceptions.GCloudError(1101, permissions='storage.buckets.get',
                                         resource_name=self.bucket_name)

    def init_db(self):
        """Connect to the database and try to access the table. The database file and the table will be created if they
         do not exist yet."""
        self.db_connector = sqlite3.connect(self.db_path)
        try:
            self.db_connector.execute(self.sql_create_table.format(table_name=self.db_table_name), {
                    'project_id': self.project_id,
                    'bucket_name': self.bucket_name,
                    'prefix': self.prefix
                })
        except sqlite3.OperationalError:
            # The table already exist
            pass

    def process_data(self):
        """Iterate over the contents of the bucket and process each blob contained.
        As the 'list_blobs' function will always return the complete list of blobs contained in the bucket this function
        checks if a particular file should be processed by taking into account the 'only_logs_after' and 'prefix', as
        well as the creation time of each blob.

        Returns
        -------
        int
            Number of blobs processed.
        """

        try:
            bucket_contents = self.bucket.list_blobs(prefix=self.prefix, delimiter='/')
            processed_files = []
            processed_messages = 0
            new_creation_time = datetime.min.replace(tzinfo=pytz.UTC)

            self.init_db()
            last_creation_time = self._get_last_creation_time()
            previous_processed_files = self._get_last_processed_files()

            if self.reparse:
                self.logger.info('Reparse Mode ON')

            for blob in bucket_contents:
                # Skip folders
                if blob.name.endswith('/'):
                    continue

                current_creation_time = blob.time_created
                comparison_date = self.only_logs_after if self.only_logs_after else self.default_date

                if current_creation_time >= comparison_date:
                    if (current_creation_time > last_creation_time) or \
                            (current_creation_time == last_creation_time and blob.name not in previous_processed_files):
                        self.logger.info(f'Processing {blob.name}')
                        processed_messages += self.process_blob(blob)

                        if current_creation_time > new_creation_time:
                            processed_files.clear()
                            new_creation_time = current_creation_time

                        processed_files.append(blob)

                    elif self.reparse:
                        processed_messages += self.process_blob(blob)
                        processed_files.append(blob)

                    else:
                        self.logger.info(f'Skipping previously processed file: {blob.name}')

                else:
                    self.logger.info(f'The creation time of {blob.name} is older than {comparison_date}. '
                                     f'Skipping it...')

        finally:
            # Ensure the changes are committed to the database even if an exception was raised
            if self.db_connector:
                self._update_last_processed_files(processed_files)
                self.db_connector.commit()
                self.db_connector.close()
        return processed_messages

    def load_information_from_file(self, msg: str):
        raise NotImplementedError

    def process_blob(self, blob):
        """Format every event obtained from `load_information_from_file` and send them to Analysisd. If the
        `delete_file` was used the blob will be removed from the bucket after being processed.

        Parameters
        ----------
        blob : google.cloud.storage.blob.Blob
            A blob object obtained from the bucket.
        Returns
        -------
        int
            Number of events processed.
        """
        num_events = 0
        try:
            events = self.load_information_from_file(blob.download_as_text())
            if len(events) > 0:
                with self.initialize_socket():
                    for event in events:
                        self.send_msg(self.format_msg(dumps(event)))
                        num_events += 1
            if self.delete_file:
                self.bucket.delete_blob(blob.name)
        except google_exceptions.NotFound:
            self.logger.warning(f'Unable to find "{blob.name}" in {self.bucket_name}')

        return num_events
