# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import copy
import sys
import botocore
import json
import csv
import zipfile
import re
from os import path
from typing import Iterator, Optional

from datetime import date, datetime, timedelta

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))
import wazuh_integration
import aws_tools

MAX_RECORD_RETENTION = 500
DB_DATE_FORMAT = "%Y%m%d"
DEFAULT_DATABASE_NAME = "s3_cloudtrail"
# Date of the folder or name right after the full prefix of a key, as the markers are built. The month and day have
# two digits, or a key such as 2026/9/9/ would sort after the logs of the following months
KEY_DATE_REGEX = re.compile(r'(\d{4})[/-](\d{2})[/-](\d{2})(?!\d)')
# The date of a key may be in a time zone ahead of UTC, such as the prefix of a Firehose stream
MAX_KEY_DATE_UTC_OFFSET = timedelta(hours=14)

RETRY_CONFIGURATION_URL = 'https://documentation.wazuh.com/current/amazon/services/prerequisites/' \
                          'considerations.html#Connection-configuration-for-retries'

INVALID_CREDENTIALS_ERROR_CODE = "SignatureDoesNotMatch"
INVALID_REQUEST_TIME_ERROR_CODE = "RequestTimeTooSkewed"
THROTTLING_EXCEPTION_ERROR_CODE = "ThrottlingException"

UNKNOWN_ERROR_MESSAGE = "Unexpected error: '{error}'."
INVALID_CREDENTIALS_ERROR_MESSAGE = "Invalid credentials to access S3 Bucket"
INVALID_REQUEST_TIME_ERROR_MESSAGE = "The server datetime and datetime of the AWS environment differ"
THROTTLING_EXCEPTION_ERROR_MESSAGE = "The '{name}' request was denied due to request throttling. " \
                                     "If the problem persists check the following link to learn how to use " \
                                     f"the Retry configuration to avoid it: '{RETRY_CONFIGURATION_URL}'"

AWS_BUCKET_MSG_TEMPLATE = {'integration': 'aws',
                           'aws': {'log_info': {'aws_account_alias': '', 'log_file': '', 's3bucket': ''}}}


class AWSBucket(wazuh_integration.WazuhAWSDatabase):
    """
    Represents a bucket with events on the inside.

    This is an abstract class.

    Parameters
    ----------
    reparse : bool
        Whether to parse already parsed logs or not.
    access_key : str
        AWS access key id.
    secret_key : str
        AWS secret access key.
    profile : str
        AWS profile.
    iam_role_arn : str
        IAM Role.
    bucket : str
        Bucket name to extract logs from.
    only_logs_after : str
        Date after which obtain logs.
    skip_on_error : bool
        Whether to continue processing logs or stop when an error takes place.
    account_alias: str
        Alias of the AWS account where the bucket is.
    prefix : str
        Prefix to filter files in bucket.
    suffix : str
        Suffix to filter files in bucket.
    delete_file : bool
        Whether to delete an already processed file from a bucket or not.
    aws_organization_id : str
        The AWS organization ID.
    discard_field : str
        Name of the event field to apply the regex value on.
    discard_regex : str
        REGEX value to determine whether an event should be skipped.

    Attributes
    ----------
    date_format : str
        The format that the service uses to store the date in the bucket's path.
    """
    empty_bucket_message_template = "+++ No logs to process in bucket: {aws_account_id}/{aws_region}"

    def __init__(self, db_table_name, bucket, reparse, access_key, secret_key, profile, iam_role_arn,
                 only_logs_after, skip_on_error, account_alias, prefix, suffix, delete_file, aws_organization_id,
                 region, discard_field, discard_regex, sts_endpoint, service_endpoint, iam_role_duration=None):
        # common SQL queries
        self.sql_already_processed = """
            SELECT
              count(*)
            FROM
              {table_name}
            WHERE
              bucket_path=:bucket_path AND
              aws_account_id=:aws_account_id AND
              aws_region=:aws_region AND
              log_key=:log_name;"""

        self.sql_mark_complete = """
            INSERT INTO {table_name} (
                bucket_path,
                aws_account_id,
                aws_region,
                log_key,
                processed_date,
                created_date) VALUES (
                :bucket_path,
                :aws_account_id,
                :aws_region,
                :log_key,
                DATETIME('now'),
                :created_date);"""

        self.sql_create_table = """
            CREATE TABLE {table_name} (
                bucket_path 'text' NOT NULL,
                aws_account_id 'text' NOT NULL,
                aws_region 'text' NOT NULL,
                log_key 'text' NOT NULL,
                processed_date 'text' NOT NULL,
                created_date 'integer' NOT NULL,
                PRIMARY KEY (bucket_path, aws_account_id, aws_region, log_key));"""

        self.sql_find_last_key_processed = """
            SELECT
                log_key,
                processed_date
            FROM
                {table_name}
            WHERE
                bucket_path=:bucket_path AND
                aws_account_id=:aws_account_id AND
                aws_region = :aws_region AND
                log_key LIKE :prefix
            ORDER BY
                log_key DESC;"""

        self.sql_delete_processed_key = """
            DELETE FROM {table_name}
            WHERE
                bucket_path=:bucket_path AND
                aws_account_id=:aws_account_id AND
                log_key=:log_key;"""

        self.sql_find_first_key_processed = """
            SELECT
                log_key
            FROM
                {table_name}
            WHERE
                bucket_path=:bucket_path AND
                aws_account_id=:aws_account_id AND
                aws_region = :aws_region
            ORDER BY
                log_key ASC
            LIMIT 1;"""

        self.sql_db_maintenance = """
            DELETE FROM {table_name}
            WHERE
                bucket_path=:bucket_path AND
                aws_account_id=:aws_account_id AND
                aws_region=:aws_region AND
                log_key <= (SELECT log_key
                    FROM
                        {table_name}
                    WHERE
                        bucket_path=:bucket_path AND
                        aws_account_id=:aws_account_id AND
                        aws_region=:aws_region
                    ORDER BY
                        log_key DESC
                    LIMIT 1
                    OFFSET :retain_db_records);"""

        self.sql_db_maintenance_before_marker = """
            DELETE FROM {table_name}
            WHERE
                bucket_path=:bucket_path AND
                aws_account_id=:aws_account_id AND
                aws_region=:aws_region AND
                log_key LIKE :prefix AND
                log_key < :marker AND
                log_key <= (SELECT log_key
                    FROM
                        {table_name}
                    WHERE
                        bucket_path=:bucket_path AND
                        aws_account_id=:aws_account_id AND
                        aws_region=:aws_region
                    ORDER BY
                        log_key DESC
                    LIMIT 1
                    OFFSET :retain_db_records);"""

        self.sql_count_region = """
            SELECT
                count(*)
            FROM
                {table_name}
            WHERE
                bucket_path=:bucket_path AND
                aws_account_id=:aws_account_id AND
                aws_region=:aws_region;"""

        # DB name
        self.db_name = DEFAULT_DATABASE_NAME
        # Table name
        self.db_table_name = db_table_name

        wazuh_integration.WazuhAWSDatabase.__init__(self,
                                                    db_name=self.db_name,
                                                    service_name='s3',
                                                    access_key=access_key,
                                                    secret_key=secret_key,
                                                    profile=profile,
                                                    iam_role_arn=iam_role_arn,
                                                    region=region,
                                                    discard_field=discard_field,
                                                    discard_regex=discard_regex,
                                                    sts_endpoint=sts_endpoint,
                                                    service_endpoint=service_endpoint,
                                                    iam_role_duration=iam_role_duration,
                                                    skip_on_error=skip_on_error)
        self.retain_db_records = MAX_RECORD_RETENTION
        self.reparse = reparse
        self.only_logs_after = datetime.strptime(only_logs_after, DB_DATE_FORMAT) if only_logs_after else None
        self.account_alias = account_alias
        self.prefix = prefix
        self.suffix = suffix
        self.delete_file = delete_file
        self.bucket = bucket
        self.bucket_path = f"{self.bucket}/{self.prefix}"
        self.aws_organization_id = aws_organization_id
        self.date_format = "%Y/%m/%d"
        self.date_regex = re.compile(r'(\d{4}/\d{2}/\d{2})')
        self.prefix_regex = re.compile(r"^\d{12}$")
        self.key_date_regex = KEY_DATE_REGEX
        # The marker goes back to the day before the last key processed, to list again the files of its day
        self.rewinds_marker = True
        self.check_prefix = False

    def _same_prefix(self, match_start: int or None, aws_account_id: str, aws_region: str) -> bool:
        """
        Check if the prefix of a file key is the same as the one expected.

        Parameters
        ----------
        match_start : int or None
            The position of the string with the file key where it started matching with a date format.
        aws_account_id : str
            The account ID of the AWS account.
        aws_region : str
            The region where the bucket is located.

        Returns
        -------
        bool
            True if the prefix is the same, False otherwise.
        """
        return isinstance(match_start, int) and match_start == len(self.get_full_prefix(aws_account_id, aws_region))

    def already_processed(self, downloaded_file, aws_account_id, aws_region, **kwargs):
        cursor = self.db_cursor.execute(self.sql_already_processed.format(table_name=self.db_table_name), {
            'bucket_path': self.bucket_path,
            'aws_account_id': aws_account_id,
            'aws_region': aws_region,
            'log_name': downloaded_file})
        return cursor.fetchone()[0] > 0

    def get_creation_date(self, log_key):
        raise NotImplementedError

    def mark_complete(self, aws_account_id, aws_region, log_file, **kwargs):
        if not self.reparse:
            try:
                self.db_cursor.execute(self.sql_mark_complete.format(table_name=self.db_table_name), {
                    'bucket_path': self.bucket_path,
                    'aws_account_id': aws_account_id,
                    'aws_region': aws_region,
                    'log_key': log_file['Key'],
                    'created_date': self.get_creation_date(log_file)})
            except Exception as e:
                aws_tools.debug("+++ Error marking log {} as completed: {}".format(log_file['Key'], e), 2)

    def rewind_marker_to_day_folder(self, marker: str, aws_account_id: str, aws_region: str) -> str:
        """
        Rewind the S3 StartAfter marker to the beginning of the day before the date of its key.

        The next fetch lists again the files of the day of the marker: the ones delivered out of order (e.g. CloudTrail
        / ALB), and the ones sorting before a key of that day, as a valid key can be dated up to the next day.
        """
        key_date = self.get_key_date(marker, aws_account_id, aws_region)
        if not key_date:
            return marker

        # Rewind one full day
        rewind_day = datetime(key_date.year, key_date.month, key_date.day) - timedelta(days=1)

        return self.marker_custom_date(aws_region, aws_account_id, rewind_day)

    def get_key_date(self, log_key: str, aws_account_id: str, aws_region: str) -> Optional[date]:
        """
        Return the date of the folder or name right after the full prefix of a key.

        Parameters
        ----------
        log_key : str
            The key of the file.
        aws_account_id : str
            The account ID of the AWS account.
        aws_region : str
            The region where the bucket is located.

        Returns
        -------
        date or None
            The date, or None if the key has no valid date right after its full prefix.
        """
        full_prefix = self.get_full_prefix(aws_account_id, aws_region)
        match = self.key_date_regex.match(log_key, len(full_prefix)) if log_key.startswith(full_prefix) else None
        try:
            return date(*map(int, match.groups())) if match else None
        except ValueError:
            return None

    def is_valid_marker(self, log_key: str, aws_account_id: str, aws_region: str, written_date: datetime) -> bool:
        """
        Check if a key can be the marker of the next fetch, which starts after the greatest key processed.

        The key is chosen by whoever writes the object, so a key with no valid date right after the full prefix, or
        dated after the object was written, such as a far future day folder, would make every fetch skip the logs.

        Parameters
        ----------
        log_key : str
            The key of the file.
        aws_account_id : str
            The account ID of the AWS account.
        aws_region : str
            The region where the bucket is located.
        written_date : datetime
            When the object was written or processed, in UTC.

        Returns
        -------
        bool
            True if the key can be the marker, False otherwise.
        """
        key_date = self.get_key_date(log_key, aws_account_id, aws_region)
        return key_date is not None and key_date <= (written_date + MAX_KEY_DATE_UTC_OFFSET).date()

    def is_valid_listed_file(self, bucket_file: dict, aws_account_id: str, aws_region: str) -> bool:
        """
        Check if a listed file can be processed, as its key is the marker of the next fetch once it is processed.

        Parameters
        ----------
        bucket_file : dict
            The file, as list_objects_v2 returns it.
        aws_account_id : str
            The account ID of the AWS account.
        aws_region : str
            The region where the bucket is located.

        Returns
        -------
        bool
            True if the file can be processed, False otherwise.
        """
        if self.is_valid_marker(bucket_file['Key'], aws_account_id, aws_region, bucket_file['LastModified']):
            return True
        aws_tools.debug(f"+++ WARNING: Skipping file without a valid date after the prefix or dated after it was "
                        f"written: {bucket_file['Key']}", 1)
        return False

    def get_last_key_processed(self, aws_account_id: str, aws_region: str, prefix: str, **kwargs) -> Optional[str]:
        """
        Return the greatest key processed that can be the marker of the next fetch.

        Older versions processed every key, so the database may keep keys of the full prefix that are not a valid
        marker. The ones greater than the marker are removed, as the retention keeps the greatest keys and would remove
        the valid ones instead. Their files are skipped if they are listed again.

        Parameters
        ----------
        aws_account_id : str
            The account ID of the AWS account.
        aws_region : str
            The region where the bucket is located.
        prefix : str
            The pattern the keys must match.
        **kwargs
            Additional parameters of the query.

        Returns
        -------
        str or None
            The key, or None if no key processed can be the marker.
        """
        rows = self.db_cursor.execute(self.sql_find_last_key_processed.format(table_name=self.db_table_name), {
            'bucket_path': self.bucket_path,
            'aws_account_id': aws_account_id,
            'aws_region': aws_region,
            'prefix': prefix,
            **kwargs})
        full_prefix = self.get_full_prefix(aws_account_id, aws_region)
        marker, invalid_keys = None, []
        for log_key, processed_date in rows:
            # The processed date is the UTC time of the manager, which AWS requests keep within minutes of its own
            if self.is_valid_marker(log_key, aws_account_id, aws_region, datetime.fromisoformat(processed_date)):
                marker = log_key
                break
            if log_key.startswith(full_prefix):
                invalid_keys.append(log_key)

        for log_key in invalid_keys:
            aws_tools.debug(f"+++ Removing the processed key that cannot be the marker: {log_key}", 1)
        self.db_cursor.executemany(self.sql_delete_processed_key.format(table_name=self.db_table_name), [
            {'bucket_path': self.bucket_path, 'aws_account_id': aws_account_id, 'log_key': log_key}
            for log_key in invalid_keys])
        return marker

    def delete_keys_before_window(self, aws_account_id: str, aws_region: str, **kwargs):
        """
        Delete the processed keys of the full prefix beyond the retention, except the ones of the window of the rewound
        marker, as the next fetch would list them again and process them as new.

        Parameters
        ----------
        aws_account_id : str
            The account ID of the AWS account.
        aws_region : str
            The region where the bucket is located.
        **kwargs
            Additional parameters of the query.
        """
        prefix = f'{self.get_full_prefix(aws_account_id, aws_region)}%'
        last_key = self.get_last_key_processed(aws_account_id, aws_region, prefix, **kwargs)
        window = self.rewind_marker_to_day_folder(last_key, aws_account_id, aws_region) if last_key else None
        keys = [row[0] for row in self.db_cursor.execute(
            self.sql_find_last_key_processed.format(table_name=self.db_table_name), {
                'bucket_path': self.bucket_path,
                'aws_account_id': aws_account_id,
                'aws_region': aws_region,
                'prefix': prefix,
                **kwargs}).fetchall()]
        self.db_cursor.executemany(self.sql_delete_processed_key.format(table_name=self.db_table_name), [
            {'bucket_path': self.bucket_path, 'aws_account_id': aws_account_id, 'log_key': key}
            for key in keys[self.retain_db_records:] if window is None or key < window])

    def db_count_region(self, aws_account_id, aws_region):
        """Counts the number of rows in DB for a region
        :param aws_account_id: AWS account ID
        :type aws_account_id: str
        :param aws_region: AWS region
        :param aws_region: str
        :rtype: int
        """
        query_count_region = self.db_cursor.execute(
            self.sql_count_region.format(table_name=self.db_table_name), {'bucket_path': self.bucket_path,
                                                                          'aws_account_id': aws_account_id,
                                                                          'aws_region': aws_region,
                                                                          'retain_db_records': self.retain_db_records})
        return query_count_region.fetchone()[0]

    def db_maintenance(self, aws_account_id=None, aws_region=None):
        aws_tools.debug("+++ DB Maintenance", 1)
        try:
            if self.db_count_region(aws_account_id, aws_region) > self.retain_db_records:
                query = self.sql_db_maintenance
                params = {
                    'bucket_path': self.bucket_path,
                    'aws_account_id': aws_account_id,
                    'aws_region': aws_region,
                    'retain_db_records': self.retain_db_records}

                if self.rewinds_marker:
                    # Keep the files of the rewound marker window, or the next fetch would list them again
                    # and process them as new. Only the keys of this prefix are deleted, as other buckets with
                    # the same path, such as an organization trail, keep their own window
                    prefix = f'{self.get_full_prefix(aws_account_id, aws_region)}%'
                    last_key = self.get_last_key_processed(aws_account_id, aws_region, prefix)
                    if last_key:
                        query = self.sql_db_maintenance_before_marker
                        params['prefix'] = prefix
                        params['marker'] = self.rewind_marker_to_day_folder(last_key, aws_account_id, aws_region)

                self.db_cursor.execute(query.format(table_name=self.db_table_name), params)
        except Exception as e:
            aws_tools.error(f"Failed to execute DB cleanup - AWS Account ID: {aws_account_id}  Region: {aws_region}: {e}")

    def marker_custom_date(self, aws_region: str, aws_account_id: str, date: datetime) -> str:
        """
        Return an AWS bucket marker using a custom date.

        Parameters
        ----------
        aws_region : str
            The region.
        aws_account_id : str
            The account ID.
        date : datetime
            The date that must be used to create the filter.

        Returns
        -------
        str
            The required marker.
        """
        return f'{self.get_full_prefix(aws_account_id, aws_region)}{date.strftime(self.date_format)}'

    def marker_only_logs_after(self, aws_region, aws_account_id):
        return '{init}{only_logs_after}'.format(
            init=self.get_full_prefix(aws_account_id, aws_region),
            only_logs_after=self.only_logs_after.strftime(self.date_format)
        )

    def get_alert_msg(self, aws_account_id, log_key, event, error_msg=""):
        def remove_none_fields(event):
            for key, value in list(event.items()):
                if isinstance(value, dict):
                    remove_none_fields(event[key])
                elif value is None:
                    del event[key]

        # error_msg will only have a value when event is None and vice versa
        msg = copy.deepcopy(AWS_BUCKET_MSG_TEMPLATE)
        msg['aws']['log_info'].update({
            'aws_account_alias': self.account_alias,
            'log_file': log_key,
            's3bucket': self.bucket
        })
        if event:
            remove_none_fields(event)
            msg['aws'].update(event)
        elif error_msg:
            msg['error_msg'] = error_msg
        return msg

    def get_full_prefix(self, account_id, account_region):
        raise NotImplementedError

    def get_base_prefix(self):
        raise NotImplementedError

    def get_service_prefix(self, account_id):
        raise NotImplementedError

    def find_account_ids(self):
        try:
            prefixes = self.client.list_objects_v2(Bucket=self.bucket, Prefix=self.get_base_prefix(),
                                                   Delimiter='/')['CommonPrefixes']
            accounts = []
            for p in prefixes:
                account_id = p['Prefix'].split('/')[-2]
                if self.prefix_regex.match(account_id):
                    accounts.append(account_id)
            return accounts
        except botocore.exceptions.ClientError as err:
            if err.response['Error']['Code'] == THROTTLING_EXCEPTION_ERROR_CODE:
                aws_tools.debug(f'ERROR: {THROTTLING_EXCEPTION_ERROR_MESSAGE.format(name="find_account_ids")}.', 2)
                sys.exit(16)
            else:
                aws_tools.debug(f'ERROR: The "find_account_ids" request failed: {err}', 1)
                sys.exit(1)

        except KeyError:
            aws_tools.error(f"No logs found in '{self.get_base_prefix()}'. Check the provided prefix and the location of "
                  f"the logs for the bucket type '{aws_tools.get_script_arguments().type.lower()}'")
            sys.exit(18)

    def find_regions(self, account_id):
        try:
            regions = self.client.list_objects_v2(Bucket=self.bucket,
                                                  Prefix=self.get_service_prefix(account_id=account_id),
                                                  Delimiter='/')

            if 'CommonPrefixes' in regions:
                return [common_prefix['Prefix'].split('/')[-2] for common_prefix in regions['CommonPrefixes']]
            else:
                aws_tools.debug(f"+++ No regions found for AWS Account {account_id}", 1)
                return []
        except botocore.exceptions.ClientError as err:
            if err.response['Error']['Code'] == THROTTLING_EXCEPTION_ERROR_CODE:
                aws_tools.debug(f'ERROR: {THROTTLING_EXCEPTION_ERROR_MESSAGE.format(name="find_regions")}. ', 2)
                sys.exit(16)
            else:
                aws_tools.debug(f'ERROR: The "find_account_ids" request failed: {err}', 1)
                sys.exit(1)

    def build_s3_filter_args(self, aws_account_id, aws_region, iterating=False, custom_delimiter='', **kwargs):
        filter_marker = ''
        last_key = None
        if self.reparse:
            if self.only_logs_after:
                filter_marker = self.marker_only_logs_after(aws_region, aws_account_id)
            else:
                filter_marker = self.marker_custom_date(aws_region, aws_account_id, self.default_date)
        elif not iterating:
            # Only the keys of the full prefix can be the marker, as the table may hold the ones of other regions or
            # buckets with the same path. The next pages are listed with the continuation token instead
            db_prefix = f'{self.get_full_prefix(aws_account_id, aws_region)}%'

            filter_marker = self.get_last_key_processed(aws_account_id, aws_region, db_prefix, **kwargs)
            if filter_marker is None:
                # if DB is empty for a region
                filter_marker = self.marker_only_logs_after(aws_region, aws_account_id) if self.only_logs_after \
                    else self.marker_custom_date(aws_region, aws_account_id, self.default_date)
            elif self.rewinds_marker:
                # Rewind marker to day folder to catch late-arriving logs
                filter_marker = self.rewind_marker_to_day_folder(filter_marker, aws_account_id, aws_region)

        filter_args = {
            'Bucket': self.bucket,
            'MaxKeys': 1000,
            'Prefix': self.get_full_prefix(aws_account_id, aws_region)
        }

        # if nextContinuationToken is not used for processing logs in a bucket
        if not iterating:
            if aws_tools.get_script_arguments().type.lower() == 'config':
                # filter_marker route up to year
                match = re.match(r'(.*?/\d{4}/)', filter_marker)
                filter_marker_short = match.group(1)
                filter_args['StartAfter'] = filter_marker_short
                aws_tools.debug(f"+++ Marker: {filter_marker}", 2)
            else: 
                filter_args['StartAfter'] = filter_marker
                if self.only_logs_after:
                    only_logs_marker = self.marker_only_logs_after(aws_region, aws_account_id)
                    filter_args['StartAfter'] = only_logs_marker if only_logs_marker > filter_marker else filter_marker

                if custom_delimiter:
                    prefix_len = len(filter_args['Prefix'])
                    filter_args['StartAfter'] = filter_args['StartAfter'][:prefix_len] + \
                                                filter_args['StartAfter'][prefix_len:].replace('/', custom_delimiter)
                aws_tools.debug(f"+++ Marker: {filter_args['StartAfter']}", 2)

        return filter_args

    def reformat_msg(self, event):
        aws_tools.debug('++ Reformat message', 3)

        def single_element_list_to_dictionary(my_event):
            for name, value in list(my_event.items()):
                if isinstance(value, list) and len(value) == 1:
                    my_event[name] = value[0]
                elif isinstance(value, dict):
                    single_element_list_to_dictionary(my_event[name])

        # turn some list fields into dictionaries
        single_element_list_to_dictionary(event)

        # In order to support both old and new index pattern, change data.aws.sourceIPAddress fieldname
        # and parse that one with type ip
        # Only add this field if the sourceIPAddress is an IP and not a DNS.
        if 'sourceIPAddress' in event['aws'] and re.match(r'\d+\.\d+.\d+.\d+', event['aws']['sourceIPAddress']):
            event['aws']['source_ip_address'] = event['aws']['sourceIPAddress']

        if 'tags' in event['aws'] and not isinstance(event['aws']['tags'], dict):
            event['aws']['tags'] = {'value': event['aws']['tags']}

        return event

    def load_information_from_file(self, log_key):
        """
        AWS logs are stored in different formats depending on the service:
        * A JSON with a unique field "Records" which is an array of jsons. The filename has .json extension.
        (Cloudtrail)
        * Multiple JSONs stored in the same line and with no separation. The filename has no extension.
        (GuardDuty, IAM, Macie, Inspector)
        * TSV format. The filename has no extension. Has multiple lines. (VPC)
        :param log_key: name of the log file
        :return: list of events in json format.
        """
        raise NotImplementedError

    def get_log_file(self, aws_account_id, log_key):
        def exception_handler(error_txt, error_code):
            if self.skip_on_error:
                aws_tools.debug("++ {}; skipping...".format(error_txt), 1)
                try:
                    error_msg = self.get_alert_msg(aws_account_id,
                                                   log_key,
                                                   None,
                                                   error_txt)
                    self.send_msg(error_msg)
                except:
                    aws_tools.debug("++ Failed to send message to Wazuh", 1)
            else:
                aws_tools.error(error_txt)
                sys.exit(error_code)

        try:
            return self.load_information_from_file(log_key=log_key)
        except (TypeError, IOError, zipfile.BadZipfile, zipfile.LargeZipFile) as e:
            exception_handler("Failed to decompress file {}: {}".format(log_key, repr(e)), 8)
        except (ValueError, csv.Error) as e:
            exception_handler("Failed to parse file {}: {}".format(log_key, repr(e)), 9)
        except Exception as e:
            exception_handler("Unknown error reading/parsing file {}: {}".format(log_key, repr(e)), 1)

    def iter_bucket(self, account_id, regions):
        self.init_db(self.sql_create_table.format(table_name=self.db_table_name))
        self.iter_regions_and_accounts(account_id, regions)
        self.db_connector.commit()
        self.db_cursor.execute(self.sql_db_optimize)
        self.db_connector.close()

    def iter_regions_and_accounts(self, account_id, regions):
        if not account_id:
            # No accounts provided, so find which exist in s3 bucket
            account_id = self.find_account_ids()
        for aws_account_id in account_id:
            # No regions provided, so find which exist for this AWS account
            if not regions:
                regions = self.find_regions(aws_account_id)
                if not regions:
                    continue
            for aws_region in regions:
                aws_tools.debug("+++ Working on {} - {}".format(aws_account_id, aws_region), 1)
                self.iter_files_in_bucket(aws_account_id, aws_region)
                self.db_maintenance(aws_account_id=aws_account_id, aws_region=aws_region)

    def send_event(self, event):
        # Change dynamic fields to strings; truncate values as needed
        event_msg = self.reformat_msg(event)
        # Send the message
        self.send_msg(event_msg)

    def iter_events(self, event_list, log_key, aws_account_id):

        if event_list is not None:
            for event in event_list:
                if self.event_should_be_skipped(event):
                    aws_tools.debug(
                        f'+++ The "{self.discard_regex.pattern}" regex found a match in the "{self.discard_field}" '
                        f'field. The event will be skipped.', 2)
                    continue
                else:
                    aws_tools.debug(
                        f'+++ The "{self.discard_regex.pattern}" regex did not find a match in the '
                        f'"{self.discard_field}" field. The event will be processed.', 3)
                # Parse out all the values of 'None'
                event_msg = self.get_alert_msg(aws_account_id, log_key, event)

                self.send_event(event_msg)

    def _print_no_logs_to_process_message(self, bucket, aws_account_id, aws_region, **kwargs):

        if aws_account_id is not None and aws_region is not None:
            message_args = {
                'aws_account_id': aws_account_id, 'aws_region': aws_region, **kwargs
            }
        else:
            message_args = {'bucket': bucket}
        aws_tools.debug(self.empty_bucket_message_template.format(**message_args), 1)

    def _filter_bucket_files(self, bucket_files: list, **kwargs) -> Iterator[dict]:
        """Apply filters over a list of bucket files.
        Parameters
        ----------
        bucket_files : list
            Bucket files to filter.
        Yields
        ------
        Iterator[str]
            A bucket file that matches the filters.
        """
        for bucket_file in bucket_files:
            if not bucket_file['Key']:
                continue

            if bucket_file['Key'][-1] == '/':
                # The file is a folder
                continue

            yield bucket_file

    def iter_files_in_bucket(self, aws_account_id=None, aws_region=None, **kwargs):
        if aws_account_id is None:
            aws_account_id = self.aws_account_id
        try:
            bucket_files = self.client.list_objects_v2(
                **self.build_s3_filter_args(aws_account_id, aws_region, **kwargs)
            )
            if self.reparse:
                aws_tools.debug('++ Reparse mode enabled', 2)

            while True:
                if 'Contents' not in bucket_files:
                    self._print_no_logs_to_process_message(self.bucket, aws_account_id, aws_region, **kwargs)
                    return

                processed_logs = 0

                for bucket_file in self._filter_bucket_files(bucket_files['Contents'], **kwargs):

                    if self.check_prefix:
                        date_match = self.date_regex.search(bucket_file['Key'])
                        match_start = date_match.span()[0] if date_match else None

                        if not self._same_prefix(match_start, aws_account_id, aws_region):
                            aws_tools.debug(f"++ Skipping file with another prefix: {bucket_file['Key']}", 3)
                            continue

                    if not self.is_valid_listed_file(bucket_file, aws_account_id, aws_region):
                        continue

                    if self.already_processed(bucket_file['Key'], aws_account_id, aws_region, **kwargs):
                        if self.reparse:
                            aws_tools.debug(f"++ File previously processed, but reparse flag set: {bucket_file['Key']}",
                                            1)
                        else:
                            aws_tools.debug(f"++ Skipping previously processed file: {bucket_file['Key']}", 1)
                            continue

                    aws_tools.debug(f"++ Found new log: {bucket_file['Key']}", 2)
                    # Get the log file from S3 and decompress it
                    log_json = self.get_log_file(aws_account_id, bucket_file['Key'])
                    self.iter_events(log_json, bucket_file['Key'], aws_account_id)
                    # Remove file from S3 Bucket
                    if self.delete_file:
                        aws_tools.debug(f"+++ Remove file from S3 Bucket:{bucket_file['Key']}", 2)
                        self.client.delete_object(Bucket=self.bucket, Key=bucket_file['Key'])
                    self.mark_complete(aws_account_id, aws_region, bucket_file, **kwargs)
                    processed_logs += 1

                # This is a workaround in order to work with custom buckets that don't have
                # base prefix to search the logs
                if processed_logs == 0:
                    self._print_no_logs_to_process_message(self.bucket, aws_account_id, aws_region, **kwargs)

                if bucket_files['IsTruncated']:
                    new_s3_args = self.build_s3_filter_args(aws_account_id, aws_region, True, **kwargs)
                    new_s3_args['ContinuationToken'] = bucket_files['NextContinuationToken']
                    bucket_files = self.client.list_objects_v2(**new_s3_args)
                else:
                    break
        except botocore.exceptions.ClientError as error:
            error_code = error.response.get("Error", {}).get("Code")

            if error_code == THROTTLING_EXCEPTION_ERROR_CODE:
                error_message = f"{THROTTLING_EXCEPTION_ERROR_MESSAGE.format(name='iter_files_in_bucket')}: {error}"
                exit_number = 16
            else:
                error_message = f'ERROR: The "iter_files_in_bucket" request failed: {error}'
                exit_number = 1
            aws_tools.error(f"{error_message}")
            exit(exit_number)

        except Exception as err:
            if hasattr(err, 'message'):
                aws_tools.debug(f"+++ Unexpected error: {err.message}", 2)
            else:
                aws_tools.debug(f"+++ Unexpected error: {err}", 2)
            aws_tools.error(f"Unexpected error querying/working with objects in S3: {err}")
            sys.exit(7)

    def check_bucket(self):
        """Check if the bucket is empty or the credentials are wrong."""
        try:
            # If folders are not among the first 1000 results, pagination is needed.
            paginator = self.client.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=self.bucket, Prefix=self.prefix, Delimiter='/'):
                if 'CommonPrefixes' in page:
                    break
            else:
                aws_tools.error("No files were found in '{0}'. No logs will be processed.".format(self.bucket_path))
                exit(14)

        except botocore.exceptions.ClientError as error:
            error_code = error.response.get("Error", {}).get("Code")

            if error_code == THROTTLING_EXCEPTION_ERROR_CODE:
                error_message = f"{THROTTLING_EXCEPTION_ERROR_MESSAGE.format(name='check_bucket')}: {error}"
                exit_number = 16
            elif error_code == INVALID_CREDENTIALS_ERROR_CODE:
                error_message = INVALID_CREDENTIALS_ERROR_MESSAGE
                exit_number = 3
            elif error_code == INVALID_REQUEST_TIME_ERROR_CODE:
                error_message = INVALID_REQUEST_TIME_ERROR_MESSAGE
                exit_number = 19
            else:
                error_message = UNKNOWN_ERROR_MESSAGE.format(error=error)
                exit_number = 1

            aws_tools.error(f"{error_message}")
            exit(exit_number)
        except botocore.exceptions.EndpointConnectionError as e:
            aws_tools.error(f"{str(e)}")
            exit(15)


class AWSLogsBucket(AWSBucket):
    """
    Abstract class for logs generated from services such as CloudTrail or Config
    """

    def __init__(self, **kwargs):
        AWSBucket.__init__(self, **kwargs)
        # If not empty, both self.prefix and self.suffix always have a trailing '/'
        self.bucket_path = f"{self.bucket}/{self.prefix}{self.suffix}"
        self.service = None

    def get_base_prefix(self):
        base_path = '{}AWSLogs/{}'.format(self.prefix, self.suffix)
        if self.aws_organization_id:
            base_path = '{base_prefix}{aws_organization_id}/'.format(
                base_prefix=base_path,
                aws_organization_id=self.aws_organization_id)

        return base_path

    def get_service_prefix(self, account_id):
        return '{base_prefix}{aws_account_id}/{aws_service}/'.format(
            base_prefix=self.get_base_prefix(),
            aws_account_id=account_id,
            aws_service=self.service)

    def get_full_prefix(self, account_id, account_region):
        return '{service_prefix}{aws_region}/'.format(
            service_prefix=self.get_service_prefix(account_id),
            aws_region=account_region)

    def get_creation_date(self, log_file):
        # An example of cloudtrail filename would be
        # AWSLogs/11111111/CloudTrail/ap-northeast-1/2018/08/10/
        # 111111_CloudTrail_ap-northeast-1_20180810T0115Z_DgrtLuV9YQvGGdN6.json.gz
        # the following line extracts this part -> 20180810
        return int(path.basename(log_file['Key']).split('_')[-2].split('T')[0])

    def get_alert_msg(self, aws_account_id, log_key, event, error_msg=""):
        alert_msg = AWSBucket.get_alert_msg(self, aws_account_id, log_key, event, error_msg)
        alert_msg['aws']['aws_account_id'] = aws_account_id
        return alert_msg

    def load_information_from_file(self, log_key):
        with self.decompress_file(self.bucket, log_key=log_key) as f:
            json_file = json.load(f)
            return None if self.field_to_load not in json_file else [dict(x, source=self.service.lower()) for x in
                                                                     json_file[self.field_to_load]]


class AWSCustomBucket(AWSBucket):
    empty_bucket_message_template = "+++ No logs to process in bucket: {bucket}"

    def __init__(self, db_table_name=None, **kwargs):
        # only special services have a different DB table
        AWSBucket.__init__(self, db_table_name=db_table_name if db_table_name else 'custom', **kwargs)
        self.retain_db_records = MAX_RECORD_RETENTION
        # get STS client
        access_key = kwargs.get('access_key', None)
        secret_key = kwargs.get('secret_key', None)
        profile = kwargs.get('profile', None)
        self.sts_client = self.get_sts_client(access_key, secret_key, profile=profile)
        # get account ID
        self.aws_account_id = self.sts_client.get_caller_identity().get('Account')
        self.macie_location_pattern = re.compile(r'"lat":(-?0\d+\.\d+),"lon":(-?0\d+\.\d+)')
        self.check_prefix = True
        # SQL queries for custom buckets
        self.sql_already_processed = """
            SELECT
                count(*)
            FROM
                {table_name}
            WHERE
                bucket_path=:bucket_path AND
                aws_account_id=:aws_account_id AND
                log_key=:log_key;"""

        self.sql_mark_complete = """
            INSERT INTO {table_name} (
                bucket_path,
                aws_account_id,
                log_key,
                processed_date,
                created_date)
            VALUES (
                :bucket_path,
                :aws_account_id,
                :log_key,
                DATETIME('now'),
                :created_date);"""

        self.sql_create_table = """
            CREATE TABLE {table_name} (
                bucket_path 'text' NOT NULL,
                aws_account_id 'text' NOT NULL,
                log_key 'text' NOT NULL,
                processed_date 'text' NOT NULL,
                created_date 'integer' NOT NULL,
                PRIMARY KEY (bucket_path, aws_account_id, log_key));"""

        self.sql_find_last_key_processed = """
            SELECT
                log_key,
                processed_date
            FROM
                {table_name}
            WHERE
                bucket_path=:bucket_path AND
                aws_account_id=:aws_account_id AND
                log_key LIKE :prefix
            ORDER BY
                log_key DESC;"""

        self.sql_count_custom = """
            SELECT
                count(*)
            FROM
                {table_name}
            WHERE
                bucket_path=:bucket_path AND
                aws_account_id=:aws_account_id;"""

    def load_information_from_file(self, log_key):
        def json_event_generator(data):
            # Track a position instead of re-slicing `data` every iteration: `data[pos:]` would
            # copy the entire remaining string on every single object, well or malformed, which
            # is what made this loop quadratic in file size. raw_decode(data, pos) parses
            # forward from `pos` without touching (or needing) anything before it.
            pos = 0
            length = len(data)
            while pos < length:
                try:
                    json_data, pos = decoder.raw_decode(data, pos)
                except ValueError as err:
                    # Handle undefined values for lat and lon fields in Macie logs. Only the
                    # unconsumed remainder is searched/rewritten, not the whole file from the
                    # start -- `data[:pos]` was already parsed and yielded.
                    remainder = data[pos:]
                    match = self.macie_location_pattern.search(remainder)
                    if not match or not match.group(1) or not match.group(2):
                        raise err
                    lat = float(match.group(1))
                    lon = float(match.group(2))
                    new_pattern = f'"lat":{lat},"lon":{lon}'
                    data = data[:pos] + re.sub(self.macie_location_pattern, new_pattern, remainder)
                    length = len(data)
                    json_data, pos = decoder.raw_decode(data, pos)
                yield json_data

        with self.decompress_file(self.bucket, log_key=log_key) as f:
            if f.read(1) == '{':
                decoder = json.JSONDecoder()
                return [dict(event['detail'], source=event['source'].replace('aws.', '')) for event in
                        json_event_generator('{' + f.read()) if 'detail' in event]
            else:
                fieldnames = (
                    "version", "account_id", "interface_id", "srcaddr", "dstaddr", "srcport", "dstport", "protocol",
                    "packets", "bytes", "start", "end", "action", "log_status")
                tsv_file = csv.DictReader(f, fieldnames=fieldnames, delimiter=' ')
                return [dict(x, source='vpc') for x in tsv_file]

    def get_creation_date(self, log_file):
        # The Amazon S3 object name follows the pattern
        # DeliveryStreamName-DeliveryStreamVersion-YYYY-MM-DD-HH-MM-SS-RandomString
        name_regex = re.match(r".*(\d\d\d\d[\/\-]\d\d[\/\-]\d\d).*", log_file['Key'])
        if name_regex is None:
            return int(log_file['LastModified'].strftime('%Y%m%d'))
        else:
            return int(name_regex.group(1).replace('/', '').replace('-', ''))

    def get_full_prefix(self, account_id, account_region):
        return self.prefix

    def reformat_msg(self, event):

        def list_paths_from_dict(d, discard_levels=None, glue=".", path=None):
            path = [] if path is None else path
            if not isinstance(d, dict):
                path.extend(d if isinstance(d, list) else [str(d)])
                return [glue.join(path[:discard_levels if discard_levels is None else -discard_levels])]
            return [item for k, v in d.items() for item in list_paths_from_dict(v,
                                                                                path=path + [k],
                                                                                discard_levels=discard_levels,
                                                                                glue=glue)]

        AWSBucket.reformat_msg(self, event)
        if event['aws']['source'] == 'macie' and 'trigger' in event['aws']:
            del event['aws']['trigger']

        if 'service' in event['aws'] and 'additionalInfo' in event['aws']['service'] and \
                'unusual' in event['aws']['service']['additionalInfo'] and \
                not isinstance(event['aws']['service']['additionalInfo']['unusual'], dict):
            event['aws']['service']['additionalInfo']['unusual'] = {
                'value': event['aws']['service']['additionalInfo']['unusual']}

        if event['aws']['source'] == 'macie':
            for field in ('Bucket', 'DLP risk', 'IP', 'Location', 'Object',
                          'Owner', 'Themes', 'Timestamps', 'recipientAccountId'):
                try:
                    if isinstance(event['aws']['summary'][field], dict):
                        event['aws']['summary'][field] = list_paths_from_dict(event['aws']['summary'][field],
                                                                              discard_levels=1,
                                                                              path=[])
                except KeyError:
                    pass

            try:
                for event_name in event['aws']['summary']['Events']:
                    for event_field in event['aws']['summary']['Events'][event_name]:
                        event['aws']['summary']['Events'][event_name][event_field] = list_paths_from_dict(
                            event['aws']['summary']['Events'][event_name][event_field],
                            discard_levels=0 if event_field == 'count' else 1,
                            path=[])
            except KeyError:
                pass

        return event

    def iter_regions_and_accounts(self, account_id, regions):
        # Only <self.retain_db_records> logs for each region are stored in DB. Using self.bucket as region name
        # would prevent to lose lots of logs from different buckets.
        # no iterations for accounts_id or regions on custom buckets
        self.iter_files_in_bucket()
        self.db_maintenance()

    def already_processed(self, downloaded_file, aws_account_id, aws_region, **kwargs):
        cursor = self.db_cursor.execute(self.sql_already_processed.format(table_name=self.db_table_name), {
            'bucket_path': self.bucket_path,
            'aws_account_id': aws_account_id if aws_account_id else self.aws_account_id,
            'log_key': downloaded_file})
        return cursor.fetchone()[0] > 0

    def mark_complete(self, aws_account_id, aws_region, log_file, **kwargs):
        AWSBucket.mark_complete(self, aws_account_id or self.aws_account_id, aws_region, log_file)

    def db_count_custom(self, aws_account_id=None):
        """Counts the number of rows in DB for a region
        :param aws_account_id: AWS account ID
        :type aws_account_id: str
        :rtype: int
        """
        query_count_custom = self.db_cursor.execute(
            self.sql_count_custom.format(table_name=self.db_table_name), {
                'bucket_path': self.bucket_path,
                'aws_account_id': aws_account_id if aws_account_id else self.aws_account_id,
                'retain_db_records': self.retain_db_records})

        return query_count_custom.fetchone()[0]

    def db_maintenance(self, aws_account_id=None, aws_region=None, **kwargs):
        aws_tools.debug("+++ DB Maintenance", 1)
        aws_account_id = aws_account_id if aws_account_id else self.aws_account_id
        try:
            if self.db_count_custom(aws_account_id) > self.retain_db_records:
                # The table has no region column, so the keys of each region of native GuardDuty are the ones of its
                # full prefix
                self.delete_keys_before_window(aws_account_id, aws_region)
        except Exception as e:
            aws_tools.error(f"ERROR: Failed to execute DB cleanup - Path: {self.bucket_path}: {e}")
