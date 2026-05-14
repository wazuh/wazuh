# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
from os import path
import botocore
import re

from aws_bucket import INVALID_CREDENTIALS_ERROR_CODE, INVALID_CREDENTIALS_ERROR_MESSAGE
from aws_bucket import INVALID_REQUEST_TIME_ERROR_CODE, INVALID_REQUEST_TIME_ERROR_MESSAGE
from aws_bucket import THROTTLING_EXCEPTION_ERROR_CODE, THROTTLING_EXCEPTION_ERROR_MESSAGE
from aws_bucket import UNKNOWN_ERROR_MESSAGE
from aws_bucket import AWSCustomBucket

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))
import aws_tools


class AWSServerAccess(AWSCustomBucket):

    def __init__(self, **kwargs):
        kwargs['db_table_name'] = 's3_server_access'
        AWSCustomBucket.__init__(self, **kwargs)
        self.date_regex = re.compile(r'(\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2})')
        self.date_format = '%Y-%m-%d'

    def iter_files_in_bucket(self, aws_account_id: str = None, aws_region: str = None):
        if aws_account_id is None:
            aws_account_id = self.aws_account_id
        try:
            bucket_files = self.client.list_objects_v2(**self.build_s3_filter_args(aws_account_id, aws_region,
                                                                                   custom_delimiter='-'))
            while True:
                if 'Contents' not in bucket_files:
                    self._print_no_logs_to_process_message(self.bucket, aws_account_id, aws_region)
                    return

                processed_logs = 0

                for bucket_file in bucket_files['Contents']:
                    if not bucket_file['Key']:
                        continue

                    if bucket_file['Key'][-1] == '/':
                        # The file is a folder
                        continue

                    try:
                        date_match = self.date_regex.search(bucket_file['Key'])
                        match_start = date_match.span()[0] if date_match else None
                    except TypeError:
                        if self.skip_on_error:
                            aws_tools.debug(
                                f"+++ WARNING: The format of the {bucket_file['Key']} filename is not valid, "
                                "skipping it.", 1)
                            continue
                        else:
                            aws_tools.error(f"The filename of {bucket_file['Key']} doesn't have the valid format.")
                            sys.exit(17)

                    if not self._same_prefix(match_start, aws_account_id, aws_region):
                        aws_tools.debug(f"++ Skipping file with another prefix: {bucket_file['Key']}", 3)
                        continue

                    if self.already_processed(bucket_file['Key'], aws_account_id, aws_region):
                        if self.reparse:
                            aws_tools.debug(f"++ File previously processed, but reparse flag set: {bucket_file['Key']}",
                                            1)
                        else:
                            aws_tools.debug(f"++ Skipping previously processed file: {bucket_file['Key']}", 2)
                            continue

                    aws_tools.debug(f"++ Found new log: {bucket_file['Key']}", 2)
                    # Get the log file from S3 and decompress it
                    log_json = self.get_log_file(aws_account_id, bucket_file['Key'])
                    self.iter_events(log_json, bucket_file['Key'], aws_account_id)
                    # Remove file from S3 Bucket
                    if self.delete_file:
                        aws_tools.debug(f"+++ Remove file from S3 Bucket:{bucket_file['Key']}", 2)
                        self.client.delete_object(Bucket=self.bucket, Key=bucket_file['Key'])
                    self.mark_complete(aws_account_id, aws_region, bucket_file)
                    processed_logs += 1

                if processed_logs == 0:
                    self._print_no_logs_to_process_message(self.bucket, aws_account_id, aws_region)

                if bucket_files['IsTruncated']:
                    new_s3_args = self.build_s3_filter_args(aws_account_id, aws_region, True)
                    new_s3_args['ContinuationToken'] = bucket_files['NextContinuationToken']
                    bucket_files = self.client.list_objects_v2(**new_s3_args)
                else:
                    break

        except Exception as err:
            if hasattr(err, 'message'):
                aws_tools.debug(f"+++ Unexpected error: {err.message}", 2)
            else:
                aws_tools.debug(f"+++ Unexpected error: {err}", 2)
            aws_tools.error(f"Unexpected error querying/working with objects in S3: {err}")
            sys.exit(7)

    def marker_only_logs_after(self, aws_region: str, aws_account_id: str) -> str:
        """
        Return a marker to filter AWS log files using the `only_logs_after` value.

        Parameters
        ----------
        aws_region : str
            The region where the bucket is located.
        aws_account_id : str
            The account ID of the AWS account.

        Returns
        -------
        str
            The filter, with the file's prefix and date.
        """
        return self.get_full_prefix(aws_account_id, aws_region) + self.only_logs_after.strftime(self.date_format)

    def check_bucket(self):
        """Check if the bucket is empty or the credentials are wrong."""

        try:
            bucket_objects = self.client.list_objects_v2(Bucket=self.bucket, Prefix=self.prefix, Delimiter='/')
            if not 'CommonPrefixes' in bucket_objects and not 'Contents' in bucket_objects:
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

            aws_tools.error(error_message)
            exit(exit_number)

    def load_information_from_file(self, log_key):
        """Load data from a S3 access log file."""

        def parse_line(line_):
            def merge_values(delimiter='"', remove=False):
                next_ = next(it, None)
                while next_:
                    value_list[-1] = f'{value_list[-1]} {next_}'
                    try:
                        if next_[-1] == delimiter:
                            if remove:
                                value_list[-1] = value_list[-1][1:-1]
                            break
                    except TypeError:
                        pass
                    next_ = next(it, None)

            value_list = list()
            it = iter(line_.split(" "))
            value = next(it, None)
            while value:
                value_list.append(value)
                # Check if the current value should be combined with the next ones
                try:
                    if value[0] == "[" and value[-1] != "]":
                        merge_values(delimiter=']', remove=True)
                    elif value[0] == '"' and value[-1] != '"':
                        merge_values(remove=True)
                    elif value[0] == "'" and value[-1] != "'":
                        merge_values(remove=True)
                    elif (value[0] == '"' and value[-1] == '"') or (value[0] == "'" and value[-1] == "'"):
                        value_list[-1] = value_list[-1][1:-1]
                except TypeError:
                    pass
                value = next(it, None)
            try:
                value_list[-1] = value_list[-1].replace("\n", "")
            except TypeError:
                pass
            return value_list

        with self.decompress_file(self.bucket, log_key=log_key) as f:
            fieldnames = (
                "bucket_owner", "bucket", "time", "remote_ip", "requester", "request_id", "operation", "key",
                "request_uri", "http_status", "error_code", "bytes_sent", "object_sent", "total_time",
                "turn_around_time", "referer", "user_agent", "version_id", "host_id", "signature_version",
                "cipher_suite", "authentication_type", "host_header", "tls_version")
            result = list()
            for line in f:
                json_list = dict(zip(fieldnames, parse_line(line)))
                json_list["source"] = 's3_server_access'
                result.append(json_list)
            return result
