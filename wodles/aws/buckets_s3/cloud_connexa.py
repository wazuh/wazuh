
import json
import sys
import re

import botocore

import aws_bucket
import aws_tools
from aws_tools import debug

from consts import (INVALID_CREDENTIALS_ERROR_CODE, INVALID_REQUEST_TIME_ERROR_CODE, THROTTLING_EXCEPTION_ERROR_CODE,
                    INVALID_CREDENTIALS_ERROR_MESSAGE, INVALID_REQUEST_TIME_ERROR_MESSAGE, THROTTLING_EXCEPTION_ERROR_MESSAGE )


def is_valid_filename(filename):
    # Define the regex pattern
    pattern = r'^.*\/\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-[A-Za-z0-9]{4}\.jsonl\.gz$'

    if re.match(pattern, filename):
        return True
    else:
        return False

class AWSCloudConnexaBucket(aws_bucket.AWSCustomBucket):

    def __init__(self, **kwargs):
        db_table_name = 'openvpncloudconnexa'
        aws_bucket.AWSCustomBucket.__init__(self, db_table_name, **kwargs)
        self.date_format = '%Y-%m-%d'
        self.check_prefix = False
        self.bucket_common_prefixes = []
        self.sql_find_last_key_processed = """
            SELECT
                log_key, marker_key
            FROM
                {table_name}
            WHERE
                bucket_path=:bucket_path AND
                aws_account_id=:aws_account_id AND
                log_key LIKE :prefix
            ORDER BY
                marker_key DESC
            LIMIT 1;"""
        self.sql_create_table = """
            CREATE TABLE {table_name} (
                bucket_path 'text' NOT NULL,
                aws_account_id 'text' NOT NULL,
                log_key 'text' NOT NULL,
                marker_key 'text' NOT NULL,
                processed_date 'text' NOT NULL,
                created_date 'integer' NOT NULL,
                PRIMARY KEY (bucket_path, aws_account_id, log_key));"""
        
        self.sql_mark_complete = """
            INSERT INTO {table_name} (
                bucket_path,
                aws_account_id,
                log_key,
                marker_key,
                processed_date,
                created_date)
            VALUES (
                :bucket_path,
                :aws_account_id,
                :log_key,
                :marker_key,
                DATETIME('now'),
                :created_date);"""
        debug(f"+++ AWSCloudConnexaBucket initialized", 3)

    def get_base_prefix(self):
        base_path = '{}AWSLogs/{}'.format(self.prefix, self.suffix)
        if self.aws_organization_id:
            base_path = '{base_prefix}{aws_organization_id}/'.format(
                base_prefix=base_path,
                aws_organization_id=self.aws_organization_id)

        return base_path
    
    def _parse_log_marker(self, key):
        # Define the regex pattern to match the date part
        pattern = r'\d{4}-\d{2}-\d{2}'

        # Search for the date pattern in the filename
        match = re.search(pattern, key)

        if match:
            date_string = match.group(0)
            return f'{date_string}'
        else:
            aws_tools.debug(f"Error: Date not found in the {key} filename.", 2)

    def mark_complete(self, aws_account_id, aws_region, log_file, **kwargs):
        if not self.reparse:
            try:
                marker_key = self._parse_log_marker(log_file['Key'])
                return_val = self.db_cursor.execute(self.sql_mark_complete.format(table_name=self.db_table_name), {
                    'bucket_path': self.bucket_path,
                    'aws_account_id': aws_account_id,
                    'aws_region': aws_region,
                    'log_key': log_file['Key'],
                    'marker_key': marker_key,
                    'created_date': self.get_creation_date(log_file)})
                print('rock111: mark_complete', log_file['Key'], marker_key, return_val)
            except Exception as e:
                debug("+++ Error marking log {} as completed: {}".format(log_file['Key'], e), 2)


    def build_s3_filter_args(self, aws_account_id, aws_region, current_folder, iterating=False, custom_delimiter='', **kwargs):
        filter_marker = ''
        marker_key = ''
        if self.reparse:
            if self.only_logs_after:
                filter_marker = self.marker_only_logs_after(aws_region, aws_account_id)
            else:
                filter_marker = self.marker_custom_date(aws_region, aws_account_id, self.default_date)
        else:
            query_last_key = self.db_cursor.execute(
                self.sql_find_last_key_processed.format(table_name=self.db_table_name), {
                    'bucket_path': self.bucket_path,
                    'aws_region': aws_region,
                    'prefix': f'{current_folder}%',
                    'aws_account_id': aws_account_id,
                    **kwargs
                })
            try:
                fetch_res =  query_last_key.fetchone()
                filter_marker, marker_key = fetch_res[0], fetch_res[1]
                debug(f"+++ fetched markers: {filter_marker} == {marker_key}", 2)
            except (TypeError, IndexError):
                # if DB is empty for a region
                filter_marker = self.marker_only_logs_after(aws_region, aws_account_id) if self.only_logs_after \
                    else self.marker_custom_date(aws_region, aws_account_id, self.default_date)

        filter_args = {
            'Bucket': self.bucket,
            'MaxKeys': 1000,
            'Prefix': self.get_full_prefix(aws_account_id, aws_region)
        }

        # if nextContinuationToken is not used for processing logs in a bucket
        if not iterating:
            filter_args['StartAfter'] = marker_key
            if self.only_logs_after:
                only_logs_marker = self.marker_only_logs_after(aws_region, aws_account_id)
                filter_args['StartAfter'] = only_logs_marker if only_logs_marker > marker_key else marker_key
                
            if custom_delimiter:
                prefix_len = len(filter_args['Prefix'])
                filter_args['StartAfter'] = filter_args['StartAfter'][:prefix_len] + \
                                            filter_args['StartAfter'][prefix_len:].replace('/', custom_delimiter)
            debug(f"+++ Marker: {filter_args['StartAfter']}", 2)
        filter_args['Prefix'] = current_folder
        if 'StartAfter' in filter_args:
            filter_args['StartAfter'] = f"{current_folder}{filter_args['StartAfter']}"

        return filter_args

    def iter_files_in_bucket(self, aws_account_id=None, aws_region=None, **kwargs):
        if aws_account_id is None:
            aws_account_id = self.aws_account_id
        try:
            for current_folder in self.bucket_common_prefixes:
                
                filter_args = self.build_s3_filter_args(aws_account_id, aws_region, current_folder, **kwargs)

                print('rock111: iter_files_in_bucket current_folder', current_folder, filter_args['Prefix'])
                bucket_files = self.client.list_objects_v2(
                    **filter_args
                )
                if self.reparse:
                    aws_tools.debug('++ Reparse mode enabled', 2)

                while True:
                    if 'Contents' not in bucket_files:
                        self._print_no_logs_to_process_message(self.bucket, aws_account_id, aws_region, **kwargs)
                        break

                    processed_logs = 0

                    for bucket_file in self._filter_bucket_files(bucket_files['Contents'], **kwargs):

                        if self.check_prefix:
                            date_match = self.date_regex.search(bucket_file['Key'])
                            match_start = date_match.span()[0] if date_match else None

                            if not self._same_prefix(match_start, aws_account_id, aws_region):
                                aws_tools.debug(f"++ Skipping file with another prefix: {bucket_file['Key']}", 3)
                                continue

                        if self.already_processed(bucket_file['Key'], aws_account_id, aws_region, **kwargs):
                            if self.reparse:
                                aws_tools.debug(f"++ File previously processed, but reparse flag set: {bucket_file['Key']}",
                                                1)
                            else:
                                aws_tools.debug(f"++ Skipping previously processed file: {bucket_file['Key']}", 1)
                                continue
                        
                        if not is_valid_filename(bucket_file['Key']):
                            aws_tools.debug(f"++ Skipping log file: {bucket_file['Key']} because of incorrect file format", 2)
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
                        new_s3_args = self.build_s3_filter_args(aws_account_id, aws_region, current_folder, True, **kwargs)
                        new_s3_args['ContinuationToken'] = bucket_files['NextContinuationToken']
                        bucket_files = self.client.list_objects_v2(**new_s3_args)
                    else:
                        break
                #commiting changes:
                self.db_connector.commit() #commit changes
        except botocore.exceptions.ClientError as error:
            error_message = "Unknown"
            exit_number = 1
            error_code = error.response.get("Error", {}).get("Code")

            if error_code == THROTTLING_EXCEPTION_ERROR_CODE:
                error_message = f"{THROTTLING_EXCEPTION_ERROR_MESSAGE.format(name='iter_files_in_bucket')}: {error}"
                exit_number = 16
            else:
                error_message = f'ERROR: The "iter_files_in_bucket" request failed: {error}'
                exit_number = 1
            print(f"ERROR: {error_message}")
            exit(exit_number)

        except Exception as err:
            if hasattr(err, 'message'):
                aws_tools.debug(f"+++ Unexpected error: {err.message}", 2)
            else:
                aws_tools.debug(f"+++ Unexpected error: {err}", 2)
            print(f"ERROR: Unexpected error querying/working with objects in S3: {err}")
            sys.exit(7)

    def check_bucket(self):
        """Check if the bucket is empty or the credentials are wrong."""
        try:
            # If folders are not among the first 1000 results, pagination is needed.
            paginator = self.client.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=self.bucket, Prefix=self.prefix, Delimiter='/'):
                if 'CommonPrefixes' in page:
                    self.bucket_common_prefixes = {curr_prefix.get('Prefix') for curr_prefix in page['CommonPrefixes']}
                    print("COMMON prefixes are:", self.bucket_common_prefixes)
                    break
            else:
                print("ERROR: No files were found in '{0}'. No logs will be processed.".format(self.bucket_path))
                exit(14)

        except botocore.exceptions.ClientError as error:
            error_message = "Unknown"
            exit_number = 1
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

            print(f"ERROR: {error_message}")
            exit(exit_number)
        except botocore.exceptions.EndpointConnectionError as e:
            print(f"ERROR: {str(e)}")
            exit(15)


    def load_information_from_file(self, log_key):
        """Load data from a OpenVPN log files."""
        debug(f"DEBUG: +++ AWSOpenVPNCloudConnexaBucket:load_information_from_file {log_key}", 3)

        def json_event_generator(data):
            while data:
                json_data, json_index = decoder.raw_decode(data)
                data = data[json_index:]
                yield json_data

        content = []
        decoder = json.JSONDecoder()
        with self.decompress_file(self.bucket, log_key=log_key) as f:
            for line in f.readlines():
                try:
                    for event in json_event_generator(line.rstrip()):
                        event['source'] = 'CloudConnexa'
                        content.append(event)

                except json.JSONDecodeError as Einst:
                    print("ERROR: Events from {} file could not be loaded.".format(log_key.split('/')[-1]))
                    print("ERROR: {}".format(Einst))
                    if not self.skip_on_error:
                        sys.exit(9)

        return json.loads(json.dumps(content))

    def marker_only_logs_after(self, aws_region, aws_account_id):
        only_logs_after_marker = f'{self.only_logs_after.strftime(self.date_format)}'
        return only_logs_after_marker

    def get_alert_msg(self, aws_account_id, log_key, event, error_msg=""):
        """ Override to send the json read from the bucklet for OpenVPN entries. """
        debug(f"+++ AWSOpenVPNCloudConnexaBucket:get_alert_msg {aws_account_id}, {log_key}, {event}, {error_msg};", 3)
        msg = event.copy()
        msg.update(
            {
                'aws': {
                    'log_info': {
                        'aws_account_alias': self.account_alias,
                        'log_file': log_key,
                        's3bucket': self.bucket
                    }
                }
            }
        )
        debug(f"+++ AWSOpenVPNCloudConnexaBucketget_alert_msg 01 {msg}", 3)
        msg['aws'].update({
                    'source': event['source']
                }
            )
        debug(f"+++ AWSOpenVPNCloudConnexaBucketget_alert_msg return {msg}", 3)
        return msg
