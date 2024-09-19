# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
from os import path
import json
import botocore
from aws_bucket import (
    AWSBucket, 
    AWSCustomBucket, 
    AWSLogsBucket, 
    THROTTLING_EXCEPTION_ERROR_CODE, 
    THROTTLING_EXCEPTION_ERROR_MESSAGE
)

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))
import aws_tools

WAF_NATIVE = 'WAFNative'
WAF_KINESIS = 'WAFKinesis'
WAF_URL = 'https://documentation.wazuh.com/current/amazon/services/supported-services/waf.html'
WAF_DEPRECATED_MESSAGE = 'The functionality to process WAF logs stored in S3 via Kinesis was deprecated ' \
                           'in {release}. Consider configuring WAF to store its logs directly in an S3 ' \
                           'bucket instead. Check {url} for more information.'


class AWSWAFBucket(AWSCustomBucket):
    standard_http_headers = ['a-im', 'accept', 'accept-charset', 'accept-encoding', 'accept-language',
                             'access-control-request-method', 'access-control-request-headers', 'authorization',
                             'cache-control', 'connection', 'content-encoding', 'content-length', 'content-type',
                             'cookie', 'date', 'expect', 'forwarded', 'from', 'host', 'http2-settings', 'if-match',
                             'if-modified-since', 'if-none-match', 'if-range', 'if-unmodified-since', 'max-forwards',
                             'origin', 'pragma', 'prefer', 'proxy-authorization', 'range', 'referer', 'te', 'trailer',
                             'transfer-encoding', 'user-agent', 'upgrade', 'via', 'warning', 'x-requested-with',
                             'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-proto']

    def __init__(self, **kwargs):
        waf_acls = kwargs.pop('waf_acls', None)
        kwargs['db_table_name'] = 'waf'
        super().__init__(**kwargs)

        if self.check_waf_type():
            self.waf_acls = waf_acls
            self.service = 'WAFLogs'
            self.type = WAF_NATIVE
            self.empty_bucket_message_template = AWSBucket.empty_bucket_message_template
        else:
            self.type = WAF_KINESIS
    
    def check_waf_type(self):
        """Checks if it contains the 'AWSLogs' prefix to determine the type of WAF.

        Returns:
            bool: True if WAF type is native, False if is Kinesis.
        """
        try:
            return 'CommonPrefixes' in self.client.list_objects_v2(Bucket=self.bucket, Prefix=f'{self.prefix}AWSLogs',
                                                                   Delimiter='/', MaxKeys=1)
        except Exception as err:
            if hasattr(err, 'message'):
                aws_tools.debug(f"+++ Unexpected error: {err.message}", 2)
            else:
                aws_tools.debug(f"+++ Unexpected error: {err}", 2)
            print(f"ERROR: Unexpected error listing S3 objects: {err}")
            sys.exit(7)

    def load_information_from_file(self, log_key):
        """Load data from a WAF log file."""

        def json_event_generator(data):
            while data:
                json_data, json_index = decoder.raw_decode(data)
                data = data[json_index:]
                yield json_data

        content = []
        decoder = json.JSONDecoder()
        file_structure_error_shown = False
        with self.decompress_file(self.bucket, log_key=log_key) as f:
            for line in f.readlines():
                try:
                    for event in json_event_generator(line.rstrip()):
                        event['source'] = 'waf'
                        try:
                            headers = {}
                            for element in event['httpRequest']['headers']:
                                name = element["name"]
                                if name.lower() in self.standard_http_headers:
                                    headers[name] = element["value"]
                            event['httpRequest']['headers'] = headers
                        except (KeyError, TypeError):
                            if not file_structure_error_shown:
                                print(f"ERROR: the {log_key} file doesn't have the expected structure.")
                                file_structure_error_shown = True
                            if not self.skip_on_error:
                                sys.exit(9)
                        content.append(event)

                except json.JSONDecodeError:
                    print("ERROR: Events from {} file could not be loaded.".format(log_key.split('/')[-1]))
                    if not self.skip_on_error:
                        sys.exit(9)

        return json.loads(json.dumps(content))

    def get_service_prefix(self, account_id):
        return AWSLogsBucket.get_service_prefix(self, account_id)
        
    def get_full_prefix(self, account_id, account_region, acl_name=None):
        if self.type == WAF_NATIVE:
            if self.waf_acls:
                return AWSLogsBucket.get_full_prefix(self, account_id, account_region, self.waf_acls)
            else: 
                aws_tools.debug(f"+++ WARNING: No waf_acls parameter found, no log will be fetched", 1)
                sys.exit(9)
        else:
            return self.prefix

    def get_base_prefix(self):
        if self.type == WAF_NATIVE:
            return AWSLogsBucket.get_base_prefix(self)
        else:
            return self.prefix

    def build_s3_filter_args(self, aws_account_id, aws_region, acl_name=None, iterating=False, custom_delimiter='',
                             **kwargs):
        filter_marker = ''
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
                    'prefix': f'{self.prefix}%',
                    'aws_account_id': aws_account_id,
                    **kwargs
                })
            try:
                filter_marker = query_last_key.fetchone()[1]
            except (TypeError, IndexError):
                # if DB is empty for a region
                filter_marker = self.marker_only_logs_after(aws_region, aws_account_id) if self.only_logs_after \
                    else self.marker_custom_date(aws_region, aws_account_id, self.default_date)

        filter_args = {
            'Bucket': self.bucket,
            'MaxKeys': 1000,
            'Prefix': self.get_full_prefix(aws_account_id, aws_region)
        }

        if acl_name:
            filter_args['Prefix'] += f'{acl_name}/'

        # if nextContinuationToken is not used for processing logs in a bucket
        if not iterating:
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

    def iter_regions_and_accounts(self, account_id, regions):
        if self.type == WAF_NATIVE:
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
                    if self.waf_acls:
                        if isinstance(self.waf_acls, str):
                            self.waf_acls = [acl.strip() for acl in self.waf_acls.split(',')]
                            for acl_name in self.waf_acls:
                                aws_tools.debug("+++ Working on {} - {} - ACL: {}".format(aws_account_id, aws_region,
                                                                                          acl_name), 1) 
                                self.get_full_prefix(aws_account_id, aws_region, acl_name)
                                self.iter_files_in_bucket(aws_account_id, aws_region, acl_name)
                                self.db_maintenance(
                                    aws_account_id=aws_account_id,
                                    aws_region=aws_region,
                                    acl_name=acl_name
                                )                                
                    else: 
                        self.get_full_prefix(aws_account_id, aws_region)
        else:
            print(WAF_DEPRECATED_MESSAGE.format(release="5.0", url=WAF_URL))
            self.check_prefix = True
            AWSCustomBucket.iter_regions_and_accounts(self, account_id, regions)

    def iter_files_in_bucket(self, aws_account_id=None, aws_region=None, acl_name=None, **kwargs):
        if aws_account_id is None:
            aws_account_id = self.aws_account_id
        try:
            if acl_name is None:
                bucket_files = self.client.list_objects_v2(
                    **self.build_s3_filter_args(aws_account_id, aws_region, **kwargs)
                )
            else:
                bucket_files = self.client.list_objects_v2(
                    **self.build_s3_filter_args(aws_account_id, aws_region, acl_name, **kwargs)
                )
            if self.reparse:
                aws_tools.debug('++ Reparse mode enabled', 2)

            while True:
                if 'Contents' not in bucket_files:
                    self._print_no_logs_to_process_message(self.bucket, aws_account_id, aws_region, **kwargs)
                    return

                processed_logs = 0

                for bucket_file in self._filter_bucket_files(bucket_files['Contents'], **kwargs):

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
            print(f"ERROR: {error_message}")
            exit(exit_number)

        except Exception as err:
            if hasattr(err, 'message'):
                aws_tools.debug(f"+++ Unexpected error: {err.message}", 2)
            else:
                aws_tools.debug(f"+++ Unexpected error: {err}", 2)
            print(f"ERROR: Unexpected error querying/working with objects in S3: {err}")
            sys.exit(7)
