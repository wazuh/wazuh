# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import re
import sys
from os import path
import json
from aws_bucket import AWSBucket, AWSCustomBucket, AWSLogsBucket

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))
import aws_tools

GUARDDUTY_URL = 'https://documentation.wazuh.com/current/amazon/services/supported-services/guardduty.html'
GUARDDUTY_DEPRECATED_MESSAGE = 'The functionality to process GuardDuty logs stored in S3 via Kinesis was deprecated ' \
                               'in {release}. Consider configuring GuardDuty to store its findings directly in an S3 ' \
                               'bucket instead. Check {url} for more information.'


class AWSGuardDutyBucket(AWSCustomBucket):

    def __init__(self, **kwargs):
        kwargs['db_table_name'] = 'guardduty'
        AWSCustomBucket.__init__(self, **kwargs)

        self.service = 'GuardDuty'
        if self.check_guardduty_type():
            self.type = "GuardDutyNative"
            self.empty_bucket_message_template = AWSBucket.empty_bucket_message_template
        else:
            self.type = "GuardDutyKinesis"

        # The table has no region column, so the keys of a region are the ones of its full prefix
        self.sql_count_prefix = """
            SELECT
                count(*)
            FROM
                {table_name}
            WHERE
                bucket_path=:bucket_path AND
                aws_account_id=:aws_account_id AND
                log_key LIKE :prefix;"""

        self.sql_db_maintenance_prefix = """
            DELETE FROM {table_name}
            WHERE
                bucket_path=:bucket_path AND
                aws_account_id=:aws_account_id AND
                log_key LIKE :prefix AND
                log_key <=
                (SELECT log_key
                    FROM
                        {table_name}
                    WHERE
                        bucket_path=:bucket_path AND
                        aws_account_id=:aws_account_id AND
                        log_key LIKE :prefix
                    ORDER BY
                        log_key DESC
                    LIMIT 1
                    OFFSET :retain_db_records);"""

    def check_guardduty_type(self):
        try:
            return \
                    'CommonPrefixes' in self.client.list_objects_v2(Bucket=self.bucket, Prefix=f'{self.prefix}AWSLogs',
                                                                    Delimiter='/', MaxKeys=1)
        except Exception as err:
            if hasattr(err, 'message'):
                aws_tools.debug(f"+++ Unexpected error: {err.message}", 2)
            else:
                aws_tools.debug(f"+++ Unexpected error: {err}", 2)
            aws_tools.error(f"Unexpected error querying/working with objects in S3: {err}")
            sys.exit(7)

    def get_service_prefix(self, account_id):
        return AWSLogsBucket.get_service_prefix(self, account_id)

    def get_full_prefix(self, account_id, account_region):
        if self.type == "GuardDutyNative":
            return AWSLogsBucket.get_full_prefix(self, account_id, account_region)
        else:
            return self.prefix

    def get_base_prefix(self):
        if self.type == "GuardDutyNative":
            return AWSLogsBucket.get_base_prefix(self)
        else:
            return self.prefix

    def already_processed(self, downloaded_file, aws_account_id, aws_region, **kwargs):
        if self.type == "GuardDutyNative":
            cursor = self.db_cursor.execute(
                self.sql_already_processed.format(table_name=self.db_table_name), {
                    'bucket_path': self.bucket_path,
                    'aws_account_id': aws_account_id,
                    'log_key': downloaded_file})
            return cursor.fetchone()[0] > 0
        return AWSCustomBucket.already_processed(self, downloaded_file, aws_account_id, aws_region, **kwargs)

    def build_s3_filter_args(self, aws_account_id, aws_region, iterating=False, custom_delimiter='', **kwargs):
        filter_args = AWSCustomBucket.build_s3_filter_args(
            self, aws_account_id, aws_region, iterating, custom_delimiter, **kwargs)

        if self.type == "GuardDutyNative" and not iterating and 'StartAfter' in filter_args:
            start_after = filter_args['StartAfter']
            match = re.match(r'(.*?/GuardDuty/[^/]+/\d{4}/\d{2}/\d{2}/)', start_after)
            if match:
                filter_args['StartAfter'] = match.group(1)
                aws_tools.debug(f"+++ GuardDuty: Rewound marker to day folder: {filter_args['StartAfter']}", 2)

        return filter_args

    def iter_regions_and_accounts(self, account_id, regions):
        if self.type == "GuardDutyNative":
            AWSBucket.iter_regions_and_accounts(self, account_id, regions)
        else:
            print(GUARDDUTY_DEPRECATED_MESSAGE.format(release="4.5", url=GUARDDUTY_URL))
            self.check_prefix = True
            AWSCustomBucket.iter_regions_and_accounts(self, account_id, regions)

    def db_maintenance(self, aws_account_id=None, aws_region=None, **kwargs):
        """Delete the processed keys beyond the retention.

        The marker of a region is one of its own keys, so the retention of the native type applies to the keys of each
        region. Otherwise, the regions whose keys sort first would lose all of them and process their files again.
        """
        if self.type != "GuardDutyNative":
            AWSCustomBucket.db_maintenance(self, aws_account_id, **kwargs)
            return

        aws_tools.debug("+++ DB Maintenance", 1)
        aws_account_id = aws_account_id if aws_account_id else self.aws_account_id
        params = {
            'bucket_path': self.bucket_path,
            'aws_account_id': aws_account_id,
            'prefix': f'{self.get_full_prefix(aws_account_id, aws_region)}%',
            'retain_db_records': self.retain_db_records}
        try:
            if self.db_cursor.execute(self.sql_count_prefix.format(table_name=self.db_table_name),
                                      params).fetchone()[0] > self.retain_db_records:
                self.db_cursor.execute(self.sql_db_maintenance_prefix.format(table_name=self.db_table_name), params)
        except Exception as e:
            aws_tools.error(f"Failed to execute DB cleanup - AWS Account ID: {aws_account_id}  Region: {aws_region}: {e}")

    def send_event(self, event):
        # Send the message (splitted if it is necessary)
        for msg in self.reformat_msg(event):
            self.send_msg(msg)

    def reformat_msg(self, event):
        aws_tools.debug('++ Reformat message', 3)
        if event['aws']['source'] == 'guardduty' and 'service' in event['aws'] and \
                'action' in event['aws']['service'] and \
                'portProbeAction' in event['aws']['service']['action'] and \
                'portProbeDetails' in event['aws']['service']['action']['portProbeAction'] and \
                len(event['aws']['service']['action']['portProbeAction']['portProbeDetails']) > 1:

            port_probe_details = event['aws']['service']['action']['portProbeAction']['portProbeDetails']
            for detail in port_probe_details:
                event['aws']['service']['action']['portProbeAction']['portProbeDetails'] = detail
                yield event
        else:
            AWSBucket.reformat_msg(self, event)
            yield event

    def load_information_from_file(self, log_key):
        if log_key.endswith('.jsonl.gz'):
            with self.decompress_file(self.bucket, log_key=log_key) as f:
                json_list = list(f)
                result = []
                for json_item in json_list:
                    x = json.loads(json_item)
                    result.append(dict(x, source=x['service']['serviceName']))
                return result
        else:
            return AWSCustomBucket.load_information_from_file(self, log_key)
