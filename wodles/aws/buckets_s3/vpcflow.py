# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import csv
import sys
from os import path
from typing import Iterator
from aws_bucket import AWSLogsBucket
try:
    import boto3
except ImportError:
    print('ERROR: boto3 module is required.')
    sys.exit(4)

import operator
from datetime import datetime

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))
import aws_tools


class AWSVPCFlowBucket(AWSLogsBucket):
    """
    Represents a bucket with AWS VPC logs
    """

    empty_bucket_message_template = (
        "+++ No logs to process for {flow_log_id} flow log ID in bucket: {aws_account_id}/{aws_region}"
    )
    empty_bucket_message_template_without_log_id = "+++ No logs to process in bucket: {aws_account_id}/{aws_region}"

    def __init__(self, **kwargs):
        kwargs['db_table_name'] = 'vpcflow'
        AWSLogsBucket.__init__(self, **kwargs)
        self.service = 'vpcflowlogs'
        self.profile_name = kwargs['profile']
        # SQL queries for VPC must be after constructor call
        self.sql_already_processed = """
            SELECT
                count(*)
            FROM
                {table_name}
            WHERE
                bucket_path=:bucket_path AND
                aws_account_id=:aws_account_id AND
                aws_region=:aws_region AND
                flow_log_id=:flow_log_id AND
                log_key=:log_key;"""

        self.sql_mark_complete = """
            INSERT INTO {table_name} (
                bucket_path,
                aws_account_id,
                aws_region,
                flow_log_id,
                log_key,
                processed_date,
                created_date)
            VALUES (
                :bucket_path,
                :aws_account_id,
                :aws_region,
                :flow_log_id,
                :log_key,
                DATETIME('now'),
                :created_date);"""

        self.sql_create_table = """
            CREATE TABLE {table_name} (
                bucket_path 'text' NOT NULL,
                aws_account_id 'text' NOT NULL,
                aws_region 'text' NOT NULL,
                flow_log_id 'text' NOT NULL,
                log_key 'text' NOT NULL,
                processed_date 'text' NOT NULL,
                created_date 'integer' NOT NULL,
                PRIMARY KEY (bucket_path, aws_account_id, aws_region, flow_log_id, log_key));"""

        self.sql_find_last_key_processed = """
            SELECT
                log_key
            FROM
                {table_name}
            WHERE
                bucket_path=:bucket_path AND
                aws_account_id=:aws_account_id AND
                aws_region = :aws_region AND
                flow_log_id = :flow_log_id AND
                log_key LIKE :prefix
            ORDER BY
                log_key DESC
            LIMIT 1;"""

        self.sql_db_maintenance = """
            DELETE FROM {table_name}
            WHERE
                bucket_path=:bucket_path AND
                aws_account_id=:aws_account_id AND
                aws_region=:aws_region AND
                flow_log_id=:flow_log_id AND
                log_key <= (SELECT log_key
                    FROM
                        {table_name}
                    WHERE
                        bucket_path=:bucket_path AND
                        aws_account_id=:aws_account_id AND
                        aws_region=:aws_region AND
                        flow_log_id=:flow_log_id
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
                aws_region=:aws_region AND
                flow_log_id=:flow_log_id;"""

    def load_information_from_file(self, log_key):
        with self.decompress_file(self.bucket, log_key=log_key) as f:
            fieldnames = (
                "version", "account_id", "interface_id", "srcaddr", "dstaddr", "srcport", "dstport", "protocol",
                "packets", "bytes", "start", "end", "action", "log_status")
            unix_fields = ('start', 'end')
            result = []

            tsv_file = csv.DictReader(f, fieldnames=fieldnames, delimiter=' ')

            # Transform UNIX timestamp to ISO8601
            for row in tsv_file:
                for key, value in row.items():
                    if key in unix_fields and value not in unix_fields:
                        row[key] = datetime.utcfromtimestamp(int(value)).strftime('%Y-%m-%dT%H:%M:%SZ')

                result.append(dict(row, source='vpc'))

            return result

    def get_ec2_client(self, region, profile_name=None):
        conn_args = {}
        conn_args['region_name'] = region

        if profile_name is not None:
            conn_args['profile_name'] = profile_name

        boto_session = boto3.Session(**conn_args)

        if region not in aws_tools.ALL_REGIONS:
            raise ValueError(f"Invalid region '{region}'")

        try:
            ec2_client = boto_session.client(service_name='ec2', **self.connection_config)
        except Exception as e:
            aws_tools.error("Error getting EC2 client: {}".format(e))
            sys.exit(3)

        return ec2_client

    def get_flow_logs_ids(self, region, account_id, profile_name=None):
        try:
            ec2_client = self.get_ec2_client(region, profile_name=profile_name)
            return list(map(operator.itemgetter('FlowLogId'), ec2_client.describe_flow_logs()['FlowLogs']))
        except ValueError:
            aws_tools.debug(
                self.empty_bucket_message_template_without_log_id.format(aws_account_id=account_id, aws_region=region),
                msg_level=1
            )
            aws_tools.debug(
                f"+++ WARNING: Check the provided region: '{region}'. It's an invalid one.", msg_level=1
            )
            return []

    def already_processed(self, downloaded_file, aws_account_id, aws_region, flow_log_id):
        cursor = self.db_cursor.execute(self.sql_already_processed.format(table_name=self.db_table_name), {
            'bucket_path': self.bucket_path,
            'aws_account_id': aws_account_id,
            'aws_region': aws_region,
            'flow_log_id': flow_log_id,
            'log_key': downloaded_file})
        return cursor.fetchone()[0] > 0

    def iter_regions_and_accounts(self, account_id, regions):
        if not account_id:
            # No accounts provided, so find which exist in s3 bucket
            account_id = self.find_account_ids()
        for aws_account_id in account_id:
            # No regions provided, so find which exist for this AWS account
            if not regions:
                regions = self.find_regions(aws_account_id)
                if regions == []:
                    continue
            for aws_region in regions:
                aws_tools.debug("+++ Working on {} - {}".format(aws_account_id, aws_region), 1)
                # get flow log ids for the current region
                flow_logs_ids = self.get_flow_logs_ids(
                    aws_region, aws_account_id, profile_name=self.profile_name
                )
                # for each flow log id
                for flow_log_id in flow_logs_ids:
                    self.iter_files_in_bucket(aws_account_id, aws_region, flow_log_id=flow_log_id)
                    self.db_maintenance(aws_account_id, aws_region, flow_log_id)

    def db_count_region(self, aws_account_id, aws_region, flow_log_id):
        """Counts the number of rows in DB for a region
        :param aws_account_id: AWS account ID
        :type aws_account_id: str
        :param aws_region: AWS region
        :type aws_region: str
        :param flow_log_id: Flow log ID
        :type flow_log_id: str
        :rtype: int
        """
        query_count_region = self.db_cursor.execute(
            self.sql_count_region.format(table_name=self.db_table_name), {
                'bucket_path': self.bucket_path,
                'aws_account_id': aws_account_id,
                'aws_region': aws_region,
                'flow_log_id': flow_log_id,
                'retain_db_records': self.retain_db_records})
        return query_count_region.fetchone()[0]

    def db_maintenance(self, aws_account_id=None, aws_region=None, flow_log_id=None):
        aws_tools.debug("+++ DB Maintenance", 1)
        try:
            if self.db_count_region(aws_account_id, aws_region, flow_log_id) > self.retain_db_records:
                self.db_cursor.execute(self.sql_db_maintenance.format(table_name=self.db_table_name), {
                    'bucket_path': self.bucket_path,
                    'aws_account_id': aws_account_id,
                    'aws_region': aws_region,
                    'flow_log_id': flow_log_id,
                    'retain_db_records': self.retain_db_records})
        except Exception as e:
            aws_tools.error(f"Failed to execute DB cleanup - AWS Account ID: {aws_account_id}  Region: {aws_region}: {e}")

    def _filter_bucket_files(self, bucket_files: list, **kwargs) -> Iterator[dict]:
        """Filter bucket files that contain the flow_log_id in the filename.
        Parameters
        ----------
        bucket_files : list
            Bucket files to filter.
        Yields
        ------
        Iterator[str]
            A bucket file that matches the filter.
        """
        flow_log_id = kwargs["flow_log_id"]
        for bucket_file in super()._filter_bucket_files(bucket_files, **kwargs):
            if flow_log_id in bucket_file["Key"]:
                yield bucket_file

    def mark_complete(self, aws_account_id, aws_region, log_file, flow_log_id):
        if self.reparse:
            if self.already_processed(log_file['Key'], aws_account_id, aws_region, flow_log_id):
                aws_tools.debug(
                    '+++ File already marked complete, but reparse flag set: {log_key}'.format(log_key=log_file['Key']),
                    2)
        else:
            try:
                self.db_cursor.execute(self.sql_mark_complete.format(table_name=self.db_table_name), {
                    'bucket_path': self.bucket_path,
                    'aws_account_id': aws_account_id,
                    'aws_region': aws_region,
                    'flow_log_id': flow_log_id,
                    'log_key': log_file['Key'],
                    'created_date': self.get_creation_date(log_file)})
            except Exception as e:
                aws_tools.debug("+++ Error marking log {} as completed: {}".format(log_file['Key'], e), 2)
