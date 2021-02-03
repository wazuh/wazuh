#!/usr/bin/env python

# Import AWS S3
#
# Copyright (C) 2015-2020, Wazuh Inc.
# Copyright: GPLv3
#
# Updated by Jeremy Phillips <jeremy@uranusbytes.com>
#
# Error Codes:
#   1 - Unknown
#   2 - SIGINT
#   3 - Invalid credentials to access S3 bucket
#   4 - boto3 module missing
#   5 - Unexpected error accessing SQLite DB
#   6 - Unable to create SQLite DB
#   7 - Unexpected error querying/working with objects in S3
#   8 - Failed to decompress file
#   9 - Failed to parse file
#   10 - Failed to execute DB cleanup
#   11 - Unable to connect to Wazuh
#   12 - Invalid type of bucket
#   13 - Unexpected error sending message to Wazuh
#   14 - Empty bucket

import signal
import sys
import sqlite3
import argparse
import socket

try:
    import boto3
except ImportError:
    print('ERROR: boto3 module is required.')
    sys.exit(4)
import botocore
import json
import csv
import gzip
import zipfile
import re
import io
from os import path
import operator
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from time import mktime

# Python 2/3 compatibility
if sys.version_info[0] == 3:
    unicode = str

################################################################################
# Constants
################################################################################

# Enable/disable debug mode
debug_level = 0


################################################################################
# Classes
################################################################################


class WazuhIntegration:
    """
    Class with common methods
    :param access_key: AWS access key id
    :param secret_key: AWS secret access key
    :param aws_profile: AWS profile
    :param iam_role_arn: IAM Role
    :param service name: Name of the service (s3 for services which stores logs in buckets)
    :param region: Region of service
    :param bucket: Bucket name to extract logs from
    """

    def __init__(self, access_key, secret_key, aws_profile, iam_role_arn,
                 service_name=None, region=None, bucket=None):
        # SQL queries
        self.sql_find_table_names = """
                            SELECT
                                tbl_name
                            FROM
                                sqlite_master
                            WHERE
                                type='table';"""

        self.sql_db_optimize = "PRAGMA optimize;"

        self.sql_create_metadata_table = """
                                        CREATE table
                                            metadata (
                                            key 'text' NOT NULL,
                                            value 'text' NOT NULL,
                                            PRIMARY KEY (key, value));
                                        """

        self.sql_get_metadata_version = """
                                        SELECT
                                            value
                                        FROM
                                            metadata
                                        WHERE
                                            key='version';
                                        """

        self.sql_find_table = """
                                SELECT
                                    tbl_name
                                FROM
                                    sqlite_master
                                WHERE
                                    type='table' AND
                                    name='{name}';
                                """

        self.sql_insert_version_metadata = """
                                        INSERT INTO metadata (
                                            key,
                                            value)
                                        VALUES (
                                            'version',
                                            '{wazuh_version}');"""

        self.sql_update_version_metadata = """
                                        UPDATE
                                            metadata
                                        SET
                                            value='{wazuh_version}'
                                        WHERE
                                            key='version';
                                        """

        self.sql_drop_table = """
                            DROP TABLE {table};
                            """

        # get path and version from ossec.init.conf
        with open('/etc/ossec-init.conf') as f:
            lines = f.readlines()
            re_ossec_init = re.compile(r'^([A-Z]+)={1}"{1}([\w\/.]+)"{1}$')
            self.wazuh_path = re.search(re_ossec_init, lines[0]).group(2)
            self.wazuh_version = re.search(re_ossec_init, lines[2]).group(2)
        self.wazuh_queue = '{0}/queue/ossec/queue'.format(self.wazuh_path)
        self.wazuh_wodle = '{0}/wodles/aws'.format(self.wazuh_path)
        self.msg_header = "1:Wazuh-AWS:"
        # GovCloud regions
        self.gov_regions = {'us-gov-east-1', 'us-gov-west-1'}
        self.client = self.get_client(access_key=access_key,
                                      secret_key=secret_key,
                                      profile=aws_profile,
                                      iam_role_arn=iam_role_arn,
                                      service_name=service_name,
                                      bucket=bucket,
                                      region=region
                                      )

        # db_name is an instance variable of subclass
        self.db_path = "{0}/{1}.db".format(self.wazuh_wodle, self.db_name)
        self.db_connector = sqlite3.connect(self.db_path)
        self.db_cursor = self.db_connector.cursor()
        if bucket:
            self.bucket = bucket
        self.old_version = None  # for DB migration if it is necessary
        self.check_metadata_version()

    def migrate_from_38(self, **kwargs):
        self.db_maintenance(**kwargs)
        self.db_connector.commit()

    def migrate(self, **kwargs):
        regex_version = re.compile(r'^v?(\d.\d){1}')
        old_version = re.search(regex_version, self.old_version).group(1).replace('.', '')
        current_version = re.search(regex_version, self.wazuh_version).group(1).replace('.', '')
        if old_version < current_version:
            migration_method_name = 'migrate_from_{}'.format(old_version)
            if hasattr(self, migration_method_name):
                migration_method = getattr(self, migration_method_name)
                # do migration from 3.8 version
                if old_version == '38':
                    migration_method(**kwargs)

    def check_metadata_version(self):
        try:
            query_metadata = self.db_connector.execute(self.sql_find_table.format(name='metadata'))
            metadata = True if query_metadata.fetchone() else False
            if metadata:
                query_version = self.db_connector.execute(self.sql_get_metadata_version)
                metadata_version = query_version.fetchone()[0]
                # update Wazuh version in metadata table
                if metadata_version != self.wazuh_version:
                    self.old_version = metadata_version
                    self.db_connector.execute(self.sql_update_version_metadata.format(wazuh_version=self.wazuh_version))
                    self.db_connector.commit()
            else:
                # create metadate table
                self.db_connector.execute(self.sql_create_metadata_table)
                # insert wazuh version value
                self.db_connector.execute(self.sql_insert_version_metadata.format(wazuh_version=self.wazuh_version))
                self.db_connector.commit()
                # delete old tables if its exist
                self.delete_deprecated_tables()
        except Exception as e:
            print('ERROR: Error creating metadata table: {}'.format(e))
            sys.exit(5)

    def delete_deprecated_tables(self):
        query_tables = self.db_connector.execute(self.sql_find_table_names)
        tables = query_tables.fetchall()
        for table in tables:
            if 'log_progress' in table:
                self.db_connector.execute(self.sql_drop_table.format(table='log_progress'))
            elif 'trail_progress' in table:
                self.db_connector.execute(self.sql_drop_table.format(table='trail_progress'))

    def get_client(self, access_key, secret_key, profile, iam_role_arn, service_name, bucket, region=None):
        conn_args = {}

        if access_key is not None and secret_key is not None:
            conn_args['aws_access_key_id'] = access_key
            conn_args['aws_secret_access_key'] = secret_key

        if profile is not None:
            conn_args['profile_name'] = profile

        # set region name
        if region and service_name == 'inspector':
            conn_args['region_name'] = region
        else:
            # it is necessary to set region_name for GovCloud regions
            conn_args['region_name'] = region if region in self.gov_regions \
                else None

        boto_session = boto3.Session(**conn_args)

        # If using a role, create session using that
        try:
            if iam_role_arn:
                sts_client = boto_session.client('sts')
                sts_role_assumption = sts_client.assume_role(RoleArn=iam_role_arn,
                                                             RoleSessionName='WazuhLogParsing'
                                                             )
                sts_session = boto3.Session(aws_access_key_id=sts_role_assumption['Credentials']['AccessKeyId'],
                                            aws_secret_access_key=sts_role_assumption['Credentials']['SecretAccessKey'],
                                            aws_session_token=sts_role_assumption['Credentials']['SessionToken'],
                                            region_name=conn_args.get('region_name')
                                            )
                client = sts_session.client(service_name='logs' if service_name == 'cloudwatchlogs' else service_name)
            elif service_name == 'cloudwatchlogs':
                client = boto3.client('logs', region_name=region,
                                      aws_access_key_id=access_key, aws_secret_access_key=secret_key)
            else:
                client = boto_session.client(service_name=service_name)
        except botocore.exceptions.ClientError as e:
            print("ERROR: Access error: {}".format(e))
            sys.exit(3)
        return client

    def get_sts_client(self, access_key, secret_key, profile=None):
        conn_args = {}
        if access_key is not None and secret_key is not None:
            conn_args['aws_access_key_id'] = access_key
            conn_args['aws_secret_access_key'] = secret_key
        elif profile is not None:
            conn_args['profile_name'] = profile

        boto_session = boto3.Session(**conn_args)

        try:
            sts_client = boto_session.client(service_name='sts')
        except Exception as e:
            print("Error getting STS client: {}".format(e))
            sys.exit(3)

        return sts_client

    def send_msg(self, msg, dump_json=True):
        """
        Sends an AWS event to the Wazuh Queue

        :param msg: JSON message to be sent.
        :para dump_json: If json.dumps should be applied to the msg
        """
        try:
            json_msg = json.dumps(msg, default=str)
            debug(json_msg, 3)
            s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            s.connect(self.wazuh_queue)
            s.send("{header}{msg}".format(header=self.msg_header,
                                          msg=json_msg if dump_json else msg).encode())
            s.close()
        except socket.error as e:
            if e.errno == 111:
                print("ERROR: Wazuh must be running.")
                sys.exit(11)
            elif e.errno == 90:
                print("ERROR: Message too long to send to Wazuh.  Skipping message...")
                debug(
                    '+++ ERROR: Message longer than buffer socket for Wazuh.  Consider increasing rmem_max  Skipping message...',
                    1)
            else:
                print("ERROR: Error sending message to wazuh: {}".format(e))
                sys.exit(13)
        except Exception as e:
            print("ERROR: Error sending message to wazuh: {}".format(e))
            sys.exit(13)

    def create_table(self, sql_create_table):
        """
        :param sql_create_table: SQL query to create the table
        """
        try:
            debug('+++ Table does not exist; create', 1)
            self.db_connector.execute(sql_create_table)
        except Exception as e:
            print("ERROR: Unable to create SQLite DB: {}".format(e))
            sys.exit(6)

    def init_db(self, sql_create_table):
        """
        :param sql_create_table: SQL query to create the table
        """
        try:
            tables = set(map(operator.itemgetter(0), self.db_connector.execute(self.sql_find_table_names)))
        except Exception as e:
            print("ERROR: Unexpected error accessing SQLite DB: {}".format(e))
            sys.exit(5)
        # if table does not exist, create a new table
        if self.db_table_name not in tables:
            self.create_table(sql_create_table)

    def close_db(self):
        self.db_connector.commit()
        self.db_connector.execute(self.sql_db_optimize)
        self.db_connector.close()


class AWSBucket(WazuhIntegration):
    """
    Represents a bucket with events on the inside.

    This is an abstract class
    """

    def __init__(self, reparse, access_key, secret_key, profile, iam_role_arn,
                 bucket, only_logs_after, skip_on_error, account_alias,
                 prefix, delete_file, aws_organization_id, region):
        """
        AWS Bucket constructor.

        :param reparse: Wether to parse already parsed logs or not
        :param access_key: AWS access key id
        :param secret_key: AWS secret access key
        :param profile: AWS profile
        :param iam_role_arn: IAM Role
        :param bucket: Bucket name to extract logs from
        :param only_logs_after: Date after which obtain logs.
        :param skip_on_error: Wether to continue processing logs or stop when an error takes place
        :param account_alias: Alias of the AWS account where the bucket is.
        :param prefix: Prefix to filter files in bucket
        :param delete_file: Wether to delete an already processed file from a bucket or not
        :param aws_organization_id: The AWS organization ID
        """

        # common SQL queries
        self.sql_already_processed = """
                          SELECT
                            count(*)
                          FROM
                            {table_name}
                          WHERE
                            bucket_path='{bucket_path}' AND
                            aws_account_id='{aws_account_id}' AND
                            aws_region='{aws_region}' AND
                            log_key='{log_name}';"""

        self.sql_mark_complete = """
                            INSERT INTO {table_name} (
                                bucket_path,
                                aws_account_id,
                                aws_region,
                                log_key,
                                processed_date,
                                created_date) VALUES (
                                '{bucket_path}',
                                '{aws_account_id}',
                                '{aws_region}',
                                '{log_key}',
                                DATETIME('now'),
                                '{created_date}');"""

        self.sql_create_table = """
                            CREATE TABLE
                                {table_name} (
                                bucket_path 'text' NOT NULL,
                                aws_account_id 'text' NOT NULL,
                                aws_region 'text' NOT NULL,
                                log_key 'text' NOT NULL,
                                processed_date 'text' NOT NULL,
                                created_date 'integer' NOT NULL,
                                PRIMARY KEY (bucket_path, aws_account_id, aws_region, log_key));"""

        self.sql_find_last_log_processed = """
                                        SELECT
                                            created_date
                                        FROM
                                            {table_name}
                                        WHERE
                                            bucket_path='{bucket_path}' AND
                                            aws_account_id='{aws_account_id}' AND
                                            aws_region ='{aws_region}'
                                        ORDER BY
                                            created_date DESC
                                        LIMIT 1;"""

        self.sql_find_last_key_processed = """
                                        SELECT
                                            log_key
                                        FROM
                                            {table_name}
                                        WHERE
                                            bucket_path='{bucket_path}' AND
                                            aws_account_id='{aws_account_id}' AND
                                            aws_region = '{aws_region}'
                                        ORDER BY
                                            log_key ASC
                                        LIMIT 1;"""

        self.sql_db_maintenance = """DELETE
                            FROM
                                {table_name}
                            WHERE
                                bucket_path='{bucket_path}' AND
                                aws_account_id='{aws_account_id}' AND
                                aws_region='{aws_region}' AND
                                log_key <=
                                (SELECT log_key
                                    FROM
                                    {table_name}
                                    WHERE
                                        bucket_path='{bucket_path}' AND
                                        aws_account_id='{aws_account_id}' AND
                                        aws_region='{aws_region}'
                                    ORDER BY
                                        log_key DESC
                                    LIMIT 1
                                    OFFSET {retain_db_records});"""

        self.sql_count_region = """
                                SELECT
                                    count(*)
                                FROM
                                    {table_name}
                                WHERE
                                    bucket_path='{bucket_path}' AND
                                    aws_account_id='{aws_account_id}' AND
                                    aws_region='{aws_region}';"""

        self.db_name = 's3_cloudtrail'
        WazuhIntegration.__init__(self, access_key=access_key,
                                  secret_key=secret_key,
                                  aws_profile=profile,
                                  iam_role_arn=iam_role_arn,
                                  bucket=bucket,
                                  service_name='s3',
                                  region=region
                                  )
        self.retain_db_records = 500
        self.reparse = reparse
        self.only_logs_after = datetime.strptime(only_logs_after, "%Y%m%d")
        self.skip_on_error = skip_on_error
        self.account_alias = account_alias
        self.prefix = prefix
        self.delete_file = delete_file
        self.bucket_path = self.bucket + '/' + self.prefix
        self.aws_organization_id = aws_organization_id

    def already_processed(self, downloaded_file, aws_account_id, aws_region):
        cursor = self.db_connector.execute(self.sql_already_processed.format(
            bucket_path=self.bucket_path,
            table_name=self.db_table_name,
            aws_account_id=aws_account_id,
            aws_region=aws_region,
            log_name=downloaded_file
        ))
        return cursor.fetchone()[0] > 0

    def get_creation_date(self, log_key):
        raise NotImplementedError

    def mark_complete(self, aws_account_id, aws_region, log_file):
        if self.reparse:
            if self.already_processed(log_file['Key'], aws_account_id, aws_region):
                debug(
                    '+++ File already marked complete, but reparse flag set: {log_key}'.format(log_key=log_file['Key']),
                    2)
        else:
            try:
                self.db_connector.execute(self.sql_mark_complete.format(
                    bucket_path=self.bucket_path,
                    table_name=self.db_table_name,
                    aws_account_id=aws_account_id,
                    aws_region=aws_region,
                    log_key=log_file['Key'],
                    created_date=self.get_creation_date(log_file)
                ))
            except Exception as e:
                debug("+++ Error marking log {} as completed: {}".format(log_file['Key'], e), 2)
                raise e

    def create_table(self):
        try:
            debug('+++ Table does not exist; create', 1)
            self.db_connector.execute(self.sql_create_table.format(table_name=self.db_table_name))
        except Exception as e:
            print("ERROR: Unable to create SQLite DB: {}".format(e))
            sys.exit(6)

    def init_db(self):
        try:
            tables = set(map(operator.itemgetter(0), self.db_connector.execute(self.sql_find_table_names)))
        except Exception as e:
            print("ERROR: Unexpected error accessing SQLite DB: {}".format(e))
            sys.exit(5)
        # DB does exist yet
        if self.db_table_name not in tables:
            self.create_table()

    def db_count_region(self, aws_account_id, aws_region):
        """Counts the number of rows in DB for a region
        :param aws_account_id: AWS account ID
        :type aws_account_id: str
        :param aws_region: AWS region
        :param aws_region: str
        :rtype: int
        """
        try:
            query_count_region = self.db_connector.execute(
                self.sql_count_region.format(
                    table_name=self.db_table_name,
                    bucket_path=self.bucket_path,
                    aws_account_id=aws_account_id,
                    aws_region=aws_region,
                    retain_db_records=self.retain_db_records
                ))
            return query_count_region.fetchone()[0]
        except Exception as e:
            print(
                "ERROR: Failed to execute DB cleanup - AWS Account ID: {aws_account_id}  Region: {aws_region}: {error_msg}".format(
                    aws_account_id=aws_account_id,
                    aws_region=aws_region,
                    error_msg=e))
            sys.exit(10)

    def db_maintenance(self, aws_account_id=None, aws_region=None):
        debug("+++ DB Maintenance", 1)
        try:
            if self.db_count_region(aws_account_id, aws_region) \
                    > self.retain_db_records:
                self.db_connector.execute(self.sql_db_maintenance.format(
                    bucket_path=self.bucket_path,
                    table_name=self.db_table_name,
                    aws_account_id=aws_account_id,
                    aws_region=aws_region,
                    retain_db_records=self.retain_db_records
                ))
        except Exception as e:
            print(
                "ERROR: Failed to execute DB cleanup - AWS Account ID: {aws_account_id}  Region: {aws_region}: {error_msg}".format(
                    aws_account_id=aws_account_id,
                    aws_region=aws_region,
                    error_msg=e))
            sys.exit(10)

    def marker_only_logs_after(self, aws_region, aws_account_id):
        return '{init}{only_logs_after}'.format(
            init=self.get_full_prefix(aws_account_id, aws_region),
            only_logs_after=self.only_logs_after.strftime('%Y/%m/%d')
        )

    def get_alert_msg(self, aws_account_id, log_key, event, error_msg=""):
        def remove_none_fields(event):
            for key, value in list(event.items()):
                if isinstance(value, dict):
                    remove_none_fields(event[key])
                elif value is None:
                    del event[key]

        # error_msg will only have a value when event is None and vice versa
        msg = {
            'integration': 'aws',
            'aws': {
                'log_info': {
                    'aws_account_alias': self.account_alias,
                    'log_file': log_key,
                    's3bucket': self.bucket
                }
            }
        }
        if event:
            remove_none_fields(event)
            msg['aws'].update(event)
        elif error_msg:
            msg['error_msg'] = error_msg
        return msg

    def get_full_prefix(self, account_id, account_region):
        raise NotImplementedError

    def build_s3_filter_args(self, aws_account_id, aws_region, iterating=False):
        filter_marker = ''
        if self.reparse:
            if self.only_logs_after:
                filter_marker = self.marker_only_logs_after(aws_region, aws_account_id)
        else:
            query_last_key = self.db_connector.execute(
                self.sql_find_last_key_processed.format(bucket_path=self.bucket_path,
                                                        table_name=self.db_table_name,
                                                        aws_account_id=aws_account_id,
                                                        aws_region=aws_region))
            try:
                last_key = query_last_key.fetchone()[0]
            except (TypeError, IndexError) as e:
                # if DB is empty for a region
                last_key = self.marker_only_logs_after(aws_region, aws_account_id)

        filter_args = {
            'Bucket': self.bucket,
            'MaxKeys': 1000,
            'Prefix': self.get_full_prefix(aws_account_id, aws_region)
        }

        # if nextContinuationToken is not used for processing logs in a bucket
        if not iterating:
            if filter_marker:
                filter_args['StartAfter'] = filter_marker
                debug('+++ Marker: {0}'.format(filter_marker), 2)
            else:
                filter_args['StartAfter'] = last_key
                debug('+++ Marker: {0}'.format(last_key), 2)

        return filter_args

    def reformat_msg(self, event):
        debug('++ Reformat message', 3)

        def single_element_list_to_dictionary(my_event):
            for name, value in list(my_event.items()):
                if isinstance(value, list) and len(value) == 1:
                    my_event[name] = value[0]
                elif isinstance(value, dict):
                    single_element_list_to_dictionary(my_event[name])

        # turn some list fields into dictionaries
        single_element_list_to_dictionary(event)

        # in order to support both old and new index pattern, change data.aws.sourceIPAddress fieldname and parse that one with type ip
        # Only add this field if the sourceIPAddress is an IP and not a DNS.
        if 'sourceIPAddress' in event['aws'] and re.match(r'\d+\.\d+.\d+.\d+', event['aws']['sourceIPAddress']):
            event['aws']['source_ip_address'] = event['aws']['sourceIPAddress']

        if 'tags' in event['aws'] and not isinstance(event['aws']['tags'], dict):
            event['aws']['tags'] = {'value': event['aws']['tags']}

        return event

    def decompress_file(self, log_key):
        def decompress_gzip(raw_object):
            # decompress gzip file in text mode.
            try:
                # Python 3
                return gzip.open(filename=raw_object, mode='rt')
            except TypeError:
                # Python 2
                return gzip.GzipFile(fileobj=raw_object, mode='r')

        raw_object = io.BytesIO(self.client.get_object(Bucket=self.bucket, Key=log_key)['Body'].read())
        if log_key[-3:] == '.gz':
            return decompress_gzip(raw_object)
        elif log_key[-4:] == '.zip':
            zipfile_object = zipfile.ZipFile(raw_object, compression=zipfile.ZIP_DEFLATED)
            return io.TextIOWrapper(zipfile_object.open(zipfile_object.namelist()[0]))
        elif log_key[-7:] == '.snappy':
            raise TypeError("Snappy compression is not supported yet.")
        else:
            return io.TextIOWrapper(raw_object)

    def load_information_from_file(self, log_key):
        """
        AWS logs are stored in different formats depending on the service:
        * A JSON with an unique field "Records" which is an array of jsons. The filename has .json extension. (Cloudtrail)
        * Multiple JSONs stored in the same line and with no separation. The filename has no extension. (GuardDuty, IAM, Macie, Inspector)
        * TSV format. The filename has no extension. Has multiple lines. (VPC)
        :param log_key: name of the log file
        :return: list of events in json format.
        """
        raise NotImplementedError

    def get_log_file(self, aws_account_id, log_key):
        def exception_handler(error_txt, error_code):
            if self.skip_on_error:
                debug("++ {}; skipping...".format(error_txt), 1)
                try:
                    error_msg = self.get_alert_msg(aws_account_id,
                                                   log_key,
                                                   None,
                                                   error_txt)
                    self.send_msg(error_msg)
                except:
                    debug("++ Failed to send message to Wazuh", 1)
            else:
                print("ERROR: {}".format(error_txt))
                sys.exit(error_code)

        try:
            return self.load_information_from_file(log_key=log_key)
        except (TypeError, IOError, zipfile.BadZipfile, zipfile.LargeZipFile) as e:
            exception_handler("Failed to decompress file {}: {}".format(log_key, e), 8)
        except (ValueError, csv.Error) as e:
            exception_handler("Failed to parse file {}: {}".format(log_key, e), 9)
        except Exception as e:
            exception_handler("Unkown error reading/parsing file {}: {}".format(log_key, e), 1)

    def iter_bucket(self, account_id, regions):
        self.init_db()
        self.iter_regions_and_accounts(account_id, regions)
        self.db_connector.commit()
        self.db_connector.execute(self.sql_db_optimize)
        self.db_connector.close()

    def iter_regions_and_accounts(self, account_id, regions):
        raise NotImplementedError

    def iter_events(self, event_list, log_key, aws_account_id):
        if event_list is not None:
            for event in event_list:
                # Parse out all the values of 'None'
                event_msg = self.get_alert_msg(aws_account_id, log_key, event)
                # Change dynamic fields to strings; truncate values as needed
                event_msg = self.reformat_msg(event_msg)
                # Send the message
                self.send_msg(event_msg)

    def iter_files_in_bucket(self, aws_account_id=None, aws_region=None):
        try:
            bucket_files = self.client.list_objects_v2(**self.build_s3_filter_args(aws_account_id, aws_region))

            if 'Contents' not in bucket_files:
                debug("+++ No logs to process in bucket: {}/{}".format(aws_account_id, aws_region), 1)
                return

            for bucket_file in bucket_files['Contents']:
                if not bucket_file['Key']:
                    continue

                if self.already_processed(bucket_file['Key'], aws_account_id, aws_region):
                    if self.reparse:
                        debug("++ File previously processed, but reparse flag set: {file}".format(
                            file=bucket_file['Key']), 1)
                    else:
                        debug("++ Skipping previously processed file: {file}".format(file=bucket_file['Key']), 1)
                        continue

                debug("++ Found new log: {0}".format(bucket_file['Key']), 2)
                # Get the log file from S3 and decompress it
                log_json = self.get_log_file(aws_account_id, bucket_file['Key'])
                self.iter_events(log_json, bucket_file['Key'], aws_account_id)
                # Remove file from S3 Bucket
                if self.delete_file:
                    debug("+++ Remove file from S3 Bucket:{0}".format(bucket_file['Key']), 2)
                    self.client.delete_object(Bucket=self.bucket, Key=bucket_file['Key'])
                self.mark_complete(aws_account_id, aws_region, bucket_file)
            # optimize DB
            self.db_maintenance(aws_account_id=aws_account_id, aws_region=aws_region)
            self.db_connector.commit()
            # iterate if there are more logs
            while bucket_files['IsTruncated']:
                new_s3_args = self.build_s3_filter_args(aws_account_id, aws_region, True)
                new_s3_args['ContinuationToken'] = bucket_files['NextContinuationToken']
                bucket_files = self.client.list_objects_v2(**new_s3_args)

                if 'Contents' not in bucket_files:
                    debug("+++ No logs to process in bucket: {}/{}".format(aws_account_id, aws_region), 1)
                    return

                for bucket_file in bucket_files['Contents']:
                    if not bucket_file['Key']:
                        continue
                    if self.already_processed(bucket_file['Key'], aws_account_id, aws_region):
                        if self.reparse:
                            debug("++ File previously processed, but reparse flag set: {file}".format(
                                file=bucket_file['Key']), 1)
                        else:
                            debug("++ Skipping previously processed file: {file}".format(file=bucket_file['Key']), 1)
                            continue
                    debug("++ Found new log: {0}".format(bucket_file['Key']), 2)
                    # Get the log file from S3 and decompress it
                    log_json = self.get_log_file(aws_account_id, bucket_file['Key'])
                    self.iter_events(log_json, bucket_file['Key'], aws_account_id)
                    # Remove file from S3 Bucket
                    if self.delete_file:
                        debug("+++ Remove file from S3 Bucket:{0}".format(bucket_file['Key']), 2)
                        self.client.delete_object(Bucket=self.bucket, Key=bucket_file['Key'])
                    self.mark_complete(aws_account_id, aws_region, bucket_file)
                # optimize DB
                self.db_maintenance(aws_account_id=aws_account_id, aws_region=aws_region)
                self.db_connector.commit()
        except SystemExit:
            raise
        except Exception as err:
            if hasattr(err, 'message'):
                debug("+++ Unexpected error: {}".format(err.message), 2)
            else:
                debug("+++ Unexpected error: {}".format(err), 2)
            print("ERROR: Unexpected error querying/working with objects in S3: {}".format(err))
            sys.exit(7)

    def check_bucket(self):
        """Check if the bucket is empty or the credentials are wrong."""
        try:
            if not 'CommonPrefixes' in self.client.list_objects_v2(Bucket=self.bucket, Prefix=self.prefix, Delimiter='/'):
                print("ERROR: No files were found in '{0}'. No logs will be processed.".format(self.bucket_path))
                exit(14)
        except botocore.exceptions.ClientError:
            print("ERROR: Invalid credentials to access S3 Bucket")
            exit(3)


class AWSLogsBucket(AWSBucket):
    """
    Abstract class for logs generated from services such as CloudTrail or Config
    """

    def get_base_prefix(self):
        base_prefix = '{}AWSLogs/'.format(self.prefix)
        if self.aws_organization_id:
            base_prefix = '{base_prefix}{aws_organization_id}/'.format(
                base_prefix=base_prefix,
                aws_organization_id=self.aws_organization_id)

        return base_prefix

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
        # AWSLogs/11111111/CloudTrail/ap-northeast-1/2018/08/10/111111_CloudTrail_ap-northeast-1_20180810T0115Z_DgrtLuV9YQvGGdN6.json.gz
        # the following line extracts this part -> 20180810
        return int(path.basename(log_file['Key']).split('_')[-2].split('T')[0])

    def get_extra_data_from_filename(self, filename):
        debug('++ Parse arguments from log file name', 2)
        filename_parts = filename.split('_')
        aws_account_id = filename_parts[0]
        aws_region = filename_parts[2]
        log_timestamp = datetime.strptime(filename_parts[3].split('.')[0], '%Y%m%dT%H%M%SZ')
        log_key = '{init}/{date_path}/{log_filename}'.format(
            init=self.get_full_prefix(aws_account_id, aws_region),
            date_path=datetime.strftime(log_timestamp, '%Y/%m/%d'),
            log_filename=filename
        )
        return aws_region, aws_account_id, log_key

    def get_alert_msg(self, aws_account_id, log_key, event, error_msg=""):
        alert_msg = AWSBucket.get_alert_msg(self, aws_account_id, log_key, event, error_msg)
        alert_msg['aws']['aws_account_id'] = aws_account_id
        return alert_msg

    def find_account_ids(self):
        try:
            return [common_prefix['Prefix'].split('/')[-2] for common_prefix in
                    self.client.list_objects_v2(Bucket=self.bucket,
                                                Prefix=self.get_base_prefix(),
                                                Delimiter='/')['CommonPrefixes']
                    ]
        except KeyError as err:
            bucket_types = {'cloudtrail', 'config', 'vpcflow', 'guardduty', 'waf', 'custom'}
            print("ERROR: Invalid type of bucket. The bucket was set up as '{}' type and this bucket does not contain log files from this type. Try with other type: {}".format(get_script_arguments().type.lower(), bucket_types - {get_script_arguments().type.lower()}))
            sys.exit(12)

    def find_regions(self, account_id):
        regions = self.client.list_objects_v2(Bucket=self.bucket,
                                              Prefix=self.get_service_prefix(account_id=account_id),
                                              Delimiter='/')

        if 'CommonPrefixes' in regions:
            return [common_prefix['Prefix'].split('/')[-2] for common_prefix in regions['CommonPrefixes']]
        else:
            debug("+++ No regions found for AWS Account {}".format(account_id), 1)
            return []

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
                if self.old_version:
                    self.migrate(aws_account_id=aws_account_id, aws_region=aws_region)
                debug("+++ Working on {} - {}".format(aws_account_id, aws_region), 1)
                self.iter_files_in_bucket(aws_account_id, aws_region)
                self.db_maintenance(aws_account_id=aws_account_id, aws_region=aws_region)

    def load_information_from_file(self, log_key):
        with self.decompress_file(log_key=log_key) as f:
            json_file = json.load(f)
            return None if self.field_to_load not in json_file else [dict(x, source=self.service.lower()) for x in
                                                                     json_file[self.field_to_load]]


class AWSCloudTrailBucket(AWSLogsBucket):
    """
    Represents a bucket with AWS CloudTrail logs
    """

    def __init__(self, **kwargs):
        self.db_table_name = 'cloudtrail'
        AWSLogsBucket.__init__(self, **kwargs)
        self.service = 'CloudTrail'
        self.field_to_load = 'Records'

    def reformat_msg(self, event):
        AWSBucket.reformat_msg(self, event)
        # Some fields in CloudTrail are dynamic in nature, which causes problems for ES mapping
        # ES mapping expects for a dictionary, if the field is any other type (list or string)
        # turn it into a dictionary
        for field_to_cast in ['additionalEventData', 'responseElements', 'requestParameters']:
            if field_to_cast in event['aws'] and not isinstance(event['aws'][field_to_cast], dict):
                event['aws'][field_to_cast] = {'string': str(event['aws'][field_to_cast])}

        if 'requestParameters' in event['aws']:
            request_parameters = event['aws']['requestParameters']
            if 'disableApiTermination' in request_parameters:
                disable_api_termination = request_parameters['disableApiTermination']
                if isinstance(disable_api_termination, bool):
                    request_parameters['disableApiTermination'] = {'value': disable_api_termination}
                elif isinstance(disable_api_termination, dict):
                    pass
                else:
                    print("WARNING: Could not reformat event {0}".format(event))

        return event


class AWSConfigBucket(AWSLogsBucket):
    """
    Represents a bucket with AWS Config logs
    """

    def __init__(self, **kwargs):
        self.db_table_name = 'config'
        AWSLogsBucket.__init__(self, **kwargs)
        self.service = 'Config'
        self.field_to_load = 'configurationItems'
        # SQL queries for AWS Config
        self.sql_find_last_key_processed_of_day = """
                                                SELECT
                                                    log_key
                                                FROM
                                                    {table_name}
                                                WHERE
                                                    bucket_path='{bucket_path}' AND
                                                    aws_account_id='{aws_account_id}' AND
                                                    aws_region = '{aws_region}' AND
                                                    created_date = {created_date}
                                                ORDER BY
                                                    log_key ASC
                                                LIMIT 1;"""

    def get_days_since_today(self, date):
        date = datetime.strptime(date, "%Y%m%d")
        # it is necessary to add one day for processing the current day
        delta = datetime.utcnow() - date + timedelta(days=1)

        return delta.days

    def get_date_list(self, aws_account_id, aws_region):
        num_days = self.get_days_since_today(self.get_date_last_log(aws_account_id, aws_region))
        date_list_time = [datetime.utcnow() - timedelta(days=x) for x in range(0, num_days)]

        return [datetime.strftime(date, "%Y/%-m/%-d") for date in reversed(date_list_time)]

    def get_date_last_log(self, aws_account_id, aws_region):
        if self.reparse:
            last_date_processed = self.only_logs_after.strftime('%Y%m%d')
        else:
            try:
                query_date_last_log = self.db_connector.execute(self.sql_find_last_log_processed.format(
                    table_name=self.db_table_name,
                    bucket_path=self.bucket_path,
                    aws_account_id=aws_account_id,
                    aws_region=aws_region))
                # query returns an integer
                last_date_processed = str(query_date_last_log.fetchone()[0])
            # if DB is empty
            except (TypeError, IndexError) as e:
                last_date_processed = self.only_logs_after.strftime('%Y%m%d')
        return last_date_processed

    def iter_regions_and_accounts(self, account_id, regions):
        # AWS Config needs to process files day by day
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
                if self.old_version:
                    self.migrate(aws_account_id=aws_account_id, aws_region=aws_region)
                debug("+++ Working on {} - {}".format(aws_account_id, aws_region), 1)
                # for processing logs day by day
                date_list = self.get_date_list(aws_account_id, aws_region)
                for date in date_list:
                    self.iter_files_in_bucket(aws_account_id, aws_region, date)
                self.db_maintenance(aws_account_id=aws_account_id, aws_region=aws_region)

    def add_zero_to_day(self, date):
        # add zero to days with one digit
        aux = datetime.strptime(date.replace('/', ''), '%Y%m%d')

        return datetime.strftime(aux, '%Y%m%d')

    def build_s3_filter_args(self, aws_account_id, aws_region, date, iterating=False):
        filter_marker = ''
        if self.reparse:
            if self.only_logs_after:
                filter_marker = self.marker_only_logs_after(aws_region, aws_account_id)
        else:
            created_date = self.add_zero_to_day(date)
            query_last_key_of_day = self.db_connector.execute(
                self.sql_find_last_key_processed_of_day.format(table_name=self.db_table_name,
                                                               bucket_path=self.bucket_path,
                                                               aws_account_id=aws_account_id,
                                                               aws_region=aws_region,
                                                               created_date=created_date))
            try:
                last_key = query_last_key_of_day.fetchone()[0]
            except (TypeError, IndexError) as e:
                # if DB is empty for a region
                last_key = self.get_full_prefix(aws_account_id, aws_region) + date

        # for getting only logs of the current date
        config_prefix = self.get_full_prefix(aws_account_id, aws_region) + date + '/'

        filter_args = {
            'Bucket': self.bucket,
            'MaxKeys': 1000,
            'Prefix': config_prefix
        }

        # if nextContinuationToken is not used for processing logs in a bucket
        if not iterating:
            if filter_marker:
                filter_args['StartAfter'] = filter_marker
                debug('+++ Marker: {0}'.format(filter_marker), 2)
            else:
                filter_args['StartAfter'] = last_key
                debug('+++ Marker: {0}'.format(last_key), 2)

        return filter_args

    def iter_files_in_bucket(self, aws_account_id, aws_region, date):
        try:
            bucket_files = self.client.list_objects_v2(**self.build_s3_filter_args(aws_account_id, aws_region, date))

            if 'Contents' not in bucket_files:
                debug("+++ No logs to process in bucket: {}/{}".format(aws_account_id, aws_region), 1)
                return

            for bucket_file in bucket_files['Contents']:
                if not bucket_file['Key']:
                    continue

                if self.already_processed(bucket_file['Key'], aws_account_id, aws_region):
                    if self.reparse:
                        debug("++ File previously processed, but reparse flag set: {file}".format(
                            file=bucket_file['Key']), 1)
                    else:
                        debug("++ Skipping previously processed file: {file}".format(file=bucket_file['Key']), 1)
                        continue

                debug("++ Found new log: {0}".format(bucket_file['Key']), 2)
                # Get the log file from S3 and decompress it
                log_json = self.get_log_file(aws_account_id, bucket_file['Key'])
                self.iter_events(log_json, bucket_file['Key'], aws_account_id)
                # Remove file from S3 Bucket
                if self.delete_file:
                    debug("+++ Remove file from S3 Bucket:{0}".format(bucket_file['Key']), 2)
                    self.client.delete_object(Bucket=self.bucket, Key=bucket_file['Key'])
                self.mark_complete(aws_account_id, aws_region, bucket_file)
            # optimize DB
            self.db_maintenance(aws_account_id=aws_account_id, aws_region=aws_region)
            self.db_connector.commit()
            # iterate if there are more logs
            while bucket_files['IsTruncated']:
                new_s3_args = self.build_s3_filter_args(aws_account_id, aws_region, date, True)
                new_s3_args['ContinuationToken'] = bucket_files['NextContinuationToken']
                bucket_files = self.client.list_objects_v2(**new_s3_args)

                if 'Contents' not in bucket_files:
                    debug("+++ No logs to process in bucket: {}/{}".format(aws_account_id, aws_region), 1)
                    return

                for bucket_file in bucket_files['Contents']:
                    if not bucket_file['Key']:
                        continue
                    if self.already_processed(bucket_file['Key'], aws_account_id, aws_region):
                        if self.reparse:
                            debug("++ File previously processed, but reparse flag set: {file}".format(
                                file=bucket_file['Key']), 1)
                        else:
                            debug("++ Skipping previously processed file: {file}".format(file=bucket_file['Key']), 1)
                            continue
                    debug("++ Found new log: {0}".format(bucket_file['Key']), 2)
                    # Get the log file from S3 and decompress it
                    log_json = self.get_log_file(aws_account_id, bucket_file['Key'])
                    self.iter_events(log_json, bucket_file['Key'], aws_account_id)
                    # Remove file from S3 Bucket
                    if self.delete_file:
                        debug("+++ Remove file from S3 Bucket:{0}".format(bucket_file['Key']), 2)
                        self.client.delete_object(Bucket=self.bucket, Key=bucket_file['Key'])
                    self.mark_complete(aws_account_id, aws_region, bucket_file)
                # optimize DB
                self.db_maintenance(aws_account_id=aws_account_id, aws_region=aws_region)
                self.db_connector.commit()
        except SystemExit:
            raise
        except Exception as err:
            if hasattr(err, 'message'):
                debug("+++ Unexpected error: {}".format(err.message), 2)
            else:
                debug("+++ Unexpected error: {}".format(err), 2)
            print("ERROR: Unexpected error querying/working with objects in S3: {}".format(err))
            sys.exit(7)

    def reformat_msg(self, event):
        AWSBucket.reformat_msg(self, event)
        if 'configuration' in event['aws']:
            configuration = event['aws']['configuration']

            # Remove unnecessary fields to avoid performance issues
            for key in configuration:
                if type(configuration[key]) is dict and "Content" in configuration[key]:
                    content_list = list(configuration[key]["Content"].keys())
                    configuration[key]["Content"] = content_list

            if 'securityGroups' in configuration:
                security_groups = configuration['securityGroups']
                if isinstance(security_groups, unicode):
                    configuration['securityGroups'] = {'groupId': [security_groups]}
                elif isinstance(security_groups, list):
                    group_ids = [sec_group['groupId'] for sec_group in security_groups if 'groupId' in sec_group]
                    group_names = [sec_group['groupName'] for sec_group in security_groups if 'groupName' in sec_group]
                    configuration['securityGroups'] = {}
                    if len(group_ids) > 0:
                        configuration['securityGroups']['groupId'] = group_ids
                    if len(group_names) > 0:
                        configuration['securityGroups']['groupName'] = group_names
                elif isinstance(configuration['securityGroups'], dict):
                    configuration['securityGroups'] = {key: [value] for key, value in security_groups.items()}
                else:
                    print("WARNING: Could not reformat event {0}".format(event))

            if 'availabilityZones' in configuration:
                availability_zones = configuration['availabilityZones']
                if isinstance(availability_zones, unicode):
                    configuration['availabilityZones'] = {'zoneName': [availability_zones]}
                elif isinstance(availability_zones, list):
                    subnet_ids = [zone['subnetId'] for zone in availability_zones if 'subnetId' in zone]
                    zone_names = [zone['zoneName'] for zone in availability_zones if 'zoneName' in zone]
                    configuration['availabilityZones'] = {}
                    if len(subnet_ids) > 0:
                        configuration['availabilityZones']['subnetId'] = subnet_ids
                    if len(zone_names) > 0:
                        configuration['availabilityZones']['zoneName'] = zone_names
                elif isinstance(configuration['availabilityZones'], dict):
                    configuration['availabilityZones'] = {key: [value] for key, value in availability_zones.items()}
                else:
                    print("WARNING: Could not reformat event {0}".format(event))

            if 'state' in configuration:
                state = configuration['state']
                if isinstance(state, unicode):
                    configuration['state'] = {'name': state}
                elif isinstance(state, dict):
                    pass
                else:
                    print("WARNING: Could not reformat event {0}".format(event))

            if 'createdTime' in configuration:
                created_time = configuration['createdTime']
                if isinstance(created_time, float) or isinstance(created_time, int):
                    configuration['createdTime'] = float(created_time)
                else:
                    try:
                        date_string = str(created_time)
                        configuration['createdTime'] = mktime(datetime.strptime(date_string,
                                                                                "%Y-%m-%dT%H:%M:%S.%fZ").timetuple())
                    except Exception:
                        print("WARNING: Could not reformat event {0}".format(event))

            if 'iamInstanceProfile' in configuration:
                iam_profile = configuration['iamInstanceProfile']
                if isinstance(iam_profile, unicode):
                    configuration['iamInstanceProfile'] = {'name': iam_profile}
                elif isinstance(iam_profile, dict):
                    pass
                else:
                    print("WARNING: Could not reformat event {0}".format(event))

        return event


class AWSVPCFlowBucket(AWSLogsBucket):
    """
    Represents a bucket with AWS VPC logs
    """

    def __init__(self, **kwargs):
        self.db_table_name = 'vpcflow'
        AWSLogsBucket.__init__(self, **kwargs)
        self.service = 'vpcflowlogs'
        self.access_key = kwargs['access_key']
        self.secret_key = kwargs['secret_key']
        self.profile_name = kwargs['profile']
        # SQL queries for VPC must be after constructor call
        self.sql_already_processed = """
                          SELECT
                            count(*)
                          FROM
                            {table_name}
                          WHERE
                            bucket_path='{bucket_path}' AND
                            aws_account_id='{aws_account_id}' AND
                            aws_region='{aws_region}' AND
                            flow_log_id='{flow_log_id}' AND
                            log_key='{log_key}';"""

        self.sql_mark_complete = """
                            INSERT INTO {table_name} (
                                bucket_path,
                                aws_account_id,
                                aws_region,
                                flow_log_id,
                                log_key,
                                processed_date,
                                created_date) VALUES (
                                '{bucket_path}',
                                '{aws_account_id}',
                                '{aws_region}',
                                '{flow_log_id}',
                                '{log_key}',
                                DATETIME('now'),
                                '{created_date}');"""

        self.sql_create_table = """
                            CREATE TABLE
                                {table_name} (
                                bucket_path 'text' NOT NULL,
                                aws_account_id 'text' NOT NULL,
                                aws_region 'text' NOT NULL,
                                flow_log_id 'text' NOT NULL,
                                log_key 'text' NOT NULL,
                                processed_date 'text' NOT NULL,
                                created_date 'integer' NOT NULL,
                                PRIMARY KEY (bucket_path, aws_account_id, aws_region, flow_log_id, log_key));"""

        self.sql_find_last_key_processed_of_day = """
                                                SELECT
                                                    log_key
                                                FROM
                                                    {table_name}
                                                WHERE
                                                    bucket_path='{bucket_path}' AND
                                                    aws_account_id='{aws_account_id}' AND
                                                    aws_region = '{aws_region}' AND
                                                    flow_log_id = '{flow_log_id}' AND
                                                    created_date = {created_date}
                                                ORDER BY
                                                    log_key ASC
                                                LIMIT 1;"""

        self.sql_get_date_last_log_processed = """
                                            SELECT
                                                created_date
                                            FROM
                                                {table_name}
                                            WHERE
                                                bucket_path='{bucket_path}' AND
                                                aws_account_id='{aws_account_id}' AND
                                                aws_region = '{aws_region}' AND
                                                flow_log_id = '{flow_log_id}'
                                            ORDER BY
                                                log_key DESC
                                            LIMIT 1;"""

        self.sql_db_maintenance = """DELETE
                            FROM
                                {table_name}
                            WHERE
                                bucket_path='{bucket_path}' AND
                                aws_account_id='{aws_account_id}' AND
                                aws_region='{aws_region}' AND
                                flow_log_id='{flow_log_id}' AND
                                log_key <=
                                (SELECT log_key
                                    FROM
                                        {table_name}
                                    WHERE
                                        bucket_path='{bucket_path}' AND
                                        aws_account_id='{aws_account_id}' AND
                                        aws_region='{aws_region}' AND
                                        flow_log_id='{flow_log_id}'
                                    ORDER BY
                                        log_key DESC
                                    LIMIT 1
                                    OFFSET {retain_db_records});"""

        self.sql_count_region = """
                                SELECT
                                    count(*)
                                FROM
                                    {table_name}
                                WHERE
                                    bucket_path='{bucket_path}' AND
                                    aws_account_id='{aws_account_id}' AND
                                    aws_region='{aws_region}' AND
                                    flow_log_id='{flow_log_id}';"""

    def load_information_from_file(self, log_key):
        with self.decompress_file(log_key=log_key) as f:
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

    def get_ec2_client(self, access_key, secret_key, region, profile_name=None):
        conn_args = {}
        conn_args['region_name'] = region

        if access_key is not None and secret_key is not None:
            conn_args['aws_access_key_id'] = access_key
            conn_args['aws_secret_access_key'] = secret_key
        elif profile_name is not None:
            conn_args['profile_name'] = profile_name

        boto_session = boto3.Session(**conn_args)

        try:
            ec2_client = boto_session.client(service_name='ec2')
        except Exception as e:
            print("Error getting EC2 client: {}".format(e))
            sys.exit(3)

        return ec2_client

    def get_flow_logs_ids(self, access_key, secret_key, region, profile_name=None):
        ec2_client = self.get_ec2_client(access_key, secret_key, region, profile_name=profile_name)
        flow_logs_ids = list(map(operator.itemgetter('FlowLogId'), ec2_client.describe_flow_logs()['FlowLogs']))
        return flow_logs_ids

    def already_processed(self, downloaded_file, aws_account_id, aws_region, flow_log_id):
        cursor = self.db_connector.execute(self.sql_already_processed.format(
            table_name=self.db_table_name,
            bucket_path=self.bucket_path,
            aws_account_id=aws_account_id,
            aws_region=aws_region,
            flow_log_id=flow_log_id,
            log_key=downloaded_file
        ))
        return cursor.fetchone()[0] > 0

    def get_days_since_today(self, date):
        date = datetime.strptime(date, "%Y%m%d")
        # it is necessary to add one day for processing the current day
        delta = datetime.utcnow() - date + timedelta(days=1)
        return delta.days

    def get_date_list(self, aws_account_id, aws_region, flow_log_id):
        num_days = self.get_days_since_today(self.get_date_last_log(aws_account_id, aws_region, flow_log_id))
        date_list_time = [datetime.utcnow() - timedelta(days=x) for x in range(0, num_days)]
        return [datetime.strftime(date, "%Y/%m/%d") for date in reversed(date_list_time)]

    def get_date_last_log(self, aws_account_id, aws_region, flow_log_id):
        try:
            query_date_last_log = self.db_connector.execute(self.sql_get_date_last_log_processed.format(
                table_name=self.db_table_name,
                bucket_path=self.bucket_path,
                aws_account_id=aws_account_id,
                aws_region=aws_region,
                flow_log_id=flow_log_id))
            # query returns an integer
            last_date_processed = str(query_date_last_log.fetchone()[0])
        # if DB is empty
        except (TypeError, IndexError) as e:
            last_date_processed = self.only_logs_after.strftime('%Y%m%d')
        return last_date_processed

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
                debug("+++ Working on {} - {}".format(aws_account_id, aws_region), 1)
                # get flow log ids for the current region
                flow_logs_ids = self.get_flow_logs_ids(self.access_key,
                                                       self.secret_key, aws_region, profile_name=self.profile_name)
                # for each flow log id
                for flow_log_id in flow_logs_ids:
                    if self.old_version:
                        self.migrate(aws_account_id=aws_account_id, aws_region=aws_region,
                                     flow_log_id=flow_log_id)
                    date_list = self.get_date_list(aws_account_id, aws_region, flow_log_id)
                    for date in date_list:
                        self.iter_files_in_bucket(aws_account_id, aws_region, date, flow_log_id)

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
        try:
            query_count_region = self.db_connector.execute(
                self.sql_count_region.format(
                    table_name=self.db_table_name,
                    bucket_path=self.bucket_path,
                    aws_account_id=aws_account_id,
                    aws_region=aws_region,
                    flow_log_id=flow_log_id,
                    retain_db_records=self.retain_db_records
                ))
            return query_count_region.fetchone()[0]
        except Exception as e:
            print(
                "ERROR: Failed to execute DB cleanup - AWS Account ID: {aws_account_id}  Region: {aws_region}: {error_msg}".format(
                    aws_account_id=aws_account_id,
                    aws_region=aws_region,
                    error_msg=e))
            sys.exit(10)

    def db_maintenance(self, aws_account_id=None, aws_region=None, flow_log_id=None):
        debug("+++ DB Maintenance", 1)
        try:
            if self.db_count_region(aws_account_id, aws_region, flow_log_id) \
                    > self.retain_db_records:
                self.db_connector.execute(self.sql_db_maintenance.format(
                    table_name=self.db_table_name,
                    bucket_path=self.bucket_path,
                    aws_account_id=aws_account_id,
                    aws_region=aws_region,
                    flow_log_id=flow_log_id,
                    retain_db_records=self.retain_db_records
                ))
        except Exception as e:
            print(
                "ERROR: Failed to execute DB cleanup - AWS Account ID: {aws_account_id}  Region: {aws_region}: {error_msg}".format(
                    aws_account_id=aws_account_id,
                    aws_region=aws_region,
                    error_msg=e))
            sys.exit(10)

    def get_vpc_prefix(self, aws_account_id, aws_region, date, flow_log_id):
        return self.get_full_prefix(aws_account_id, aws_region) + date \
               + '/' + aws_account_id + '_vpcflowlogs_' + aws_region + '_' + flow_log_id

    def build_s3_filter_args(self, aws_account_id, aws_region, date, flow_log_id, iterating=False):
        filter_marker = ''
        if self.reparse:
            if self.only_logs_after:
                filter_marker = self.marker_only_logs_after(aws_region, aws_account_id)
        else:

            query_last_key_of_day = self.db_connector.execute(
                self.sql_find_last_key_processed_of_day.format(table_name=self.db_table_name,
                                                               bucket_path=self.bucket_path,
                                                               aws_account_id=aws_account_id,
                                                               aws_region=aws_region,
                                                               flow_log_id=flow_log_id,
                                                               created_date=int(date.replace('/', ''))))
            try:
                last_key = query_last_key_of_day.fetchone()[0]
            except (TypeError, IndexError) as e:
                # if DB is empty for a region
                last_key = self.get_full_prefix(aws_account_id, aws_region) + date

        vpc_prefix = self.get_vpc_prefix(aws_account_id, aws_region, date, flow_log_id)
        filter_args = {
            'Bucket': self.bucket,
            'MaxKeys': 1000,
            'Prefix': vpc_prefix
        }

        # if nextContinuationToken is not used for processing logs in a bucket
        if not iterating:
            if filter_marker:
                filter_args['StartAfter'] = filter_marker
                debug('+++ Marker: {0}'.format(filter_marker), 2)
            else:
                filter_args['StartAfter'] = last_key
                debug('+++ Marker: {0}'.format(last_key), 2)

        return filter_args

    def iter_files_in_bucket(self, aws_account_id, aws_region, date, flow_log_id):
        try:
            bucket_files = self.client.list_objects_v2(
                **self.build_s3_filter_args(aws_account_id, aws_region, date, flow_log_id))

            if 'Contents' not in bucket_files:
                debug("+++ No logs to process for {} flow log ID in bucket: {}/{}".format(flow_log_id,
                                                                                          aws_account_id, aws_region),
                      1)
                return

            for bucket_file in bucket_files['Contents']:
                if not bucket_file['Key']:
                    continue

                if self.already_processed(bucket_file['Key'], aws_account_id, aws_region, flow_log_id):
                    if self.reparse:
                        debug("++ File previously processed, but reparse flag set: {file}".format(
                            file=bucket_file['Key']), 1)
                    else:
                        debug("++ Skipping previously processed file: {file}".format(file=bucket_file['Key']), 1)
                        continue

                debug("++ Found new log: {0}".format(bucket_file['Key']), 2)
                # Get the log file from S3 and decompress it
                log_json = self.get_log_file(aws_account_id, bucket_file['Key'])
                self.iter_events(log_json, bucket_file['Key'], aws_account_id)
                # Remove file from S3 Bucket
                if self.delete_file:
                    debug("+++ Remove file from S3 Bucket:{0}".format(bucket_file['Key']), 2)
                    self.client.delete_object(Bucket=self.bucket, Key=bucket_file['Key'])
                self.mark_complete(aws_account_id, aws_region, bucket_file, flow_log_id)
            # optimize DB
            self.db_maintenance(aws_account_id=aws_account_id, aws_region=aws_region,
                                flow_log_id=flow_log_id)
            self.db_connector.commit()
            # iterate if there are more logs
            while bucket_files['IsTruncated']:
                new_s3_args = self.build_s3_filter_args(aws_account_id, aws_region, date, flow_log_id, True)
                new_s3_args['ContinuationToken'] = bucket_files['NextContinuationToken']
                bucket_files = self.client.list_objects_v2(**new_s3_args)

                if 'Contents' not in bucket_files:
                    debug("+++ No logs to process for {} flow log ID in bucket: {}/{}".format(flow_log_id,
                                                                                              aws_account_id,
                                                                                              aws_region), 1)
                    return

                for bucket_file in bucket_files['Contents']:
                    if not bucket_file['Key']:
                        continue
                    if self.already_processed(bucket_file['Key'], aws_account_id, aws_region, flow_log_id):
                        if self.reparse:
                            debug("++ File previously processed, but reparse flag set: {file}".format(
                                file=bucket_file['Key']), 1)
                        else:
                            debug("++ Skipping previously processed file: {file}".format(file=bucket_file['Key']), 1)
                            continue
                    debug("++ Found new log: {0}".format(bucket_file['Key']), 2)
                    # Get the log file from S3 and decompress it
                    log_json = self.get_log_file(aws_account_id, bucket_file['Key'])
                    self.iter_events(log_json, bucket_file['Key'], aws_account_id)
                    # Remove file from S3 Bucket
                    if self.delete_file:
                        debug("+++ Remove file from S3 Bucket:{0}".format(bucket_file['Key']), 2)
                        self.client.delete_object(Bucket=self.bucket, Key=bucket_file['Key'])
                    self.mark_complete(aws_account_id, aws_region, bucket_file, flow_log_id)
                # optimize DB
                self.db_maintenance(aws_account_id=aws_account_id, aws_region=aws_region,
                                    flow_log_id=flow_log_id)
                self.db_connector.commit()
        except SystemExit:
            raise
        except Exception as err:
            if hasattr(err, 'message'):
                debug("+++ Unexpected error: {}".format(err.message), 2)
            else:
                debug("+++ Unexpected error: {}".format(err), 2)
            print("ERROR: Unexpected error querying/working with objects in S3: {}".format(err))
            sys.exit(7)

    def mark_complete(self, aws_account_id, aws_region, log_file, flow_log_id):
        if self.reparse:
            if self.already_processed(log_file['Key'], aws_account_id, aws_region):
                debug(
                    '+++ File already marked complete, but reparse flag set: {log_key}'.format(log_key=log_file['Key']),
                    2)
        else:
            try:
                self.db_connector.execute(self.sql_mark_complete.format(
                    table_name=self.db_table_name,
                    bucket_path=self.bucket_path,
                    aws_account_id=aws_account_id,
                    aws_region=aws_region,
                    flow_log_id=flow_log_id,
                    log_key=log_file['Key'],
                    created_date=self.get_creation_date(log_file)
                ))
            except Exception as e:
                debug("+++ Error marking log {} as completed: {}".format(log_file['Key'], e), 2)
                raise e


class AWSCustomBucket(AWSBucket):

    def __init__(self, db_table_name=None, **kwargs):
        # only special services have a different DB table
        if db_table_name:
            self.db_table_name = db_table_name
        else:
            self.db_table_name = 'custom'
        AWSBucket.__init__(self, **kwargs)
        self.retain_db_records = 500
        # get STS client
        access_key = kwargs.get('access_key', None)
        secret_key = kwargs.get('secret_key', None)
        profile = kwargs.get('profile', None)
        self.sts_client = self.get_sts_client(access_key, secret_key, profile=profile)
        # get account ID
        self.aws_account_id = self.sts_client.get_caller_identity().get('Account')
        # SQL queries for custom buckets
        self.sql_already_processed = """
                          SELECT
                            count(*)
                          FROM
                            {table_name}
                          WHERE
                            bucket_path='{bucket_path}' AND
                            aws_account_id='{aws_account_id}' AND
                            log_key='{log_key}';"""

        self.sql_mark_complete = """
                            INSERT INTO {table_name} (
                                bucket_path,
                                aws_account_id,
                                log_key,
                                processed_date,
                                created_date) VALUES (
                                '{bucket_path}',
                                '{aws_account_id}',
                                '{log_key}',
                                DATETIME('now'),
                                '{created_date}');"""

        self.sql_create_table = """
                            CREATE TABLE
                                {table_name} (
                                bucket_path 'text' NOT NULL,
                                aws_account_id 'text' NOT NULL,
                                log_key 'text' NOT NULL,
                                processed_date 'text' NOT NULL,
                                created_date 'integer' NOT NULL,
                                PRIMARY KEY (bucket_path, aws_account_id, log_key));"""

        self.sql_find_last_log_processed = """
                                        SELECT
                                            created_date
                                        FROM
                                            {table_name}
                                        WHERE
                                            bucket_path='{bucket_path}' AND
                                            aws_account_id='{aws_account_id}'
                                        ORDER BY
                                            created_date DESC
                                        LIMIT 1;"""

        self.sql_find_last_key_processed = """
                                        SELECT
                                            log_key
                                        FROM
                                            {table_name}
                                        WHERE
                                            bucket_path='{bucket_path}' AND
                                            aws_account_id='{aws_account_id}'
                                        ORDER BY
                                            log_key ASC
                                        LIMIT 1;"""

        self.sql_db_maintenance = """DELETE
                            FROM
                                {table_name}
                            WHERE
                                bucket_path='{bucket_path}' AND
                                aws_account_id='{aws_account_id}' AND
                                log_key <=
                                (SELECT log_key
                                    FROM
                                        {table_name}
                                    WHERE
                                        bucket_path='{bucket_path}' AND
                                        aws_account_id='{aws_account_id}'
                                    ORDER BY
                                        log_key DESC
                                    LIMIT 1
                                    OFFSET {retain_db_records});"""

        self.sql_count_custom = """
                                SELECT
                                    count(*)
                                FROM
                                    {table_name}
                                WHERE
                                    bucket_path='{bucket_path}' AND
                                    aws_account_id='{aws_account_id}';"""

    def load_information_from_file(self, log_key):
        def json_event_generator(data):
            while data:
                json_data, json_index = decoder.raw_decode(data)
                data = data[json_index:]
                yield json_data

        with self.decompress_file(log_key=log_key) as f:
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
        # The Amazon S3 object name follows the pattern DeliveryStreamName-DeliveryStreamVersion-YYYY-MM-DD-HH-MM-SS-RandomString
        name_regex = re.match(r"^[\w\-]+(\d\d\d\d-\d\d-\d\d)[\w\-.]+$", path.basename(log_file['Key']))
        if name_regex is None:
            return log_file['LastModified'].strftime('%Y%m%d')
        else:
            return int(name_regex.group(1).replace('-', ''))

    def get_full_prefix(self, account_id, account_region):
        return self.prefix

    def reformat_msg(self, event):

        def list_paths_from_dict(d, discard_levels=None, glue=".", path=None):
            path = [] if path is None else path
            if not isinstance(d, dict):
                path.extend(d if isinstance(d, list) else [str(d)])
                return [glue.join(path[:discard_levels if discard_levels is None else -discard_levels])]
            return [item for k, v in d.items() for item in list_paths_from_dict(v,
                                                                                path=path+[k],
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
                        event['aws']['summary']['Events'][event_name][event_field] = list_paths_from_dict(event['aws']['summary']['Events'][event_name][event_field],
                                                                                                          discard_levels=0 if event_field == 'count' else 1,
                                                                                                          path=[])
            except KeyError:
                pass

        return event

    def iter_regions_and_accounts(self, account_id, regions):
        # Only <self.retain_db_records> logs for each region are stored in DB. Using self.bucket as region name
        # would prevent to loose lots of logs from different buckets.
        # no iterations for accounts_id or regions on custom buckets
        self.iter_files_in_bucket()
        self.db_maintenance()

    def already_processed(self, downloaded_file, aws_account_id, aws_region):
        cursor = self.db_connector.execute(self.sql_already_processed.format(
            table_name=self.db_table_name,
            bucket_path=self.bucket_path,
            aws_account_id=self.aws_account_id,
            log_key=downloaded_file
        ))
        return cursor.fetchone()[0] > 0

    def mark_complete(self, aws_account_id, aws_region, log_file):
        if self.reparse:
            if self.already_processed(log_file['Key'], aws_account_id, aws_region):
                debug(
                    '+++ File already marked complete, but reparse flag set: {log_key}'.format(log_key=log_file['Key']),
                    2)
        else:
            try:
                self.db_connector.execute(self.sql_mark_complete.format(
                    table_name=self.db_table_name,
                    bucket_path=self.bucket_path,
                    aws_account_id=self.aws_account_id,
                    log_key=log_file['Key'],
                    created_date=self.get_creation_date(log_file)
                ))
            except Exception as e:
                debug("+++ Error marking log {} as completed: {}".format(log_file['Key'], e), 2)
                raise e

    def db_count_custom(self):
        """Counts the number of rows in DB for a region
        :param aws_account_id: AWS account ID
        :type aws_account_id: str
        :rtype: int
        """
        try:
            query_count_custom = self.db_connector.execute(
                self.sql_count_custom.format(
                    table_name=self.db_table_name,
                    bucket_path=self.bucket_path,
                    aws_account_id=self.aws_account_id,
                    retain_db_records=self.retain_db_records
                ))
            return query_count_custom.fetchone()[0]
        except Exception as e:
            print(
                "ERROR: Failed to execute DB cleanup - Path: {bucket_path}: {error_msg}".format(
                    bucket_path=self.bucket_path,
                    error_msg=e))
            sys.exit(10)

    def db_maintenance(self, **kwargs):
        debug("+++ DB Maintenance", 1)
        try:
            if self.db_count_custom() > self.retain_db_records:
                self.db_connector.execute(self.sql_db_maintenance.format(
                    table_name=self.db_table_name,
                    bucket_path=self.bucket_path,
                    aws_account_id=self.aws_account_id,
                    retain_db_records=self.retain_db_records
                ))
        except Exception as e:
            print(
                "ERROR: Failed to execute DB cleanup - Path: {bucket_path}: {error_msg}".format(
                    bucket_path=self.bucket_path,
                    error_msg=e))
            sys.exit(10)

    def build_s3_filter_args(self, aws_account_id, aws_region, iterating=False):
        filter_marker = ''
        if self.reparse:
            if self.only_logs_after:
                filter_marker = self.marker_only_logs_after(aws_account_id, aws_region)

        else:
            query_last_key = self.db_connector.execute(
                self.sql_find_last_key_processed.format(table_name=self.db_table_name,
                                                        bucket_path=self.bucket_path,
                                                        aws_account_id=self.aws_account_id))
            try:
                last_key = query_last_key.fetchone()[0]
            except (TypeError, IndexError) as e:
                # if DB is empty for a service
                last_key = self.marker_only_logs_after(aws_region, aws_account_id)

        filter_args = {
            'Bucket': self.bucket,
            'MaxKeys': 1000,
            'Prefix': self.get_full_prefix(aws_account_id, aws_region)
        }

        # if nextContinuationToken is not used for processing logs in a bucket
        if not iterating:
            if filter_marker:
                filter_args['StartAfter'] = filter_marker
                debug('+++ Marker: {0}'.format(filter_marker), 2)
            else:
                filter_args['StartAfter'] = last_key
                debug('+++ Marker: {0}'.format(last_key), 2)

        return filter_args


class AWSGuardDutyBucket(AWSCustomBucket):

    def __init__(self, **kwargs):
        db_table_name = 'guardduty'
        AWSCustomBucket.__init__(self, db_table_name, **kwargs)

    def iter_events(self, event_list, log_key, aws_account_id):
        if event_list is not None:
            for event in event_list:
                # Parse out all the values of 'None'
                event_msg = self.get_alert_msg(aws_account_id, log_key, event)
                # Send the message (splitted if it is necessary)
                for msg in self.reformat_msg(event_msg):
                    self.send_msg(msg)

    def reformat_msg(self, event):
        debug('++ Reformat message', 3)
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


class CiscoUmbrella(AWSCustomBucket):

    def __init__(self, **kwargs):
        db_table_name = 'cisco_umbrella'
        AWSCustomBucket.__init__(self, db_table_name, **kwargs)

    def load_information_from_file(self, log_key):
        """Load data from a Cisco Umbrella log file."""
        with self.decompress_file(log_key=log_key) as f:
            if 'dnslogs' in self.prefix:
                fieldnames = ('timestamp', 'most_granular_identity',
                              'identities', 'internal_ip', 'external_ip',
                              'action', 'query_type', 'response_code', 'domain',  # noqa: E501
                              'categories', 'most_granular_identity_type',
                              'identity_types', 'blocked_categories'
                              )
            elif 'proxylogs' in self.prefix:
                fieldnames = ('timestamp', 'identities', 'internal_ip',
                              'external_ip', 'destination_ip', 'content_type',
                              'verdict', 'url', 'referer', 'user_agent',
                              'status_code', 'requested_size', 'response_size',
                              'response_body_size', 'sha', 'categories',
                              'av_detections', 'puas', 'amp_disposition',
                              'amp_malware_name', 'amp_score', 'identity_type',
                              'blocked_categories'
                              )
            elif 'iplogs' in self.prefix:
                fieldnames = ('timestamp', 'identity', 'source_ip',
                              'source_port', 'destination_ip',
                              'destination_port', 'categories'
                              )
            else:
                print("ERROR: Only 'dnslogs', 'proxylogs' or 'iplogs' are allowed for Cisco Umbrella")
                exit(12)
            csv_file = csv.DictReader(f, fieldnames=fieldnames, delimiter=',')

            # remove None values in csv_file
            return [dict({k: v for k, v in row.items() if v is not None},
                    source='cisco_umbrella') for row in csv_file]

    def marker_only_logs_after(self, aws_region, aws_account_id):
        return '{init}{only_logs_after}'.format(
            init=self.get_full_prefix(aws_account_id, aws_region),
            only_logs_after=self.only_logs_after.strftime('%Y-%m-%d')
        )


class AWSWAFBucket(AWSCustomBucket):

    def __init__(self, **kwargs):
        db_table_name = 'waf'
        AWSCustomBucket.__init__(self, db_table_name, **kwargs)

    def load_information_from_file(self, log_key):
        """Load data from a WAF log file."""
        content = []
        with self.decompress_file(log_key=log_key) as f:
            for line in f.readlines():
                try:
                    event = json.loads(line.rstrip())
                except json.JSONDecodeError:
                    print("ERROR: Events from {} file could not be loaded.".format(log_key.split('/')[-1]))
                    sys.exit(9)
                event['source'] = 'waf'
                content.append(event)

        return json.loads(json.dumps(content))


class AWSALBBucket(AWSCustomBucket):

    def __init__(self, **kwargs):
        db_table_name = 'alb'
        AWSCustomBucket.__init__(self, db_table_name, **kwargs)

    def load_information_from_file(self, log_key):
        """Load data from a ALB access log file."""
        with self.decompress_file(log_key=log_key) as f:
            fieldnames = (
                "type", "time", "elb", "client_port", "target_port", "request_processing_time",
                "target_processing_time", "response_processing_time", "elb_status_code", "target_status_code",
                "received_bytes", "sent_bytes", "request", "user_agent", "ssl_cipher", "ssl_protocol",
                "target_group_arn", "trace_id", "domain_name", "chosen_cert_arn", "matched_rule_priority",
                "request_creation_time", "action_executed", "redirect_url", "error_reason", "target_port_list",
                "target_status_code_list", "classification", "classification_reason")
            tsv_file = csv.DictReader(f, fieldnames=fieldnames, delimiter=' ')

            return [dict(x, source='alb') for x in tsv_file]


class AWSCLBBucket(AWSCustomBucket):

    def __init__(self, **kwargs):
        db_table_name = 'clb'
        AWSCustomBucket.__init__(self, db_table_name, **kwargs)

    def load_information_from_file(self, log_key):
        """Load data from a CLB access log file."""
        with self.decompress_file(log_key=log_key) as f:
            fieldnames = (
                "time", "elb", "client_port", "backend_port", "request_processing_time", "backend_processing_time",
                "response_processing_time", "elb_status_code", "backend_status_code", "received_bytes", "sent_bytes",
                "request", "user_agent", "ssl_cipher", "ssl_protocol")
            tsv_file = csv.DictReader(f, fieldnames=fieldnames, delimiter=' ')

            return [dict(x, source='clb') for x in tsv_file]


class AWSNLBBucket(AWSCustomBucket):

    def __init__(self, **kwargs):
        db_table_name = 'nlb'
        AWSCustomBucket.__init__(self, db_table_name, **kwargs)

    def load_information_from_file(self, log_key):
        """Load data from a NLB access log file."""
        with self.decompress_file(log_key=log_key) as f:
            fieldnames = (
                "type", "version", "time", "elb", "listener", "client_port", "destination_port", "connection_time",
                "tls_handshake_time", "received_bytes", "sent_bytes", "incoming_tls_alert", "chosen_cert_arn",
                "chosen_cert_serial", "tls_cipher", "tls_protocol_version", "tls_named_group", "domain_name",
                "alpn_fe_protocol", "alpn_client_preference_list")
            tsv_file = csv.DictReader(f, fieldnames=fieldnames, delimiter=' ')

            return [dict(x, source='nlb') for x in tsv_file]


class AWSService(WazuhIntegration):
    """
    Class for getting AWS Services logs from API calls
    :param access_key: AWS access key id
    :param secret_key: AWS secret access key
    :param profile: AWS profile
    :param iam_role_arn: IAM Role
    :param only_logs_after: Date after which obtain logs.
    :param region: Region of service
    """

    def __init__(self, access_key, secret_key, aws_profile, iam_role_arn,
                 service_name, only_logs_after, region, aws_log_groups=None, remove_log_streams=None):
        # DB name
        self.db_name = 'aws_services'
        # table name
        self.db_table_name = 'aws_services'

        WazuhIntegration.__init__(self, access_key=access_key, secret_key=secret_key,
                                  aws_profile=aws_profile, iam_role_arn=iam_role_arn,
                                  service_name=service_name, region=region)

        # get sts client (necessary for getting account ID)
        self.sts_client = self.get_sts_client(access_key, secret_key, aws_profile)
        # get account ID
        self.account_id = self.sts_client.get_caller_identity().get('Account')
        self.only_logs_after = only_logs_after

        # SQL queries for services
        self.sql_create_table = """
                            CREATE TABLE
                                {table_name} (
                                    service_name 'text' NOT NULL,
                                    aws_account_id 'text' NOT NULL,
                                    aws_region 'text' NOT NULL,
                                    scan_date 'text' NOT NULL,
                                    PRIMARY KEY (service_name, aws_account_id, aws_region, scan_date));"""

        self.sql_insert_value = """
                                INSERT INTO {table_name} (
                                    service_name,
                                    aws_account_id,
                                    aws_region,
                                    scan_date)
                                VALUES
                                    ('{service_name}',
                                    '{aws_account_id}',
                                    '{aws_region}',
                                    '{scan_date}');"""

        self.sql_find_last_scan = """
                                SELECT
                                    scan_date
                                FROM
                                    {table_name}
                                WHERE
                                    service_name='{service_name}' AND
                                    aws_account_id='{aws_account_id}' AND
                                    aws_region='{aws_region}'
                                ORDER BY
                                    scan_date DESC
                                LIMIT 1;"""

        self.sql_db_maintenance = """DELETE
                        FROM
                            {table_name}
                        WHERE
                            service_name='{service_name}' AND
                            aws_account_id='{aws_account_id}' AND
                            aws_region='{aws_region}' AND
                            rowid NOT IN
                            (SELECT ROWID
                                FROM
                                    {table_name}
                                WHERE
                                    service_name='{service_name}' AND
                                    aws_account_id='{aws_account_id}' AND
                                    aws_region='{aws_region}'
                                ORDER BY
                                    scan_date DESC
                                LIMIT {retain_db_records});"""

    def get_last_log_date(self):
        return '{Y}-{m}-{d} 00:00:00.0'.format(Y=self.only_logs_after[0:4],
                                               m=self.only_logs_after[4:6], d=self.only_logs_after[6:8])

    def format_message(self, msg):
        # rename service field to source
        if 'service' in msg:
            msg['source'] = msg['service'].lower()
            del msg['service']
        # cast createdAt
        if 'createdAt' in msg:
            msg['createdAt'] = datetime.strftime(msg['createdAt'],
                                                 '%Y-%m-%dT%H:%M:%SZ')
        # cast updatedAt
        if 'updatedAt' in msg:
            msg['updatedAt'] = datetime.strftime(msg['updatedAt'],
                                                 '%Y-%m-%dT%H:%M:%SZ')

        return {'integration': 'aws', 'aws': msg}


class AWSInspector(AWSService):
    """
    Class for getting AWS Inspector logs
    :param access_key: AWS access key id
    :param secret_key: AWS secret access key
    :param aws_profile: AWS profile
    :param iam_role_arn: IAM Role
    :param only_logs_after: Date after which obtain logs.
    :param region: Region of service
    """

    def __init__(self, reparse, access_key, secret_key, aws_profile,
                 iam_role_arn, only_logs_after, region, aws_log_groups=None,
                 remove_log_streams=None):

        self.service_name = 'inspector'
        self.inspector_region = region

        AWSService.__init__(self, access_key=access_key, secret_key=secret_key,
                            aws_profile=aws_profile, iam_role_arn=iam_role_arn, only_logs_after=only_logs_after,
                            service_name=self.service_name, region=region, aws_log_groups=aws_log_groups,
                            remove_log_streams=remove_log_streams)

        # max DB records for region
        self.retain_db_records = 5
        self.reparse = reparse

    def send_describe_findings(self, arn_list):
        if len(arn_list) == 0:
            debug('+++ There are not new events from {region} region'.format(region=self.inspector_region), 1)
        else:
            debug('+++ Processing new events from {region} region'.format(region=self.inspector_region), 1)
            response = self.client.describe_findings(findingArns=arn_list)['findings']
            for elem in response:
                self.send_msg(self.format_message(elem))

    def get_alerts(self):
        self.init_db(self.sql_create_table.format(table_name=self.db_table_name))
        try:
            initial_date = self.get_last_log_date()
            # reparse logs if this parameter exists
            if self.reparse:
                last_scan = initial_date
            else:
                self.db_cursor.execute(self.sql_find_last_scan.format(table_name=self.db_table_name,
                                                                      service_name=self.service_name,
                                                                      aws_account_id=self.account_id,
                                                                      aws_region=self.inspector_region))
                last_scan = self.db_cursor.fetchone()[0]
        except TypeError as e:
            # write initial date if DB is empty
            self.db_cursor.execute(self.sql_insert_value.format(table_name=self.db_table_name,
                                                                service_name=self.service_name,
                                                                aws_account_id=self.account_id,
                                                                aws_region=self.inspector_region,
                                                                scan_date=initial_date))
            last_scan = initial_date

        datetime_last_scan = datetime.strptime(last_scan, '%Y-%m-%d %H:%M:%S.%f')
        # get current time (UTC)
        datetime_current = datetime.utcnow()
        # describe_findings only retrieves 100 results per call
        response = self.client.list_findings(maxResults=100, filter={'creationTimeRange':
                                                                         {'beginDate': datetime_last_scan,
                                                                          'endDate': datetime_current}})
        self.send_describe_findings(response['findingArns'])
        # iterate if there are more elements
        while 'nextToken' in response:
            response = self.client.list_findings(maxResults=100, nextToken=response['nextToken'],
                                                 filter={'creationTimeRange': {'beginDate': datetime_last_scan,
                                                                               'endDate': datetime_current}})
            self.send_describe_findings(response['findingArns'])
        # insert last scan in DB
        self.db_cursor.execute(self.sql_insert_value.format(table_name=self.db_table_name,
                                                            service_name=self.service_name,
                                                            aws_account_id=self.account_id,
                                                            aws_region=self.inspector_region,
                                                            scan_date=datetime_current))
        # DB maintenance
        self.db_cursor.execute(self.sql_db_maintenance.format(table_name=self.db_table_name,
                                                              service_name=self.service_name,
                                                              aws_account_id=self.account_id,
                                                              aws_region=self.inspector_region,
                                                              retain_db_records=self.retain_db_records))
        # close connection with DB
        self.db_connector.commit()
        self.close_db()


class AWSCloudWatchLogs(AWSService):
    """
    Class for getting AWS Cloudwatch logs

    Attributes
    ----------
    access_key : str
        AWS access key id
    secret_key : str
        AWS secret access key
    aws_profile : str
        AWS profile
    iam_role_arn : str
        IAM Role
    only_logs_after : str
        Date after which obtain logs
    region : str
        Region where the logs are located
    aws_log_groups : str
        String containing a list of log group names separated by a comma
    remove_log_streams : bool
        Indicate if log streams should be removed after being fetched
    db_table_name : str
        Name of the table to be created on aws_service.db
    only_logs_after_millis : int
        only_logs_after expressed as the number of milliseconds after Jan 1, 1970 00:00:00 UTC
    log_group_list : list of str
        List of each log group to be parsed
    sql_cloudwatch_create_table : str
        Query for the creation of the table
    sql_cloudwatch_insert : str
        Query to insert the token for a given log stream
    sql_cloudwatch_update : str
        Query for updating the token, start_time and end_time values
    sql_cloudwatch_select : str
        Query to obtain the token, start_time and end_time values
    sql_cloudwatch_select_logstreams : str
        Query to get all logstreams in the DB
    sql_cloudwatch_purge : str
        Query to delete a row from the DB.
    """

    def __init__(self, reparse, access_key, secret_key, aws_profile,
                 iam_role_arn, only_logs_after, region, aws_log_groups,
                 remove_log_streams):

        self.sql_cloudwatch_create_table = """
                                CREATE TABLE 
                                    {table_name} (
                                        aws_region 'text' NOT NULL,
                                        aws_log_group 'text' NOT NULL,
                                        aws_log_stream 'text' NOT NULL,
                                        next_token 'text',
                                        start_time 'integer',
                                        end_time 'integer',
                                        PRIMARY KEY (aws_region, aws_log_group, aws_log_stream));"""

        self.sql_cloudwatch_insert = """
                                INSERT INTO {table_name} (
                                    aws_region,
                                    aws_log_group,
                                    aws_log_stream,
                                    next_token,
                                    start_time,
                                    end_time)
                                VALUES
                                    ('{aws_region}',
                                    '{aws_log_group}',
                                    '{aws_log_stream}',
                                    '{next_token}',
                                    '{start_time}',
                                    '{end_time}');"""

        self.sql_cloudwatch_update = """
                                UPDATE 
                                    {table_name}
                                SET
                                    next_token='{next_token}',
                                    start_time='{start_time}',
                                    end_time='{end_time}'
                                WHERE
                                    aws_region='{aws_region}' AND
                                    aws_log_group='{aws_log_group}' AND
                                    aws_log_stream='{aws_log_stream}';"""

        self.sql_cloudwatch_select = """
                            SELECT
                                next_token,
                                start_time,
                                end_time
                            FROM
                                '{table_name}'
                            WHERE
                                aws_region='{aws_region}' AND 
                                aws_log_group='{aws_log_group}' AND 
                                aws_log_stream='{aws_log_stream}'"""
        self.sql_cloudwatch_select_logstreams = """
                            SELECT
                                aws_log_stream
                            FROM
                                '{table_name}'
                            WHERE
                                aws_region='{aws_region}' AND 
                                aws_log_group='{aws_log_group}'
                            ORDER BY
                                aws_log_stream;"""
        self.sql_cloudwatch_purge = """
                            DELETE FROM
                                {table_name}
                            WHERE
                                aws_region='{aws_region}' AND 
                                aws_log_group='{aws_log_group}' AND 
                                aws_log_stream='{aws_log_stream}';"""

        AWSService.__init__(self, access_key=access_key, secret_key=secret_key,
                            aws_profile=aws_profile, iam_role_arn=iam_role_arn, only_logs_after=only_logs_after,
                            region=region, aws_log_groups=aws_log_groups, remove_log_streams=remove_log_streams,
                            service_name='cloudwatchlogs')

        self.region = region
        self.db_table_name = 'cloudwatch_logs'
        self.log_group_list = [group for group in aws_log_groups.split(",") if group != ""] if aws_log_groups else []
        self.remove_log_streams = remove_log_streams
        self.only_logs_after_millis = int(datetime.strptime(only_logs_after, '%Y%m%d').replace(
            tzinfo=timezone.utc).timestamp() * 1000) if only_logs_after else None
        debug("only logs: {}".format(self.only_logs_after_millis), 1)

    def get_alerts(self):
        """Iterate over all the log streams for each log group provided by the user in the given region to get their
        logs and send them to analysisd, which will raise alerts if applicable.

        It will avoid getting duplicate events by using the token, start_time and end_time variables stored in the DB.
        Logs with a timestamp lesser that start_time and greater than end_time will be fetched using the
        `get_alerts_within_range` function.

        The log streams will be removed after fetching them if `remove_log_streams` value is True.

        The database will be purged to remove unnecessary records at the end of each log group iteration.
        """
        self.init_db(self.sql_cloudwatch_create_table.format(table_name=self.db_table_name))

        try:
            for log_group in self.log_group_list:
                for log_stream in self.get_log_streams(log_group=log_group):
                    debug('Getting data from DB for log stream "{}" in log group "{}"'.format(log_stream, log_group), 1)
                    db_values = self.get_data_from_db(log_group=log_group, log_stream=log_stream)
                    debug('Token: "{}", start_time: "{}", '
                          'end_time: "{}"'.format(db_values['token'] if db_values else None,
                                                  db_values['start_time'] if db_values else None,
                                                  db_values['end_time'] if db_values else None), 2)
                    result_before = None
                    result_after = None
                    if self.only_logs_after_millis is None:
                        if db_values:
                            result_before = self.get_alerts_within_range(log_group=log_group, log_stream=log_stream,
                                                                         token=None, start_time=None,
                                                                         end_time=db_values['start_time'])
                            if db_values['end_time'] is not None:
                                result_after = self.get_alerts_within_range(log_group=log_group, log_stream=log_stream,
                                                                            token=db_values['token'],
                                                                            start_time=db_values['end_time'] + 1,
                                                                            end_time=None)
                        else:
                            result_after = self.get_alerts_within_range(log_group=log_group, log_stream=log_stream,
                                                                        token=None, start_time=None, end_time=None)
                    elif db_values is None:
                        result_before = self.get_alerts_within_range(log_group=log_group, log_stream=log_stream,
                                                                     token=None, start_time=self.only_logs_after_millis,
                                                                     end_time=None)
                    elif db_values['start_time'] is not None and self.only_logs_after_millis < db_values['start_time']:
                        result_before = self.get_alerts_within_range(log_group=log_group, log_stream=log_stream,
                                                                     token=None, start_time=self.only_logs_after_millis,
                                                                     end_time=db_values['start_time'])
                        if db_values['end_time'] is not None:
                            result_after = self.get_alerts_within_range(log_group=log_group, log_stream=log_stream,
                                                                        token=db_values['token'],
                                                                        start_time=db_values['end_time'] + 1,
                                                                        end_time=None)
                    elif db_values['end_time'] is not None and self.only_logs_after_millis < db_values['end_time']:
                        result_after = self.get_alerts_within_range(log_group=log_group, log_stream=log_stream,
                                                                    token=db_values['token'],
                                                                    start_time=db_values['end_time'] + 1,
                                                                    end_time=None)
                    else:
                        result_after = self.get_alerts_within_range(log_group=log_group, log_stream=log_stream,
                                                                    token=None, start_time=self.only_logs_after_millis,
                                                                    end_time=None)

                    db_values = self.update_values(values=db_values, result_before=result_before,
                                                   result_after=result_after)

                    self.save_data_db(log_group=log_group, log_stream=log_stream, values=db_values)

                    if self.remove_log_streams:
                        self.remove_aws_log_stream(log_group=log_group, log_stream=log_stream)

                self.purge_db(log_group=log_group)
        finally:
            self.close_database()

    def remove_aws_log_stream(self, log_group, log_stream):
        """Remove a log stream from a log group in AWS Cloudwatch Logs.

        Parameters
        ----------
        log_group : str
            Name of the group where the log stream is stored
        log_stream : str
            Name of the log stream to be removed
        """
        try:
            debug('Removing log stream "{}" from log group "{}"'.format(log_group, log_stream), 1)
            self.client.delete_log_stream(logGroupName=log_group, logStreamName=log_stream)
        except Exception:
            debug('Error trying to remove "{}" log stream from "{}" log group.'.format(log_stream, log_group), 0)

    def get_alerts_within_range(self, log_group, log_stream, token, start_time, end_time):
        """Get all the logs from a log stream with a timestamp between the range of the provided start and end times and
        send them to Analysisd.

        It will fetch every log from the given log stream using boto3 `get_log_events` until it returns an empty
        response.

        Parameters
        ----------
        log_group : str
            Name of the log group where the log stream is stored
        log_stream : str
            Name of the log stream to get its logs
        token : str
            Token to the next set of logs. Obtained from a previous call and stored in DB.
        start_time : int
            The start of the time range, expressed as the number of milliseconds after Jan 1, 1970 00:00:00 UTC.
            Logs with a timestamp equal to this time or later will be fetched.
        end_time : int
            The end of the time range, expressed as the number of milliseconds after Jan 1, 1970 00:00:00 UTC.
            Events with a timestamp equal to or later than this time won't be fetched.

        Returns
        -------
        A dict containing the Token for the next set of logs, the timestamp of the first fetched log and the timestamp
        of the latest one.
        """
        response = None
        min_start_time = start_time
        max_end_time = end_time
        while response is None or response['events'] != list():
            debug('Getting CloudWatch logs from log stream "{}" in log group "{}" using token "{}", start_time '
                  '"{}" and end_time "{}"'.format(log_stream, log_group, token, start_time, end_time), 1)

            parameters = {'logGroupName': log_group,
                          'logStreamName': log_stream,
                          'nextToken': token,
                          'startTime': start_time,
                          'endTime': end_time,
                          'startFromHead': True}

            response = self.client.get_log_events(
                **{param: value for param, value in parameters.items() if value is not None})

            token = response['nextForwardToken']

            # Send events to Analysisd
            for event in response['events']:
                debug('+++ Sending events to Analysd...', 1)
                debug('The message is "{}"'.format(event['message']), 2)
                self.send_msg(event['message'], dump_json=False)

                if min_start_time is None:
                    min_start_time = event['timestamp']
                elif event['timestamp'] < min_start_time:
                    min_start_time = event['timestamp']

                if max_end_time is None:
                    max_end_time = event['timestamp']
                elif event['timestamp'] > max_end_time:
                    max_end_time = event['timestamp']

        if token is None and min_start_time is None and max_end_time is None:
            return None
        return {'token': token, 'start_time': min_start_time, 'end_time': max_end_time}

    def get_data_from_db(self, log_group, log_stream):
        """Get the token, start time and end time of a log stream stored in DB.

        Parameters
        ----------
        log_group : str
            Name of the log group
        log_stream : str
            Name of the log stream

        Returns
        -------
        A dict containing the token, start_time and end_time of the log stream. None if no data were found in the DB.
        """
        self.db_cursor.execute(self.sql_cloudwatch_select.format(table_name=self.db_table_name,
                                                                 aws_region=self.region,
                                                                 aws_log_group=log_group,
                                                                 aws_log_stream=log_stream))
        query_result = self.db_cursor.fetchone()
        if query_result:
            return {'token': None if query_result[0] == "None" else query_result[0],
                    'start_time': None if query_result[1] == "None" else query_result[1],
                    'end_time': None if query_result[2] == "None" else query_result[2]}

    def update_values(self, values, result_after, result_before):
        """Update the values for token, start_time and end_time using the results of previous 'get_alerts_within_range'
        executions.

        Parameters
        ----------
        values : dict
            A dict containing the token, start_time and end_time values to be updated
        result_after : dict
            A dict containing the resulting token, start_time and end_time values of a 'get_alerts_within_range'
            execution
        result_before : dict
            A dict containing the resulting token, start_time and end_time values of a 'get_alerts_within_range'
            execution

        Returns
        -------
        A dict containing the last token, minimal start_time and maximum end_value of the provided parameters.
        """
        min_start_time = result_before['start_time'] if result_before else None
        max_end_time = result_before['end_time'] if result_before else None

        if result_after is not None:
            if min_start_time is None:
                min_start_time = result_after['start_time']
            else:
                min_start_time = result_after['start_time'] if result_after[
                                                                   'start_time'] < min_start_time else min_start_time

            if max_end_time is None:
                max_end_time = result_after['start_time']
            else:
                max_end_time = result_after['start_time'] if result_after['start_time'] > max_end_time else max_end_time

        token = result_before['token'] if result_before is not None else None
        token = result_after['token'] if result_after is not None else token

        if values is None:
            return {'token': token, 'start_time': min_start_time, 'end_time': max_end_time}
        else:
            result = {'token': token}

            if values['start_time'] is not None:
                result['start_time'] = min_start_time if min_start_time < values['start_time'] else values['start_time']
            else:
                result['start_time'] = max_end_time

            if values['end_time'] is not None:
                result['end_time'] = max_end_time if max_end_time > values['end_time'] else values['end_time']
            else:
                result['end_time'] = max_end_time
            return result

    def save_data_db(self, log_group, log_stream, values):
        """Insert the token, start_time and end_time values into the DB. If the values already exists they will be
        updated instead.

        Parameters
        ----------
        log_group : str
            Name of the log group
        log_stream : str
            Name of the log stream
        values : dict
            Dict containing the token, start_time and end_time.
        """
        debug('Saving data for log group "{}" and log stream "{}".'.format(log_group, log_stream), 1)
        debug('The saved values are "{}"'.format(values), 2)
        try:
            self.db_cursor.execute(self.sql_cloudwatch_insert.format(table_name=self.db_table_name,
                                                                     aws_region=self.region,
                                                                     aws_log_group=log_group,
                                                                     aws_log_stream=log_stream,
                                                                     next_token=values['token'],
                                                                     start_time=values['start_time'],
                                                                     end_time=values['end_time']))
        except sqlite3.IntegrityError:
            debug("Some data already exists on DB for that key. Updating their values...", 2)
            self.db_cursor.execute(self.sql_cloudwatch_update.format(table_name=self.db_table_name,
                                                                     aws_region=self.region,
                                                                     aws_log_group=log_group,
                                                                     aws_log_stream=log_stream,
                                                                     next_token=values['token'],
                                                                     start_time=values['start_time'],
                                                                     end_time=values['end_time']))

    def get_log_streams(self, log_group):
        """Get the list of log streams stored in the specified log group.

        Parameters
        ----------
        log_group : str
            Name of the log group to get its log streams

        Returns
        -------
        A list with the name of each log stream for the given log group.
        """

        result_list = list()
        try:
            debug('Getting log streams for "{}" log group'.format(log_group), 1)
            response = self.client.describe_log_streams(logGroupName=log_group)

            for log_stream in response['logStreams']:
                debug('Found "{}" log stream in {}'.format(log_stream['logStreamName'], log_group), 2)
                result_list.append(log_stream['logStreamName'])

            if result_list == list():
                debug('No log streams were found for log group "{}"'.format(log_group), 1)
        except Exception:
            debug('++++ The specified "{}" log group does not exist or insufficient privileges to access it.'.format(log_group), 0)

        return result_list

    def purge_db(self, log_group):
        """Remove from AWS_Service.db any record for log streams that no longer exists on AWS CloudWatch.

        Parameters
        ----------
        log group : str
            Name of the log group to check its log streams
        """
        debug('Purging the BD', 1)
        # Get the list of log streams from DB
        self.db_cursor.execute(self.sql_cloudwatch_select_logstreams.format(table_name=self.db_table_name,
                                                                            aws_region=self.region,
                                                                            aws_log_group=log_group))
        query_result = self.db_cursor.fetchall()
        log_streams_sql = set()
        for log_stream in query_result:
            log_streams_sql.add(log_stream[0])

        # Get the list of log streams from AWS
        log_streams_aws = set(self.get_log_streams(log_group))

        # Check the difference and remove if applicable
        log_streams_to_purge = log_streams_sql - log_streams_aws
        if log_streams_to_purge != set():
            debug('Data for the following log streams will be removed from {}: "{}"'.format(self.db_table_name,
                                                                                            log_streams_to_purge), 2)
        for log_stream in log_streams_to_purge:
            self.db_cursor.execute(self.sql_cloudwatch_purge.format(table_name=self.db_table_name,
                                                                    aws_region=self.region,
                                                                    aws_log_group=log_group,
                                                                    aws_log_stream=log_stream))

    def close_database(self):
        """Commit the changes to the DB and close the connection."""
        debug("committing changes and closing the DB", 1)
        self.db_connector.commit()
        self.close_db()


################################################################################
# Functions
################################################################################

def handler(signal, frame):
    print("ERROR: SIGINT received.")
    sys.exit(12)


def debug(msg, msg_level):
    if debug_level >= msg_level:
        print('DEBUG: {debug_msg}'.format(debug_msg=msg))


def arg_valid_date(arg_string):
    try:
        parsed_date = datetime.strptime(arg_string, "%Y-%b-%d")
        # Return int created from date in YYYYMMDD format
        return parsed_date.strftime('%Y%m%d')
    except ValueError:
        raise argparse.ArgumentTypeError("Argument not a valid date in format YYYY-MMM-DD: '{0}'.".format(arg_string))


def arg_valid_prefix(arg_string):
    if arg_string and arg_string[-1] != '/' and arg_string[-1] != "\\":
        return '{arg_string}/'.format(arg_string=arg_string)
    return arg_string


def arg_valid_accountid(arg_string):
    if arg_string is None:
        return []
    account_ids = arg_string.split(',')
    for account in account_ids:
        if not account.strip().isdigit() and len(account) != 12:
            raise argparse.ArgumentTypeError(
                "Not valid AWS account ID (numeric digits only): '{0}'.".format(arg_string))

    return account_ids


def arg_valid_regions(arg_string):
    if not arg_string:
        return []
    final_regions = []
    regions = arg_string.split(',')
    for arg_region in regions:
        if arg_region.strip():
            final_regions.append(arg_region.strip())
    return final_regions


def get_script_arguments():
    parser = argparse.ArgumentParser(usage="usage: %(prog)s [options]",
                                     description="Wazuh wodle for monitoring AWS",
                                     formatter_class=argparse.RawTextHelpFormatter)
    # only one must be present (bucket or service)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-b', '--bucket', dest='logBucket', help='Specify the S3 bucket containing AWS logs',
                       action='store')
    group.add_argument('-sr', '--service', dest='service', help='Specify the name of the service',
                       action='store')
    parser.add_argument('-O', '--aws_organization_id', dest='aws_organization_id',
                        help='AWS organization ID for logs', required=False)
    parser.add_argument('-c', '--aws_account_id', dest='aws_account_id',
                        help='AWS Account ID for logs', required=False,
                        type=arg_valid_accountid)
    parser.add_argument('-d', '--debug', action='store', dest='debug', default=0, help='Enable debug')
    parser.add_argument('-a', '--access_key', dest='access_key', help='S3 Access key credential', default=None)
    parser.add_argument('-k', '--secret_key', dest='secret_key', help='S3 Secret key credential', default=None)
    # Beware, once you delete history it's gone.
    parser.add_argument('-R', '--remove', action='store_true', dest='deleteFile',
                        help='Remove processed files from the AWS S3 bucket', default=False)
    parser.add_argument('-p', '--aws_profile', dest='aws_profile', help='The name of credential profile to use',
                        default=None)
    parser.add_argument('-i', '--iam_role_arn', dest='iam_role_arn',
                        help='ARN of IAM role to assume for access to S3 bucket',
                        default=None)
    parser.add_argument('-n', '--aws_account_alias', dest='aws_account_alias',
                        help='AWS Account ID Alias', default='')
    parser.add_argument('-l', '--trail_prefix', dest='trail_prefix',
                        help='Log prefix for S3 key',
                        default='', type=arg_valid_prefix)
    parser.add_argument('-s', '--only_logs_after', dest='only_logs_after',
                        help='Only parse logs after this date - format YYYY-MMM-DD',
                        default=datetime.strftime(datetime.utcnow(), '%Y-%b-%d'), type=arg_valid_date)
    parser.add_argument('-r', '--regions', dest='regions', help='Comma delimited list of AWS regions to parse logs',
                        default='', type=arg_valid_regions)
    parser.add_argument('-e', '--skip_on_error', action='store_true', dest='skip_on_error',
                        help='If fail to parse a file, error out instead of skipping the file', default=True)
    parser.add_argument('-o', '--reparse', action='store_true', dest='reparse',
                        help='Parse the log file, even if its been parsed before', default=False)
    parser.add_argument('-t', '--type', dest='type', type=str, help='Bucket type.', default='cloudtrail')
    parser.add_argument('-g', '--aws_log_groups', dest='aws_log_groups', help='Name of the log group to be parsed',
                        default='')
    parser.add_argument('-P', '--remove-log-streams', action='store_true', dest='deleteLogStreams',
                        help='Remove processed log streams from the log group', default=False)

    return parser.parse_args()


# Main
###############################################################################


def main(argv):
    # Parse arguments
    options = get_script_arguments()

    if int(options.debug) > 0:
        global debug_level
        debug_level = int(options.debug)
        debug('+++ Debug mode on - Level: {debug}'.format(debug=options.debug), 1)

    try:
        if options.logBucket:
            if options.type.lower() == 'cloudtrail':
                bucket_type = AWSCloudTrailBucket
            elif options.type.lower() == 'vpcflow':
                bucket_type = AWSVPCFlowBucket
            elif options.type.lower() == 'config':
                bucket_type = AWSConfigBucket
            elif options.type.lower() == 'custom':
                bucket_type = AWSCustomBucket
            elif options.type.lower() == 'guardduty':
                bucket_type = AWSGuardDutyBucket
            elif options.type.lower() == 'cisco_umbrella':
                bucket_type = CiscoUmbrella
            elif options.type.lower() == 'waf':
                bucket_type = AWSWAFBucket
            elif options.type.lower() == 'alb':
                bucket_type = AWSALBBucket
            elif options.type.lower() == 'clb':
                bucket_type = AWSCLBBucket
            elif options.type.lower() == 'nlb':
                bucket_type = AWSNLBBucket
            else:
                raise Exception("Invalid type of bucket")
            bucket = bucket_type(reparse=options.reparse, access_key=options.access_key,
                                 secret_key=options.secret_key,
                                 profile=options.aws_profile,
                                 iam_role_arn=options.iam_role_arn,
                                 bucket=options.logBucket,
                                 only_logs_after=options.only_logs_after,
                                 skip_on_error=options.skip_on_error,
                                 account_alias=options.aws_account_alias,
                                 prefix=options.trail_prefix,
                                 delete_file=options.deleteFile,
                                 aws_organization_id=options.aws_organization_id,
                                 region=options.regions[0] if options.regions else None
                                 )
            # check if bucket is empty or credentials are wrong
            bucket.check_bucket()
            bucket.iter_bucket(options.aws_account_id, options.regions)
        elif options.service:
            if options.service.lower() == 'inspector':
                service_type = AWSInspector
            elif options.service.lower() == 'cloudwatchlogs':
                service_type = AWSCloudWatchLogs
            else:
                raise Exception("Invalid type of service")

            if not options.regions:
                debug("+++ Warning: No regions were specified, trying to get events from all regions", 1)
                options.regions = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
                                   'ap-northeast-1', 'ap-northeast-2', 'ap-southeast-2', 'ap-south-1',
                                   'eu-central-1', 'eu-west-1']

            for region in options.regions:
                debug('+++ Getting alerts from "{}" region.'.format(region), 1)
                service = service_type(reparse=options.reparse,
                                       access_key=options.access_key,
                                       secret_key=options.secret_key,
                                       aws_profile=options.aws_profile,
                                       iam_role_arn=options.iam_role_arn,
                                       only_logs_after=options.only_logs_after,
                                       region=region,
                                       aws_log_groups=options.aws_log_groups,
                                       remove_log_streams=options.deleteLogStreams)
                service.get_alerts()

    except Exception as err:
        debug("+++ Error: {}".format(err), 2)
        if debug_level > 0:
            raise
        print("ERROR: {}".format(err))
        sys.exit(12)


if __name__ == '__main__':
    try:
        debug('Args: {args}'.format(args=str(sys.argv)), 2)
        signal.signal(signal.SIGINT, handler)
        main(sys.argv[1:])
        sys.exit(0)
    except Exception as e:
        print("Unknown error: {}".format(e))
        if debug_level > 0:
            raise
        sys.exit(1)
