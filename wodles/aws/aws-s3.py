#!/usr/bin/env python
#
# Import AWS S3
#
# Author: Wazuh, Inc.
# Copyright: GPLv3
#
# Updated by Jeremy Phillips <jeremy@uranusbytes.com>
# Full re-work of AWS wodle as per #510
# - Scalability and functional enhancements for parsing of CloudTrail
# - Support for existing config params
# - Upgrade to a granular object key addressing to support multiple CloudTrails in S3 bucket
# - Support granular parsing by account id, region, prefix
# - Support only parsing logs after a given date
# - Support IAM credential profiles, IAM roles
# - Only look for new logs/objects since last iteration
# - Skip digest files altogether (only look at logs)
# - Move from downloading object and working with file on filesystem to byte stream
# - Inherit debug from modulesd
# - Add bounds checks for msg against socket buffer size; truncate fields if too big (wazuh/wazuh#733)
# - Support multiple debug levels
# - Move connect error so not confused with general error
# - If fail to parse log, and skip_on_error, attempt to send me msg to wazuh
# - Support existing configurations by migrating data, inferring other required params
# - Reparse flag to support re-parsing of log files from s3 bucket
# - Use CloudTrail timestamp for ES timestamp
#
# Future
# ToDo: Integrity check logs against digest
# ToDo: Escape special characters in arguments?  Needed?
#     Valid values for AWS Keys
#     Alphanumeric characters [0-9a-zA-Z]
#     Special characters !, -, _, ., *, ', (, and )
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
from datetime import datetime
from os import path
import operator

################################################################################
# Constants
################################################################################

# Enable/disable debug mode
debug_level = 0

# DB Query SQL
sql_already_processed = """
                          SELECT
                            count(*)
                          FROM
                            trail_progress
                          WHERE
                            aws_account_id='{aws_account_id}' AND
                            aws_region='{aws_region}' AND
                            log_key='{log_name}'"""

sql_mark_complete = """
                      INSERT INTO trail_progress (
                        aws_account_id,
                        aws_region,
                        log_key,
                        processed_date,
                        created_date) VALUES (
                        '{aws_account_id}',
                        '{aws_region}',
                        '{log_key}',
                        DATETIME('now'),
                        '{created_date}')"""

sql_select_migrate_legacy = """
                               SELECT
                                 log_name,
                                 processed_date
                               FROM
                                 log_progress;"""

sql_rename_migrate_legacy = """
                              ALTER TABLE log_progress
                                RENAME TO legacy_log_progress;"""

sql_find_table_names = """
                           SELECT
                             tbl_name
                           FROM
                             sqlite_master
                           WHERE
                             type='table';"""

sql_create_table = """
                      CREATE TABLE
                        trail_progress (
                          aws_account_id 'text' NOT NULL,
                          aws_region 'text' NOT NULL,
                          log_key 'text' NOT NULL,
                          processed_date 'text' NOT NULL,
                          created_date 'integer' NOT NULL,
                          PRIMARY KEY (aws_account_id, aws_region, log_key));"""

sql_find_last_log_processed = """
                                  SELECT
                                    created_date
                                  FROM
                                    trail_progress
                                  WHERE
                                    aws_account_id='{aws_account_id}' AND
                                    aws_region = '{aws_region}'
                                  ORDER BY
                                    ROWID DESC
                                  LIMIT 1;"""

sql_db_maintenance = """DELETE
                       FROM
                         trail_progress
                       WHERE
                         aws_account_id='{aws_account_id}' AND
                         aws_region='{aws_region}' AND
                         rowid NOT IN
                           (SELECT ROWID
                            FROM
                              trail_progress
                            WHERE
                              aws_account_id='{aws_account_id}' AND
                              aws_region='{aws_region}'
                            ORDER BY
                              ROWID DESC
                            LIMIT {retain_db_records})"""

sql_db_optimize = "PRAGMA optimize;"


################################################################################
# Classes
################################################################################

class AWSBucket:
    """
    Represents a bucket with events on the inside.

    This is an abstract class
    """

    def __init__(self, reparse, access_key, secret_key, profile, iam_role_arn,
                 bucket, only_logs_after, skip_on_error, account_alias,
                 max_queue_buffer, prefix, delete_file):
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
        :param max_queue_buffer: Maximum event length
        :param prefix: Prefix to filter files in bucket
        :param delete_file: Wether to delete an already processed file from a bucket or not
        """
        self.wazuh_path = open('/etc/ossec-init.conf').readline().split('"')[1]
        self.wazuh_queue = '{0}/queue/ossec/queue'.format(self.wazuh_path)
        self.wazuh_wodle = '{0}/wodles/aws'.format(self.wazuh_path)
        self.msg_header = "1:Wazuh-AWS:"
        self.legacy_db_table_name = 'log_progress'
        self.db_table_name = 'trail_progress'
        self.db_path = "{0}/s3_cloudtrail.db".format(self.wazuh_wodle)
        self.db_connector = sqlite3.connect(self.db_path)
        self.retain_db_records = 100
        self.reparse = reparse
        self.bucket = bucket
        self.client = self.get_s3_client(access_key, secret_key, profile, iam_role_arn)
        self.only_logs_after = datetime.strptime(only_logs_after, "%Y%m%d")
        self.skip_on_error = skip_on_error
        self.account_alias = account_alias
        self.max_queue_buffer = max_queue_buffer
        self.prefix = prefix
        self.delete_file = delete_file

    def get_s3_client(self, access_key, secret_key, profile, iam_role_arn):
        conn_args = {}
        if access_key is not None and secret_key is not None:
            conn_args['aws_access_key_id'] = access_key
            conn_args['aws_secret_access_key'] = secret_key
        if profile is not None:
            conn_args['profile_name'] = profile

        boto_session = boto3.Session(**conn_args)

        # If using a role, create session using that
        try:
            if iam_role_arn:
                sts_client = boto_session.client('sts')
                sts_role_assumption = sts_client.assume_role(RoleArn=iam_role_arn,
                                                             RoleSessionName='WazuhLogParsing')
                sts_session = boto3.Session(aws_access_key_id=sts_role_assumption['Credentials']['AccessKeyId'],
                                            aws_secret_access_key=sts_role_assumption['Credentials']['SecretAccessKey'],
                                            aws_session_token=sts_role_assumption['Credentials']['SessionToken'])
                s3_client = sts_session.client(service_name='s3')
            else:
                s3_client = boto_session.client(service_name='s3')
                s3_client.head_bucket(Bucket=self.bucket)
        except botocore.exceptions.ClientError as e:
            print("ERROR: Bucket {} access error: {}".format(self.bucket, e))
            sys.exit(3)
        return s3_client

    def send_msg(self, msg):
        """
        Sends an AWS event to the Wazuh Queue

        :param msg: JSON message to be sent.
        """
        try:
            json_msg = json.dumps(msg)
            debug(json_msg, 3)
            s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            s.connect(self.wazuh_queue)
            s.send("{header}{msg}".format(header=self.msg_header,
                                          msg=json_msg).encode())
            s.close()
        except socket.error as e:
            if e.errno == 111:
                print('ERROR: Wazuh must be running.')
                sys.exit(11)
            else:
                print("ERROR: Error sending message to wazuh: {}".format(e))
                sys.exit(13)
        except Exception as e:
            print("ERROR: Error sending message to wazuh: {}".format(e))
            sys.exit(13)

    def already_processed(self, downloaded_file, aws_account_id, aws_region):
        cursor = self.db_connector.execute(sql_already_processed.format(
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
                self.db_connector.execute(sql_mark_complete.format(
                    aws_account_id=aws_account_id,
                    aws_region=aws_region,
                    log_key=log_file['Key'],
                    created_date=self.get_creation_date(log_file)
                ))
            except Exception as e:
                debug("+++ Error marking log {} as completed: {}".format(log_file['Key'], e), 2)
                raise e

    def migrate_legacy_table(self):
        raise NotImplementedError

    def create_table(self):
        try:
            debug('+++ Table does not exist; create', 1)
            self.db_connector.execute(sql_create_table)
        except Exception as e:
            print("ERROR: Unable to create SQLite DB: {}".format(e))
            sys.exit(6)

    def init_db(self):
        try:
            tables = set(map(operator.itemgetter(0), self.db_connector.execute(sql_find_table_names)))
        except Exception as e:
            print("ERROR: Unexpected error accessing SQLite DB: {}".format(e))
            sys.exit(5)

        # DB does exist yet
        if self.db_table_name not in tables:
            self.create_table()

        # Legacy table exists; migrate progress to new table
        if self.legacy_db_table_name in tables:
            self.migrate_legacy_table()

    def db_maintenance(self, aws_account_id, aws_region):
        debug("+++ DB Maintenance", 1)
        try:
            self.db_connector.execute(sql_db_maintenance.format(
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
            msg['aws'].update({key: value for key, value in filter(lambda x: x[1] is not None, event.items())})
        elif error_msg:
            msg['error_msg'] = error_msg
        return msg

    def get_full_prefix(self, account_id, account_region):
        raise NotImplementedError

    def build_s3_filter_args(self, aws_account_id, aws_region):
        filter_marker = ''
        if self.reparse:
            if self.only_logs_after:
                filter_marker = self.marker_only_logs_after(aws_region, aws_account_id)
        else:
            # Where did we end last run thru on this account/region?
            query_results = self.db_connector.execute(sql_find_last_log_processed.format(aws_account_id=aws_account_id,
                                                                                         aws_region=aws_region))
            try:
                created_date = query_results.fetchone()[0]
                # Existing logs processed, but older than only_logs_after
                if int(created_date) < int(self.only_logs_after.strftime('%Y%m%d')):
                    filter_marker = self.marker_only_logs_after(aws_region, aws_account_id)
            except TypeError:
                # No logs processed for this account/region, but if only_logs_after has been set
                if self.only_logs_after:
                    filter_marker = self.marker_only_logs_after(aws_region, aws_account_id)
        filter_args = {
            'Bucket': self.bucket,
            'MaxKeys': 1000,
            'Prefix': self.get_full_prefix(aws_account_id, aws_region)
        }
        if filter_marker:
            filter_args['StartAfter'] = filter_marker
            debug('+++ Marker: {0}'.format(filter_marker), 2)
        return filter_args

    def reformat_msg(self, event):
        raise NotImplementedError

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

        def json_event_generator(data):
            while data:
                json_data, json_index = decoder.raw_decode(data)
                data = data[json_index:]
                yield json_data

        with self.decompress_file(log_key=log_key) as f:
            if '.json' in log_key:
                json_file = json.load(f)
                return None if 'Records' not in json_file else [dict(x, source='cloudtrail') for x in
                                                                json_file['Records']]
            elif f.read(1) == '{':
                decoder = json.JSONDecoder()
                return [dict(event['detail'], source=event['source'].replace('aws.', '')) for event in
                        json_event_generator('{' + f.read()) if 'detail' in event]
            else:
                fieldnames = (
                "version", "account_id", "interface_id", "srcaddr", "dstaddr", "srcport", "dstport", "protocol",
                "packets", "bytes", "start", "end", "action", "log_status")
                tsv_file = csv.DictReader(f, fieldnames=fieldnames, delimiter=' ')
                return [dict(x, source='vpc') for x in tsv_file]

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
        self.db_connector.execute(sql_db_optimize)
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

    def iter_files_in_bucket(self, aws_account_id, aws_region):
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
        except SystemExit:
            raise
        except Exception as err:
            if hasattr(err, 'message'):
                debug("+++ Unexpected error: {}".format(err.message), 2)
            else:
                debug("+++ Unexpected error: {}".format(err), 2)
            print("ERROR: Unexpected error querying/working with objects in S3: {}".format(err))
            sys.exit(7)


class AWSCloudtrailBucket(AWSBucket):
    """
    Represents a bucket with cloudtrail logs
    """

    def get_full_prefix(self, account_id, account_region):
        return '{trail_prefix}AWSLogs/{aws_account_id}/CloudTrail/{aws_region}/'.format(
            trail_prefix=self.prefix,
            aws_account_id=account_id,
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

    def migrate_legacy_table(self):
        for row in filter(lambda x: x[0] != '', self.db_connector(sql_select_migrate_legacy)):
            try:
                aws_region, aws_account_id, new_filename = self.get_extra_data_from_filename(row[0])
                self.mark_complete(aws_account_id, aws_region, {'Key': new_filename})
            except Exception as e:
                debug("++ Error parsing log file name: {}".format(row[0]), 1)

    def get_alert_msg(self, aws_account_id, log_key, event, error_msg=""):
        alert_msg = AWSBucket.get_alert_msg(self, aws_account_id, log_key, event, error_msg)
        alert_msg['aws']['aws_account_id'] = aws_account_id
        return alert_msg

    def reformat_msg(self, event):
        debug('++ Reformat message', 3)
        # Some fields in CloudTrail are dynamic in nature, which causes problems for ES mapping
        for field_to_str in ['additionalEventData', 'responseElements', 'requestParameters']:
            if field_to_str in event['aws']:
                try:
                    debug('++ Reformat field: {}'.format(field_to_str), 3)
                    # Nested json
                    if 'policyDocument' in event['aws'][field_to_str]:
                        event['aws']['{}_policyDocument'.format(field_to_str)] = json.dumps(
                            event['aws'][field_to_str]['policyDocument'],
                            ensure_ascii=True,
                            indent=2,
                            sort_keys=True)
                        event['aws'][field_to_str]['policyDocument'] = 'See field {}_policyDocument'.format(
                            field_to_str)
                    event['aws'][field_to_str] = json.dumps(
                        event['aws'][field_to_str],
                        ensure_ascii=True,
                        indent=2,
                        sort_keys=True)
                except:
                    debug('++ Failed to convert field to string: {}'.format(field_to_str), 1)
                    event['aws'][field_to_str] = 'Unable to convert field to string: {field}'.format(field=field_to_str)

        debug('++ Shrink message', 3)
        # If msg too large, start truncating
        for field_to_shrink in ['additionalEventData', 'responseElements', 'requestParameters']:
            if field_to_shrink not in event['aws']:
                continue
            if event['aws'][field_to_shrink] == 'Unable to convert field to string: {field}'.format(field=field_to_shrink):
                continue

            if len(json.dumps(event).encode()) > self.max_queue_buffer:
                debug('++ Message too large; truncating {field}'.format(field=field_to_shrink), 2)
                event['aws'][field_to_shrink] = 'Value truncated because event msg too large for socket buffer'
            else:
                debug('++ Message not too large; skip out', 3)
                break
        return event

    def find_account_ids(self):
        return [common_prefix['Prefix'].split('/')[-2] for common_prefix in
                self.client.list_objects_v2(Bucket=self.bucket,
                                            Prefix='{}AWSLogs/'.format(self.prefix),
                                            Delimiter='/')['CommonPrefixes']
                ]

    def find_regions(self, account_id):
        regions_prefix = '{trail_prefix}AWSLogs/{aws_account_id}/CloudTrail/'.format(
            trail_prefix=self.prefix,
            aws_account_id=account_id)
        regions = self.client.list_objects_v2(Bucket=self.bucket,
                                              Prefix=regions_prefix,
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
                debug("+++ Working on {} - {}".format(aws_account_id, aws_region), 1)
                self.iter_files_in_bucket(aws_account_id, aws_region)
                self.db_maintenance(aws_account_id, aws_region)


class AWSFirehouseBucket(AWSBucket):
    def __init__(self, *args):
        AWSBucket.__init__(self, *args)
        self.retain_db_records = 1000  # in firehouse logs there are no regions/users, this number must be increased.

    def get_creation_date(self, log_file):
        # The Amazon S3 object name follows the pattern DeliveryStreamName-DeliveryStreamVersion-YYYY-MM-DD-HH-MM-SS-RandomString
        name_regex = re.match(r"^[\w\-]+(\d\d\d\d-\d\d-\d\d)[\w\-.]+$", path.basename(log_file['Key']))
        if name_regex is None:
            return log_file['LastModified'].strftime('%Y%m%d')
        else:
            return int(name_regex.group(1).replace('-', ''))

    def migrate_legacy_table(self):
        # Firehouse events aren't legacy. No migration is needed.
        debug("+++ Migrating firehouse events. Skipping...", 1)

    def get_full_prefix(self, account_id, account_region):
        return self.prefix

    def reformat_msg(self, event):
        def single_element_list_to_dictionary(my_event):
            for name, value in my_event.items():
                if isinstance(value, list) and len(value) == 1:
                    my_event[name] = value[0]
                elif isinstance(value, dict):
                    single_element_list_to_dictionary(my_event[name])

        try:
            # remove aws.event.trigger field, since it has repeated data and increases log size.
            if event['aws']['source'] == 'macie' and 'trigger' in event['aws']:
                del event['aws']['trigger']

            # turn some list fields into dictionaries
            single_element_list_to_dictionary(event)

        except Exception as e:
            debug("Error reformatting event {}.".format(json.dumps(event)), 2)
            raise e

        return event

    def iter_regions_and_accounts(self, account_id, regions):
        # Only <self.retain_db_records> logs for each region are stored in DB. Using self.bucket as region name
        # would prevent to loose lots of logs from different buckets.
        self.iter_files_in_bucket('', self.bucket)
        self.db_maintenance('', self.bucket)


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
                                     description="Wazuh wodle for monitoring of AWS logs in S3 bucket",
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-b', '--bucket', dest='logBucket', help='Specify the S3 bucket containing AWS logs',
                        action='store', required=True)
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
                        help='Only parse logs after this date - format YYYY-MMM-DD', default='1970-JAN-01',
                        type=arg_valid_date)
    parser.add_argument('-r', '--regions', dest='regions', help='Comma delimited list of AWS regions to parse logs',
                        default='', type=arg_valid_regions)
    parser.add_argument('-e', '--skip_on_error', action='store_true', dest='skip_on_error',
                        help='If fail to parse a file, error out instead of skipping the file', default=True)
    parser.add_argument('-o', '--reparse', action='store_true', dest='reparse',
                        help='Parse the log file, even if its been parsed before', default=False)
    parser.add_argument('-t', '--type', dest='type', type=str, help='Bucket type.', default='cloudtrail')
    return parser.parse_args()


# Main
###############################################################################


def main(argv):
    # Parse arguments
    options = get_script_arguments()

    # Get socket buffer size
    with open('/proc/sys/net/core/rmem_max', 'r') as kernel_param:
        max_queue_buffer = int(kernel_param.read().strip())

    if int(options.debug) > 0:
        global debug_level
        debug_level = int(options.debug)
        debug('+++ Debug mode on - Level: {debug}'.format(debug=options.debug), 1)

    bucket_type = AWSCloudtrailBucket if options.type.lower() == 'cloudtrail' else AWSFirehouseBucket
    bucket = bucket_type(options.reparse, options.access_key, options.secret_key,
                         options.aws_profile, options.iam_role_arn, options.logBucket,
                         options.only_logs_after, options.skip_on_error,
                         options.aws_account_alias, max_queue_buffer,
                         options.trail_prefix, options.deleteFile)
    bucket.iter_bucket(options.aws_account_id, options.regions)


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
