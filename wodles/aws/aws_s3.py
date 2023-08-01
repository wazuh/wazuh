#!/usr/bin/env python3
# Import AWS S3
#
# Copyright (C) 2015, Wazuh Inc.
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
#   10 - pyarrow module missing
#   11 - Unable to connect to Wazuh
#   12 - Invalid type of bucket
#   13 - Unexpected error sending message to Wazuh
#   14 - Empty bucket
#   15 - Invalid endpoint URL
#   16 - Throttling error
#   17 - Invalid key format
#   18 - Invalid prefix
#   19 - The server datetime and datetime of the AWS environment differ
#   20 - Unable to find SQS
#   21 - Failed fetch/delete from SQS
#   22 - Invalid region
#   23 - Profile not found

import argparse
import configparser
import signal
import socket
import sqlite3
import sys
from typing import Optional

try:
    import boto3
except ImportError:
    print('ERROR: boto3 module is required.')
    sys.exit(4)

try:
    import pyarrow.parquet as pq
except ImportError:
    print('ERROR: pyarrow module is required.')
    sys.exit(10)

import botocore
import json
import csv
import gzip
import zipfile
import re
import io
import zlib
from os import path
import operator
from datetime import datetime, timezone
from time import mktime

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))
import utils

# Python 2/3 compatibility
if sys.version_info[0] == 3:
    unicode = str

################################################################################
# Constants
################################################################################

CREDENTIALS_URL = 'https://documentation.wazuh.com/current/amazon/services/prerequisites/credentials.html'
RETRY_CONFIGURATION_URL = 'https://documentation.wazuh.com/current/amazon/services/prerequisites/considerations.html' \
                          '#Connection-configuration-for-retries'
DEPRECATED_MESSAGE = 'The {name} authentication parameter was deprecated in {release}. ' \
                     'Please use another authentication method instead. Check {url} for more information.'
GUARDDUTY_URL = 'https://documentation.wazuh.com/current/amazon/services/supported-services/guardduty.html'
GUARDDUTY_DEPRECATED_MESSAGE = 'The functionality to process GuardDuty logs stored in S3 via Kinesis was deprecated ' \
                               'in {release}. Consider configuring GuardDuty to store its findings directly in an S3 ' \
                               'bucket instead. Check {url} for more information. '
DEFAULT_AWS_CONFIG_PATH = path.join(path.expanduser('~'), '.aws', 'config')

# Enable/disable debug mode
debug_level = 0
INVALID_CREDENTIALS_ERROR_CODE = "SignatureDoesNotMatch"
INVALID_REQUEST_TIME_ERROR_CODE = "RequestTimeTooSkewed"
THROTTLING_EXCEPTION_ERROR_CODE = "ThrottlingException"

INVALID_CREDENTIALS_ERROR_MESSAGE = "Invalid credentials to access S3 Bucket"
INVALID_REQUEST_TIME_ERROR_MESSAGE = "The server datetime and datetime of the AWS environment differ"
THROTTLING_EXCEPTION_ERROR_MESSAGE = "The '{name}' request was denied due to request throttling. If the problem " \
                                     "persists check the following link to learn how to use the Retry configuration " \
                                     f"to avoid it: {RETRY_CONFIGURATION_URL}'"
RETRY_ATTEMPTS_KEY: str = "max_attempts"
RETRY_MODE_CONFIG_KEY: str = "retry_mode"
RETRY_MODE_BOTO_KEY: str = "mode"


ALL_REGIONS = [
    'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ap-northeast-1', 'ap-northeast-2', 'ap-southeast-2',
    'ap-south-1', 'eu-central-1', 'eu-west-1'
]


################################################################################
# Helpers functions
################################################################################

def set_profile_dict_config(boto_config: dict, profile: str, profile_config: dict):
    """Create a botocore.config.Config object with the specified profile and profile_config.

    This function reads the profile configuration from the provided profile_config object and extracts the necessary
    parameters to create a botocore.config.Config object.
    It handles the signature version, s3, proxies, and proxies_config settings found in the .aws/config file for the
    specified profile. If a setting is not found, a default value is used based on the boto3 documentation and config is
    set into the boto_config.

    Parameters
    ----------
    boto_config: dict
        The config dictionary where the Boto Config will be set.

    profile : str
        The AWS profile name to use for the configuration.

    profile_config : dict
        The user config dict containing the profile configuration.
    """
    # Set s3 config
    if f'{profile}.s3' in str(profile_config):
        s3_config = {
            "max_concurrent_requests": int(profile_config.get(f'{profile}.s3.max_concurrent_requests', 10)),
            "max_queue_size": int(profile_config.get(f'{profile}.s3.max_queue_size', 10)),
            "multipart_threshold": profile_config.get(f'{profile}.s3.multipart_threshold', '8MB'),
            "multipart_chunksize": profile_config.get(f'{profile}.s3.multipart_chunksize', '8MB'),
            "max_bandwidth": profile_config.get(f'{profile}.s3.max_bandwidth'),
            "use_accelerate_endpoint": (
                True if profile_config.get(f'{profile}.s3.use_accelerate_endpoint') == 'true' else False
            ),
            "addressing_style": profile_config.get(f'{profile}.s3.addressing_style', 'auto'),
        }
        boto_config['config'].s3 = s3_config

    # Set Proxies configuration
    if f'{profile}.proxy' in str(profile_config):
        proxy_config = {
            "host": profile_config.get(f'{profile}.proxy.host'),
            "port": int(profile_config.get(f'{profile}.proxy.port')),
            "username": profile_config.get(f'{profile}.proxy.username'),
            "password": profile_config.get(f'{profile}.proxy.password'),
        }
        boto_config['config'].proxies = proxy_config

        proxies_config = {
            "ca_bundle": profile_config.get(f'{profile}.proxy.ca_bundle'),
            "client_cert": profile_config.get(f'{profile}.proxy.client_cert'),
            "use_forwarding_for_https": (
                True if profile_config.get(f'{profile}.proxy.use_forwarding_for_https') == 'true' else False
            )
        }
        boto_config['config'].proxies_config = proxies_config


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
    :param iam_role_duration: The desired duration of the session that is going to be assumed.
    :param external_id: AWS external ID for IAM Role assumption
    """

    def __init__(self, access_key, secret_key, aws_profile, iam_role_arn,
                 service_name=None, region=None, bucket=None, discard_field=None,
                 discard_regex=None, sts_endpoint=None, service_endpoint=None, iam_role_duration=None,
                 external_id=None):
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
            CREATE TABLE metadata (
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
                name=:name;
            """

        self.sql_insert_version_metadata = """
            INSERT INTO metadata (
                key,
                value)
            VALUES (
                'version',
                :wazuh_version);"""

        self.sql_update_version_metadata = """
            UPDATE
                metadata
            SET
                value=:wazuh_version
            WHERE
                key='version';
            """

        self.sql_drop_table = "DROP TABLE {table_name};"

        self.wazuh_path = utils.find_wazuh_path()
        self.wazuh_version = utils.get_wazuh_version()
        self.wazuh_queue = '{0}/queue/sockets/queue'.format(self.wazuh_path)
        self.wazuh_wodle = '{0}/wodles/aws'.format(self.wazuh_path)
        self.msg_header = "1:Wazuh-AWS:"
        # GovCloud regions
        self.gov_regions = {'us-gov-east-1', 'us-gov-west-1'}

        self.connection_config = self.default_config(profile=aws_profile)

        self.client = self.get_client(access_key=access_key,
                                      secret_key=secret_key,
                                      profile=aws_profile,
                                      iam_role_arn=iam_role_arn,
                                      service_name=service_name,
                                      bucket=bucket,
                                      region=region,
                                      sts_endpoint=sts_endpoint,
                                      service_endpoint=service_endpoint,
                                      iam_role_duration=iam_role_duration,
                                      external_id=external_id
                                      )


        if hasattr(self, 'db_name'):  # If db_name is present, the subclass is not part of the SecLake process
            # db_name is an instance variable of subclass
            self.db_path = "{0}/{1}.db".format(self.wazuh_wodle, self.db_name)
            self.db_connector = sqlite3.connect(self.db_path)
            self.db_cursor = self.db_connector.cursor()
            self.check_metadata_version()
        if bucket:
            self.bucket = bucket

        self.discard_field = discard_field
        self.discard_regex = re.compile(fr'{discard_regex}')
        # to fetch logs using this date if no only_logs_after value was provided on the first execution
        self.default_date = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0, tzinfo=timezone.utc)

    def check_metadata_version(self):
        try:
            query_metadata = self.db_connector.execute(self.sql_find_table, {'name': 'metadata'})
            metadata = True if query_metadata.fetchone() else False
            if metadata:
                query_version = self.db_connector.execute(self.sql_get_metadata_version)
                metadata_version = query_version.fetchone()[0]
                # update Wazuh version in metadata table
                if metadata_version != self.wazuh_version:
                    self.db_connector.execute(self.sql_update_version_metadata, {'wazuh_version': self.wazuh_version})
                    self.db_connector.commit()
            else:
                # create metadate table
                self.db_connector.execute(self.sql_create_metadata_table)
                # insert wazuh version value
                self.db_connector.execute(self.sql_insert_version_metadata, {'wazuh_version': self.wazuh_version})
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

    @staticmethod
    def default_config(profile: str) -> dict:
        """Set the parameters found in user config file as a default configuration for client.

        This method is called when Wazuh Integration is instantiated and sets a default config using .aws/config file
        using the profile received from parameter.

        If .aws/config file exist the file is retrieved and read to check for the existence of retry parameters mode and
        max attempts if they exist and empty dictionary is returned and config is handled by botocore but if they don't
        exist a botocore Config object is created and default configuration is set using user config for received
        profile and retries parameters are set to avoid a throttling exception.

        Parameters
        ----------
        profile : string
                Aws profile configuration to use.

        Returns
        -------
        dict
            Configuration dictionary.

        Raises
        ------
        KeyError
            KeyError when there is no region in user config file.

        ValueError
            ValueError when there is an error parsing config file.

        NoSectionError
            configparser error when given profile does not exist in user config file.
        """
        args = {}

        if path.exists(DEFAULT_AWS_CONFIG_PATH):
            # Create boto Config object
            args['config'] = botocore.config.Config()

            # Get User Aws Config
            aws_config = get_aws_config_params()

            # Set profile
            profile = profile if profile is not None else 'default'

            try:
                # Get profile config dictionary
                profile_config = {option: aws_config.get(profile, option) for option in aws_config.options(profile)}

            except configparser.NoSectionError:
                print(f"No profile named: '{profile}' was found in the user config file")
                sys.exit(23)

            # Map Primary Botocore Config parameters with profile config file
            try:
                # Checks for retries config in profile config and sets it if not found to avoid throttling exception
                if RETRY_ATTEMPTS_KEY in profile_config \
                        or RETRY_MODE_CONFIG_KEY in profile_config:
                    retries = {
                        RETRY_ATTEMPTS_KEY: int(profile_config.get(RETRY_ATTEMPTS_KEY, 10)),
                        RETRY_MODE_BOTO_KEY: profile_config.get(RETRY_MODE_CONFIG_KEY, 'standard')
                    }
                    debug(
                        f"Retries parameters found in user profile. Using profile '{profile}' retries configuration",
                        2)

                else:
                    # Set retry config
                    retries = {
                        RETRY_ATTEMPTS_KEY: 10,
                        RETRY_MODE_BOTO_KEY: 'standard'
                    }
                    debug(
                        "No retries configuration found in profile config. Generating default configuration for "
                        f"retries: mode: {retries['mode']} - max_attempts: {retries['max_attempts']}",
                        2)

                args['config'].retries = retries

                # Set signature version
                signature_version = profile_config.get('signature_version', 's3v4')
                args['config'].signature_version = signature_version

                # Set profile dictionaries configuration
                set_profile_dict_config(boto_config=args,
                                        profile=profile,
                                        profile_config=profile_config)

            except (KeyError, ValueError) as e:
                print('Invalid key or value found in config '.format(e))
                sys.exit(17)

            debug(
                f"Created Config object using profile: '{profile}' configuration",
                2)

        else:
            # Set retries parameters to avoid a throttling exception
            args['config'] = botocore.config.Config(
                retries={
                    RETRY_ATTEMPTS_KEY: 10,
                    RETRY_MODE_BOTO_KEY: 'standard'
                }
            )
            debug(
                f"Generating default configuration for retries: {RETRY_MODE_BOTO_KEY} {args['config'].retries[RETRY_MODE_BOTO_KEY]} - "
                f"{RETRY_ATTEMPTS_KEY} {args['config'].retries[RETRY_ATTEMPTS_KEY]}",
                2)

        return args

    def get_client(self, access_key, secret_key, profile, iam_role_arn, service_name,
                   bucket, region=None,
                   sts_endpoint=None, service_endpoint=None, iam_role_duration=None, external_id=None):

        conn_args = {}

        if access_key is not None and secret_key is not None:
            print(DEPRECATED_MESSAGE.format(name="access_key and secret_key", release="4.4", url=CREDENTIALS_URL))
            conn_args['aws_access_key_id'] = access_key
            conn_args['aws_secret_access_key'] = secret_key

        if profile is not None:
            conn_args['profile_name'] = profile

        # set region name
        if region and service_name in ('inspector', 'cloudwatchlogs'):
            conn_args['region_name'] = region
        else:
            # it is necessary to set region_name for GovCloud regions
            conn_args['region_name'] = region if region in self.gov_regions \
                else None

        boto_session = boto3.Session(**conn_args)
        service_name = "logs" if service_name == "cloudwatchlogs" else service_name
        # If using a role, create session using that
        try:
            if iam_role_arn:

                sts_client = boto_session.client('sts', endpoint_url=sts_endpoint, **self.connection_config)

                assume_role_kwargs = {'RoleArn': iam_role_arn,
                                      'RoleSessionName': 'WazuhLogParsing'}
                if external_id:
                    assume_role_kwargs['ExternalId'] = external_id

                if iam_role_duration is not None:
                    assume_role_kwargs['DurationSeconds'] = iam_role_duration

                sts_role_assumption = sts_client.assume_role(**assume_role_kwargs)

                sts_session = boto3.Session(aws_access_key_id=sts_role_assumption['Credentials']['AccessKeyId'],
                                            aws_secret_access_key=sts_role_assumption['Credentials']['SecretAccessKey'],
                                            aws_session_token=sts_role_assumption['Credentials']['SessionToken'],
                                            region_name=conn_args.get('region_name'))

                client = sts_session.client(service_name=service_name, endpoint_url=service_endpoint,
                                            **self.connection_config)
            else:
                client = boto_session.client(service_name=service_name, endpoint_url=service_endpoint,
                                             **self.connection_config)

        except (botocore.exceptions.ClientError, botocore.exceptions.NoCredentialsError) as e:
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
            sts_client = boto_session.client(service_name='sts', **self.connection_config)

        except Exception as e:
            print("Error getting STS client: {}".format(e))
            sys.exit(3)

        return sts_client

    def event_should_be_skipped(self, event_):
        def _check_recursive(json_item=None, nested_field: str = '', regex: str = ''):
            field_list = nested_field.split('.', 1)
            try:
                expression_to_evaluate = json_item[field_list[0]]
            except TypeError:
                if isinstance(json_item, list):
                    return any(_check_recursive(i, field_list[0], regex=regex) for i in json_item)
                return False
            except KeyError:
                return False
            if len(field_list) == 1:
                def check_regex(exp):
                    try:
                        return re.match(regex, exp) is not None
                    except TypeError:
                        return isinstance(exp, list) and any(check_regex(ex) for ex in exp)

                return check_regex(expression_to_evaluate)
            return _check_recursive(expression_to_evaluate, field_list[1], regex=regex)

        return self.discard_field and self.discard_regex \
            and _check_recursive(event_, nested_field=self.discard_field, regex=self.discard_regex)

    def send_msg(self, msg, dump_json=True):
        """
        Sends an AWS event to the Wazuh Queue

        :param msg: JSON message to be sent.
        :param dump_json: If json.dumps should be applied to the msg
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

    def __init__(self, reparse, access_key, secret_key, profile, iam_role_arn,
                 bucket, only_logs_after, skip_on_error, account_alias,
                 prefix, suffix, delete_file, aws_organization_id, region,
                 discard_field, discard_regex, sts_endpoint, service_endpoint, iam_role_duration=None):
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
                log_key
            FROM
                {table_name}
            WHERE
                bucket_path=:bucket_path AND
                aws_account_id=:aws_account_id AND
                aws_region = :aws_region AND
                log_key LIKE :prefix
            ORDER BY
                log_key DESC
            LIMIT 1;"""

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

        self.sql_count_region = """
            SELECT
                count(*)
            FROM
                {table_name}
            WHERE
                bucket_path=:bucket_path AND
                aws_account_id=:aws_account_id AND
                aws_region=:aws_region;"""

        self.db_name = 's3_cloudtrail'
        WazuhIntegration.__init__(self, access_key=access_key,
                                  secret_key=secret_key,
                                  aws_profile=profile,
                                  iam_role_arn=iam_role_arn,
                                  bucket=bucket,
                                  service_name='s3',
                                  region=region,
                                  discard_field=discard_field,
                                  discard_regex=discard_regex,
                                  sts_endpoint=sts_endpoint,
                                  service_endpoint=service_endpoint,
                                  iam_role_duration=iam_role_duration
                                  )
        self.retain_db_records = 500
        self.reparse = reparse
        self.only_logs_after = datetime.strptime(only_logs_after, "%Y%m%d") if only_logs_after else None
        self.skip_on_error = skip_on_error
        self.account_alias = account_alias
        self.prefix = prefix
        self.suffix = suffix
        self.delete_file = delete_file
        self.bucket_path = self.bucket + '/' + self.prefix
        self.aws_organization_id = aws_organization_id
        self.date_regex = re.compile(r'(\d{4}/\d{2}/\d{2})')
        self.prefix_regex = re.compile("^\d{12}$")
        self.check_prefix = False
        self.date_format = "%Y/%m/%d"
        self.db_date_format = "%Y%m%d"

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

    def _get_last_key_processed(self, aws_account_id: str) -> str or None:
        """
        Get the key of the last file processed by the module.

        Parameters
        ----------
        aws_account_id : str
            The account ID of the AWS account.

        Returns
        -------
        str or None
            A str with the key of the last file processed, None if no file has been processed yet.
        """
        query_last_key = self.db_connector.execute(
            self.sql_find_last_key_processed.format(table_name=self.db_table_name), {'bucket_path': self.bucket_path,
                                                                                     'aws_account_id': aws_account_id,
                                                                                     'prefix': f'{self.prefix}%'})
        try:
            return query_last_key.fetchone()[0]
        except (TypeError, IndexError):
            # if DB is empty for a region
            return None

    def already_processed(self, downloaded_file, aws_account_id, aws_region, **kwargs):
        cursor = self.db_connector.execute(self.sql_already_processed.format(table_name=self.db_table_name), {
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
                self.db_connector.execute(self.sql_mark_complete.format(table_name=self.db_table_name), {
                    'bucket_path': self.bucket_path,
                    'aws_account_id': aws_account_id,
                    'aws_region': aws_region,
                    'log_key': log_file['Key'],
                    'created_date': self.get_creation_date(log_file)})
            except Exception as e:
                debug("+++ Error marking log {} as completed: {}".format(log_file['Key'], e), 2)

    def db_count_region(self, aws_account_id, aws_region):
        """Counts the number of rows in DB for a region
        :param aws_account_id: AWS account ID
        :type aws_account_id: str
        :param aws_region: AWS region
        :param aws_region: str
        :rtype: int
        """
        query_count_region = self.db_connector.execute(
            self.sql_count_region.format(table_name=self.db_table_name), {'bucket_path': self.bucket_path,
                                                                          'aws_account_id': aws_account_id,
                                                                          'aws_region': aws_region,
                                                                          'retain_db_records': self.retain_db_records})
        return query_count_region.fetchone()[0]

    def db_maintenance(self, aws_account_id=None, aws_region=None):
        debug("+++ DB Maintenance", 1)
        try:
            if self.db_count_region(aws_account_id, aws_region) > self.retain_db_records:
                self.db_connector.execute(self.sql_db_maintenance.format(table_name=self.db_table_name), {
                    'bucket_path': self.bucket_path,
                    'aws_account_id': aws_account_id,
                    'aws_region': aws_region,
                    'retain_db_records': self.retain_db_records})
        except Exception as e:
            print(f"ERROR: Failed to execute DB cleanup - AWS Account ID: {aws_account_id}  Region: {aws_region}: {e}")

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
                debug(f'ERROR: {THROTTLING_EXCEPTION_ERROR_MESSAGE.format(name="find_account_ids")}.', 2)
                sys.exit(16)
            else:
                debug(f'ERROR: The "find_account_ids" request failed: {err}', 1)
                sys.exit(1)

        except KeyError:
            print(
                f"ERROR: No logs found in '{self.get_base_prefix()}'. Check the provided prefix and the location of the"
                f" logs for the bucket type '{get_script_arguments().type.lower()}'")
            sys.exit(18)

    def find_regions(self, account_id):
        try:
            regions = self.client.list_objects_v2(Bucket=self.bucket,
                                                  Prefix=self.get_service_prefix(account_id=account_id),
                                                  Delimiter='/')

            if 'CommonPrefixes' in regions:
                return [common_prefix['Prefix'].split('/')[-2] for common_prefix in regions['CommonPrefixes']]
            else:
                debug(f"+++ No regions found for AWS Account {account_id}", 1)
                return []

        except botocore.exceptions.ClientError as err:
            if err.response['Error']['Code'] == THROTTLING_EXCEPTION_ERROR_CODE:
                debug(f'ERROR: {THROTTLING_EXCEPTION_ERROR_MESSAGE.format(name="find_regions")}. ', 2)
                sys.exit(16)
            else:
                debug(f'ERROR: The "find_account_ids" request failed: {err}', 1)
                sys.exit(1)

    def build_s3_filter_args(self, aws_account_id, aws_region, iterating=False, custom_delimiter='', **kwargs):
        filter_marker = ''
        last_key = None
        if self.reparse:
            if self.only_logs_after:
                filter_marker = self.marker_only_logs_after(aws_region, aws_account_id)
            else:
                filter_marker = self.marker_custom_date(aws_region, aws_account_id, self.default_date)
        else:
            query_last_key = self.db_connector.execute(
                self.sql_find_last_key_processed.format(table_name=self.db_table_name), {
                    'bucket_path': self.bucket_path,
                    'aws_region': aws_region,
                    'prefix': f'{self.prefix}%',
                    'aws_account_id': aws_account_id,
                    **kwargs
                })
            try:
                filter_marker = query_last_key.fetchone()[0]
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
            filter_args['StartAfter'] = filter_marker
            if self.only_logs_after:
                only_logs_marker = self.marker_only_logs_after(aws_region, aws_account_id)
                filter_args['StartAfter'] = only_logs_marker if only_logs_marker > filter_marker else filter_marker

            if custom_delimiter:
                prefix_len = len(filter_args['Prefix'])
                filter_args['StartAfter'] = filter_args['StartAfter'][:prefix_len] + \
                                            filter_args['StartAfter'][prefix_len:].replace('/', custom_delimiter)
            debug(f"+++ Marker: {filter_args['StartAfter']}", 2)

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

        # in order to support both old and new index pattern,
        # change data.aws.sourceIPAddress fieldname and parse that one with type ip
        # Only add this field if the sourceIPAddress is an IP and not a DNS.
        if 'sourceIPAddress' in event['aws'] and re.match(r'\d+\.\d+.\d+.\d+', event['aws']['sourceIPAddress']):
            event['aws']['source_ip_address'] = event['aws']['sourceIPAddress']

        if 'tags' in event['aws'] and not isinstance(event['aws']['tags'], dict):
            event['aws']['tags'] = {'value': event['aws']['tags']}

        return event

    def _decompress_gzip(self, raw_object: io.BytesIO):
        """
        Method that decompress gzip compressed data.

        Parameters
        ----------
        raw_object : io.BytesIO
            Buffer with the gzip compressed object.

        Returns
        -------
        file_object
            Decompressed object.
        """
        try:
            gzip_file = gzip.open(filename=raw_object, mode='rt')
            # Ensure that the file is not corrupted by reading from it
            gzip_file.read()
            gzip_file.seek(0)
            return gzip_file
        except (gzip.BadGzipFile, zlib.error, TypeError):
            print(f'ERROR: invalid gzip file received.')
            if not self.skip_on_error:
                sys.exit(8)

    def _decompress_zip(self, raw_object: io.BytesIO):
        """
        Method that decompress zip compressed data.

        Parameters
        ----------
        raw_object : io.BytesIO
            Buffer with the zip compressed object.

        Returns
        -------
        file_object
            Decompressed object.
        """
        try:
            zipfile_object = zipfile.ZipFile(raw_object, compression=zipfile.ZIP_DEFLATED)
            return io.TextIOWrapper(zipfile_object.open(zipfile_object.namelist()[0]))
        except zipfile.BadZipFile:
            print('ERROR: invalid zip file received.')
        if not self.skip_on_error:
            sys.exit(8)

    def decompress_file(self, log_key: str):
        """
        Method that returns a file stored in a bucket decompressing it if necessary.

        Parameters
        ----------
        log_key : str
            Name of the file that should be returned.
        """
        raw_object = io.BytesIO(self.client.get_object(Bucket=self.bucket, Key=log_key)['Body'].read())
        if log_key[-3:] == '.gz':
            return self._decompress_gzip(raw_object)
        elif log_key[-4:] == '.zip':
            return self._decompress_zip(raw_object)
        elif log_key[-7:] == '.snappy':
            print(f"ERROR: couldn't decompress the {log_key} file, snappy compression is not supported.")
            if not self.skip_on_error:
                sys.exit(8)
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
        self.init_db(self.sql_create_table.format(table_name=self.db_table_name))
        self.iter_regions_and_accounts(account_id, regions)
        self.db_connector.commit()
        self.db_connector.execute(self.sql_db_optimize)
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
                debug("+++ Working on {} - {}".format(aws_account_id, aws_region), 1)
                self.iter_files_in_bucket(aws_account_id, aws_region)
                self.db_maintenance(aws_account_id=aws_account_id, aws_region=aws_region)

    def send_event(self, event):
        # Change dynamic fields to strings; truncate values as needed
        event_msg = self.reformat_msg(event)
        # Send the message
        self.send_msg(event_msg)

    def iter_events(self, event_list, log_key, aws_account_id):
        def _check_recursive(json_item=None, nested_field: str = '', regex: str = ''):
            field_list = nested_field.split('.', 1)
            try:
                expression_to_evaluate = json_item[field_list[0]]
            except TypeError:
                if isinstance(json_item, list):
                    return any(_check_recursive(i, field_list[0], regex=regex) for i in json_item)
                return False
            except KeyError:
                return False
            if len(field_list) == 1:
                def check_regex(exp):
                    try:
                        return re.match(regex, exp) is not None
                    except TypeError:
                        return isinstance(exp, list) and any(check_regex(ex) for ex in exp)

                return check_regex(expression_to_evaluate)
            return _check_recursive(expression_to_evaluate, field_list[1], regex=regex)

        def _event_should_be_skipped(event_):
            return self.discard_field and self.discard_regex \
                and _check_recursive(event_, nested_field=self.discard_field, regex=self.discard_regex)

        if event_list is not None:
            for event in event_list:
                if _event_should_be_skipped(event):
                    debug(f'+++ The "{self.discard_regex.pattern}" regex found a match in the "{self.discard_field}" '
                          f'field. The event will be skipped.', 2)
                    continue
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

        debug(self.empty_bucket_message_template.format(**message_args), 1)

    def iter_files_in_bucket(self, aws_account_id=None, aws_region=None, **kwargs):
        if aws_account_id is None:
            aws_account_id = self.aws_account_id

        try:
            bucket_files = self.client.list_objects_v2(
                **self.build_s3_filter_args(aws_account_id, aws_region, **kwargs)
            )
            if self.reparse:
                debug('++ Reparse mode enabled', 2)

            while True:
                if 'Contents' not in bucket_files:
                    self._print_no_logs_to_process_message(self.bucket, aws_account_id, aws_region, **kwargs)
                    return

                processed_logs = 0

                for bucket_file in bucket_files['Contents']:

                    if not bucket_file['Key']:
                        continue

                    if bucket_file['Key'][-1] == '/':
                        # The file is a folder
                        continue

                    if self.check_prefix:
                        date_match = self.date_regex.search(bucket_file['Key'])
                        match_start = date_match.span()[0] if date_match else None

                        if not self._same_prefix(match_start, aws_account_id, aws_region):
                            debug(f"++ Skipping file with another prefix: {bucket_file['Key']}", 3)
                            continue

                    if self.already_processed(bucket_file['Key'], aws_account_id, aws_region, **kwargs):
                        if self.reparse:
                            debug(f"++ File previously processed, but reparse flag set: {bucket_file['Key']}", 1)
                        else:
                            debug(f"++ Skipping previously processed file: {bucket_file['Key']}", 1)
                            continue

                    debug(f"++ Found new log: {bucket_file['Key']}", 2)
                    # Get the log file from S3 and decompress it
                    log_json = self.get_log_file(aws_account_id, bucket_file['Key'])
                    self.iter_events(log_json, bucket_file['Key'], aws_account_id)
                    # Remove file from S3 Bucket
                    if self.delete_file:
                        debug(f"+++ Remove file from S3 Bucket:{bucket_file['Key']}", 2)
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

        except botocore.exceptions.ClientError as err:
            if err.response['Error']['Code'] == 'ThrottlingException':
                debug('Error: The "iter_files_in_bucket" request was denied due to request throttling. If the problem '
                      'persists check the following link to learn how to use the Retry configuration to avoid it: '
                      f'{RETRY_CONFIGURATION_URL}', 2)
                sys.exit(16)
            else:
                debug(f'ERROR: The "iter_files_in_bucket" request failed: {err}', 1)
                sys.exit(1)

        except Exception as err:
            if hasattr(err, 'message'):
                debug(f"+++ Unexpected error: {err.message}", 2)
            else:
                debug(f"+++ Unexpected error: {err}", 2)
            print(f"ERROR: Unexpected error querying/working with objects in S3: {err}")
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


class AWSLogsBucket(AWSBucket):
    """
    Abstract class for logs generated from services such as CloudTrail or Config
    """

    def __init__(self, **kwargs):
        AWSBucket.__init__(self, **kwargs)
        # If not empty, both self.prefix and self.suffix always have a trailing '/'
        self.bucket_path = f"{self.bucket}/{self.prefix}{self.suffix}"

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
            date_path=datetime.strftime(log_timestamp, self.date_format),
            log_filename=filename
        )
        return aws_region, aws_account_id, log_key

    def get_alert_msg(self, aws_account_id, log_key, event, error_msg=""):
        alert_msg = AWSBucket.get_alert_msg(self, aws_account_id, log_key, event, error_msg)
        alert_msg['aws']['aws_account_id'] = aws_account_id
        return alert_msg

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
                bucket_path=:bucket_path AND
                aws_account_id=:aws_account_id AND
                aws_region = :aws_region AND
                created_date = :created_date
            ORDER BY
                log_key DESC
            LIMIT 1;"""
        self._leading_zero_regex = re.compile(r'/(0)(?P<num>\d)')
        self._extract_date_regex = re.compile(r'\d{4}/\d{1,2}/\d{1,2}')

    def _format_created_date(self, date: str) -> str:
        """
        Return a date with the format used by the created_date field of the database.

        Parameters
        ----------
        date : str
            Date in the "%Y/%m/%d" format.

        Returns
        -------
        str
            Date with the format used by the database.
        """
        return datetime.strftime(datetime.strptime(date, self.date_format), self.db_date_format)

    def _remove_padding_zeros_from_marker(self, marker: str) -> str:
        """Remove the leading zeros from the month and day of a given marker.

        For example, 'AWSLogs/123456789012/Config/us-east-1/2020/01/06' would become
        'AWSLogs/123456789012/Config/us-east-1/2020/1/6'.

        Parameters
        ----------
        marker : str
            The marker which may include a date with leading zeros as part of the month and the day.

        Returns
        -------
        str
            Marker without padding zeros in the date.
        """
        try:
            date = self._extract_date_regex.search(marker).group(0)
            # We can't call re.sub directly on the marker because the AWS account ID could start with a 0 too
            parsed_date = re.sub(self._leading_zero_regex, r'/\g<num>', date)
            return marker.replace(date, parsed_date)
        except AttributeError:
            print(f"ERROR: There was an error while trying to extract a date from the marker '{marker}'")
            sys.exit(16)

    def marker_only_logs_after(self, aws_region: str, aws_account_id: str) -> str:
        """Return a marker using the only_logs_after date to pass it as a filter to the list_objects_v2 method.

        This method removes the leading zeroes for the month and the day to comply with the config buckets folder
        structure.

        Parameters
        ----------
        aws_region : str
            Region where the bucket is located.
        aws_account_id : str
            Account ID that's being used to access the bucket.

        Returns
        -------
        str
            Marker generated using the only_logs_after value.
        """
        return self._remove_padding_zeros_from_marker(AWSBucket.marker_only_logs_after(self, aws_region,
                                                                                       aws_account_id))

    def marker_custom_date(self, aws_region: str, aws_account_id: str, date: datetime) -> str:
        """Return a marker using the specified date to pass it as a filter to the list_objects_v2 method.

        This method removes the leading zeroes for the month and the day to comply with the config buckets folder
        structure.

        Parameters
        ----------
        aws_region : str
            Region where the bucket is located.
        aws_account_id : str
            Account ID that's being used to access the bucket.
        date : datetime
            Date that will be used to generate the marker.

        Returns
        -------
        str
            Marker generated using the specified date.
        """
        return self._remove_padding_zeros_from_marker(AWSBucket.marker_custom_date(self, aws_region, aws_account_id,
                                                                                   date))

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
    empty_bucket_message_template = (
        "+++ No logs to process for {flow_log_id} flow log ID in bucket: {aws_account_id}/{aws_region}"
    )
    empty_bucket_message_template_without_log_id = "+++ No logs to process in bucket: {aws_account_id}/{aws_region}"

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

        if region not in ALL_REGIONS:
            raise ValueError(f"Invalid region '{region}'")

        try:
            ec2_client = boto_session.client(service_name='ec2', **self.connection_config)
        except Exception as e:
            print("Error getting EC2 client: {}".format(e))
            sys.exit(3)

        return ec2_client

    def get_flow_logs_ids(self, access_key, secret_key, region, account_id, profile_name=None):
        try:
            ec2_client = self.get_ec2_client(access_key, secret_key, region, profile_name=profile_name)
            return list(map(operator.itemgetter('FlowLogId'), ec2_client.describe_flow_logs()['FlowLogs']))
        except ValueError:
            debug(
                self.empty_bucket_message_template_without_log_id.format(aws_account_id=account_id, aws_region=region),
                msg_level=1
            )
            debug(
                f"+++ WARNING: Check the provided region: '{region}'. It's an invalid one.", msg_level=1
            )
            return []

    def already_processed(self, downloaded_file, aws_account_id, aws_region, flow_log_id):
        cursor = self.db_connector.execute(self.sql_already_processed.format(table_name=self.db_table_name), {
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
                debug("+++ Working on {} - {}".format(aws_account_id, aws_region), 1)
                # get flow log ids for the current region
                flow_logs_ids = self.get_flow_logs_ids(
                    self.access_key, self.secret_key, aws_region, aws_account_id, profile_name=self.profile_name
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
        query_count_region = self.db_connector.execute(
            self.sql_count_region.format(table_name=self.db_table_name), {
                'bucket_path': self.bucket_path,
                'aws_account_id': aws_account_id,
                'aws_region': aws_region,
                'flow_log_id': flow_log_id,
                'retain_db_records': self.retain_db_records})
        return query_count_region.fetchone()[0]

    def db_maintenance(self, aws_account_id=None, aws_region=None, flow_log_id=None):
        debug("+++ DB Maintenance", 1)
        try:
            if self.db_count_region(aws_account_id, aws_region, flow_log_id) > self.retain_db_records:
                self.db_connector.execute(self.sql_db_maintenance.format(table_name=self.db_table_name), {
                    'bucket_path': self.bucket_path,
                    'aws_account_id': aws_account_id,
                    'aws_region': aws_region,
                    'flow_log_id': flow_log_id,
                    'retain_db_records': self.retain_db_records})
        except Exception as e:
            print(f"ERROR: Failed to execute DB cleanup - AWS Account ID: {aws_account_id}  Region: {aws_region}: {e}")

    def get_vpc_prefix(self, aws_account_id, aws_region, date, flow_log_id):
        return self.get_full_prefix(aws_account_id, aws_region) + date \
            + '/' + aws_account_id + '_vpcflowlogs_' + aws_region + '_' + flow_log_id

    def mark_complete(self, aws_account_id, aws_region, log_file, flow_log_id):
        if self.reparse:
            if self.already_processed(log_file['Key'], aws_account_id, aws_region, flow_log_id):
                debug(
                    '+++ File already marked complete, but reparse flag set: {log_key}'.format(log_key=log_file['Key']),
                    2)
        else:
            try:
                self.db_connector.execute(self.sql_mark_complete.format(table_name=self.db_table_name), {
                    'bucket_path': self.bucket_path,
                    'aws_account_id': aws_account_id,
                    'aws_region': aws_region,
                    'flow_log_id': flow_log_id,
                    'log_key': log_file['Key'],
                    'created_date': self.get_creation_date(log_file)})
            except Exception as e:
                debug("+++ Error marking log {} as completed: {}".format(log_file['Key'], e), 2)


class AWSCustomBucket(AWSBucket):

    empty_bucket_message_template = "+++ No logs to process in bucket: {bucket}"

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
        self.macie_location_pattern = re.compile(r'"lat":(-?0+\d+\.\d+),"lon":(-?0+\d+\.\d+)')
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
                log_key
            FROM
                {table_name}
            WHERE
                bucket_path=:bucket_path AND
                aws_account_id=:aws_account_id AND
                log_key LIKE :prefix
            ORDER BY
                log_key DESC
            LIMIT 1;"""

        self.sql_db_maintenance = """
            DELETE FROM {table_name}
            WHERE
                bucket_path=:bucket_path AND
                aws_account_id=:aws_account_id AND
                log_key <=
                (SELECT log_key
                    FROM
                        {table_name}
                    WHERE
                        bucket_path=:bucket_path AND
                        aws_account_id=:aws_account_id
                    ORDER BY
                        log_key DESC
                    LIMIT 1
                    OFFSET :retain_db_records);"""

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
            while data:
                try:
                    json_data, json_index = decoder.raw_decode(data)
                except ValueError as err:
                    # Handle undefined values for lat and lon fields in Macie logs
                    match = self.macie_location_pattern.search(data)
                    if not match or not match.group(1) or not match.group(2):
                        raise err
                    lat = float(match.group(1))
                    lon = float(match.group(2))
                    new_pattern = f'"lat":{lat},"lon":{lon}'
                    data = re.sub(self.macie_location_pattern, new_pattern, data)
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

    def already_processed(self, downloaded_file, aws_account_id, aws_region):
        cursor = self.db_connector.execute(self.sql_already_processed.format(table_name=self.db_table_name), {
            'bucket_path': self.bucket_path,
            'aws_account_id': self.aws_account_id,
            'log_key': downloaded_file})
        return cursor.fetchone()[0] > 0

    def mark_complete(self, aws_account_id, aws_region, log_file):
        AWSBucket.mark_complete(self, aws_account_id or self.aws_account_id, aws_region, log_file)

    def db_count_custom(self, aws_account_id=None):
        """Counts the number of rows in DB for a region
        :param aws_account_id: AWS account ID
        :type aws_account_id: str
        :rtype: int
        """
        query_count_custom = self.db_connector.execute(
            self.sql_count_custom.format(table_name=self.db_table_name), {
                'bucket_path': self.bucket_path,
                'aws_account_id': aws_account_id if aws_account_id else self.aws_account_id,
                'retain_db_records': self.retain_db_records})

        return query_count_custom.fetchone()[0]

    def db_maintenance(self, aws_account_id=None, **kwargs):
        debug("+++ DB Maintenance", 1)
        try:
            if self.db_count_custom(aws_account_id) > self.retain_db_records:
                self.db_connector.execute(self.sql_db_maintenance.format(table_name=self.db_table_name), {
                    'bucket_path': self.bucket_path,
                    'aws_account_id': aws_account_id if aws_account_id else self.aws_account_id,
                    'retain_db_records': self.retain_db_records})
        except Exception as e:
            print(f"ERROR: Failed to execute DB cleanup - Path: {self.bucket_path}: {e}")


class AWSGuardDutyBucket(AWSCustomBucket):

    def __init__(self, **kwargs):
        self.db_table_name = 'guardduty'
        AWSCustomBucket.__init__(self, self.db_table_name, **kwargs)
        self.service = 'GuardDuty'
        if self.check_guardduty_type():
            self.type = "GuardDutyNative"
            self.empty_bucket_message_template = AWSBucket.empty_bucket_message_template
        else:
            self.type = "GuardDutyKinesis"

    def check_guardduty_type(self):
        try:
            return \
                    'CommonPrefixes' in self.client.list_objects_v2(Bucket=self.bucket, Prefix=f'{self.prefix}AWSLogs',
                                                                    Delimiter='/', MaxKeys=1)
        except Exception as err:
            if hasattr(err, 'message'):
                debug(f"+++ Unexpected error: {err.message}", 2)
            else:
                debug(f"+++ Unexpected error: {err}", 2)
            print(f"ERROR: Unexpected error querying/working with objects in S3: {err}")
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

    def iter_regions_and_accounts(self, account_id, regions):
        if self.type == "GuardDutyNative":
            AWSBucket.iter_regions_and_accounts(self, account_id, regions)
        else:
            print(GUARDDUTY_DEPRECATED_MESSAGE.format(release="4.5", url=GUARDDUTY_URL))
            self.check_prefix = True
            AWSCustomBucket.iter_regions_and_accounts(self, account_id, regions)

    def send_event(self, event):
        # Send the message (splitted if it is necessary)
        for msg in self.reformat_msg(event):
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

    def load_information_from_file(self, log_key):
        if log_key.endswith('.jsonl.gz'):
            with self.decompress_file(log_key=log_key) as f:
                json_list = list(f)
                result = []
                for json_item in json_list:
                    x = json.loads(json_item)
                    result.append(dict(x, source=x['service']['serviceName']))
                return result
        else:
            return AWSCustomBucket.load_information_from_file(self, log_key)


class CiscoUmbrella(AWSCustomBucket):

    def __init__(self, **kwargs):
        db_table_name = 'cisco_umbrella'
        AWSCustomBucket.__init__(self, db_table_name, **kwargs)
        self.check_prefix = False
        self.date_format = '%Y-%m-%d'

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
            only_logs_after=self.only_logs_after.strftime(self.date_format)
        )


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
        db_table_name = 'waf'
        AWSCustomBucket.__init__(self, db_table_name, **kwargs)

    def load_information_from_file(self, log_key):
        """Load data from a WAF log file."""

        def json_event_generator(data):
            while data:
                json_data, json_index = decoder.raw_decode(data)
                data = data[json_index:]
                yield json_data

        content = []
        decoder = json.JSONDecoder()
        with self.decompress_file(log_key=log_key) as f:
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
                            print(f"ERROR: the {log_key} file doesn't have the expected structure.")
                            if not self.skip_on_error:
                                sys.exit(9)
                        content.append(event)

                except json.JSONDecodeError:
                    print("ERROR: Events from {} file could not be loaded.".format(log_key.split('/')[-1]))
                    if not self.skip_on_error:
                        sys.exit(9)

        return json.loads(json.dumps(content))


class AWSLBBucket(AWSCustomBucket):
    """Class that has common methods unique to the load balancers."""

    empty_bucket_message_template = AWSBucket.empty_bucket_message_template

    def __init__(self, *args, **kwargs):
        self.service = 'elasticloadbalancing'
        AWSCustomBucket.__init__(self, *args, **kwargs)

    def get_base_prefix(self):
        return f'{self.prefix}AWSLogs/{self.suffix}'

    def get_service_prefix(self, account_id):
        return f'{self.get_base_prefix()}{account_id}/{self.service}/'

    def iter_regions_and_accounts(self, account_id, regions):
        AWSBucket.iter_regions_and_accounts(self, account_id, regions)

    def get_full_prefix(self, account_id, account_region):
        return f'{self.get_service_prefix(account_id)}{account_region}/'

    def mark_complete(self, aws_account_id, aws_region, log_file):
        AWSBucket.mark_complete(self, aws_account_id, aws_region, log_file)


class AWSALBBucket(AWSLBBucket):

    def __init__(self, **kwargs):
        db_table_name = 'alb'
        AWSLBBucket.__init__(self, db_table_name, **kwargs)

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
            tsv_file = [dict(x, source='alb') for x in tsv_file]

            fields_to_process_map = {
                "client_port": "client_ip",
                "target_port": "target_ip",
                "target_port_list": "target_ip_list"
            }

            for log_entry in tsv_file:
                for field_to_process, ip_field in fields_to_process_map.items():
                    try:
                        port, ip = "", ""
                        for item in [i.split(":") for i in log_entry[field_to_process].split()]:
                            ip += f"{item[0]} "
                            port += f"{item[1]} "
                        log_entry[field_to_process], log_entry[ip_field] = port.strip(), ip.strip()
                    except (ValueError, IndexError):
                        debug(f"Unable to process correctly ABL log entry, for field {field_to_process}.", msg_level=1)
                        debug(f"Log Entry: {log_entry}", msg_level=2)

            return tsv_file


class AWSCLBBucket(AWSLBBucket):

    def __init__(self, **kwargs):
        db_table_name = 'clb'
        AWSLBBucket.__init__(self, db_table_name, **kwargs)

    def load_information_from_file(self, log_key):
        """Load data from a CLB access log file."""
        with self.decompress_file(log_key=log_key) as f:
            fieldnames = (
                "time", "elb", "client_port", "backend_port", "request_processing_time", "backend_processing_time",
                "response_processing_time", "elb_status_code", "backend_status_code", "received_bytes", "sent_bytes",
                "request", "user_agent", "ssl_cipher", "ssl_protocol")
            tsv_file = csv.DictReader(f, fieldnames=fieldnames, delimiter=' ')

            return [dict(x, source='clb') for x in tsv_file]


class AWSNLBBucket(AWSLBBucket):

    def __init__(self, **kwargs):
        db_table_name = 'nlb'
        AWSLBBucket.__init__(self, db_table_name, **kwargs)

    def load_information_from_file(self, log_key):
        """Load data from a NLB access log file."""
        with self.decompress_file(log_key=log_key) as f:
            fieldnames = (
                "type", "version", "time", "elb", "listener", "client_port", "destination_port", "connection_time",
                "tls_handshake_time", "received_bytes", "sent_bytes", "incoming_tls_alert", "chosen_cert_arn",
                "chosen_cert_serial", "tls_cipher", "tls_protocol_version", "tls_named_group", "domain_name",
                "alpn_fe_protocol", "alpn_client_preference_list")
            tsv_file = csv.DictReader(f, fieldnames=fieldnames, delimiter=' ')

            tsv_file = [dict(x, source='nlb') for x in tsv_file]

            # Split ip_addr:port field into ip_addr and port fields
            for log_entry in tsv_file:
                try:
                    log_entry['client_ip'], log_entry['client_port'] = log_entry['client_port'].split(':')
                    log_entry['destination_ip'], log_entry['destination_port'] = \
                        log_entry['destination_port'].split(':')
                except ValueError:
                    log_entry['client_ip'] = log_entry['client_port']
                    log_entry['destination_ip'] = log_entry['destination_port']

            return tsv_file


class AWSServerAccess(AWSCustomBucket):

    def __init__(self, **kwargs):
        db_table_name = 's3_server_access'
        AWSCustomBucket.__init__(self, db_table_name=db_table_name, **kwargs)
        self.date_regex = re.compile(r'(\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2})')
        self.date_format = '%Y-%m-%d'

    def _key_is_old(self, file_date: datetime or None, last_key_date: datetime or None) -> bool:
        """
        Check if the file key provided is too old to process.

        Parameters
        ----------
        file_date : datetime or None
            The date extracted from a file key.
        last_key_date : datetime or None
            The date extracted from a file key.

        Returns
        -------
        bool
            True if the file must be skipped, False otherwise.
        """
        if file_date:
            if (self.only_logs_after and file_date < self.only_logs_after) or \
                    (last_key_date and file_date < last_key_date):
                return True

        return False

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
                            debug(f"+++ WARNING: The format of the {bucket_file['Key']} filename is not valid, "
                                  "skipping it.", 1)
                            continue
                        else:
                            print(f"ERROR: The filename of {bucket_file['Key']} doesn't have the a valid format.")
                            sys.exit(17)

                    if not self._same_prefix(match_start, aws_account_id, aws_region):
                        debug(f"++ Skipping file with another prefix: {bucket_file['Key']}", 3)
                        continue

                    if self.already_processed(bucket_file['Key'], aws_account_id, aws_region):
                        if self.reparse:
                            debug(f"++ File previously processed, but reparse flag set: {bucket_file['Key']}", 1)
                        else:
                            debug(f"++ Skipping previously processed file: {bucket_file['Key']}", 2)
                            continue

                    debug(f"++ Found new log: {bucket_file['Key']}", 2)
                    # Get the log file from S3 and decompress it
                    log_json = self.get_log_file(aws_account_id, bucket_file['Key'])
                    self.iter_events(log_json, bucket_file['Key'], aws_account_id)
                    # Remove file from S3 Bucket
                    if self.delete_file:
                        debug(f"+++ Remove file from S3 Bucket:{bucket_file['Key']}", 2)
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
                debug(f"+++ Unexpected error: {err.message}", 2)
            else:
                debug(f"+++ Unexpected error: {err}", 2)
            print(f"ERROR: Unexpected error querying/working with objects in S3: {err}")
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

        with self.decompress_file(log_key=log_key) as f:
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

    def __init__(self, reparse, access_key, secret_key, aws_profile, iam_role_arn,
                 service_name, only_logs_after, region, aws_log_groups=None, remove_log_streams=None,
                 discard_field=None, discard_regex=None, sts_endpoint=None, service_endpoint=None,
                 iam_role_duration=None):
        # DB name
        self.db_name = 'aws_services'
        # table name
        self.db_table_name = 'aws_services'
        self.reparse = reparse

        WazuhIntegration.__init__(self, access_key=access_key, secret_key=secret_key,
                                  aws_profile=aws_profile, iam_role_arn=iam_role_arn,
                                  service_name=service_name, region=region, discard_field=discard_field,
                                  discard_regex=discard_regex, sts_endpoint=sts_endpoint,
                                  service_endpoint=service_endpoint, iam_role_duration=iam_role_duration)

        # get sts client (necessary for getting account ID)
        self.sts_client = self.get_sts_client(access_key, secret_key, aws_profile)
        # get account ID
        self.account_id = self.sts_client.get_caller_identity().get('Account')
        self.only_logs_after = only_logs_after

        # SQL queries for services
        self.sql_create_table = """
            CREATE TABLE {table_name} (
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
            VALUES (
                :service_name,
                :aws_account_id,
                :aws_region,
                :scan_date);"""

        self.sql_find_last_scan = """
            SELECT
                scan_date
            FROM
                {table_name}
            WHERE
                service_name=:service_name AND
                aws_account_id=:aws_account_id AND
                aws_region=:aws_region
            ORDER BY
                scan_date DESC
            LIMIT 1;"""

        self.sql_db_maintenance = """
            DELETE FROM {table_name}
            WHERE
                service_name=:service_name AND
                aws_account_id=:aws_account_id AND
                aws_region=:aws_region AND
                rowid NOT IN (SELECT ROWID
                    FROM
                        {table_name}
                    WHERE
                        service_name=:service_name AND
                        aws_account_id=:aws_account_id AND
                        aws_region=:aws_region
                    ORDER BY
                        scan_date DESC
                    LIMIT :retain_db_records);"""

    def get_last_log_date(self):
        date = self.only_logs_after if self.only_logs_after is not None else self.default_date.strftime('%Y%m%d')
        return f'{date[0:4]}-{date[4:6]}-{date[6:8]} 00:00:00.0'

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

    @staticmethod
    def check_region(region: str) -> None:
        if region not in ALL_REGIONS:
            raise ValueError(f"Invalid region '{region}'")


class AWSInspector(AWSService):
    """
    Class for getting AWS Inspector logs

    Parameters
    ----------
    access_key : str
        AWS access key id.
    secret_key : str
        AWS secret access key.
    aws_profile : str
        AWS profile.
    iam_role_arn : str
        IAM Role that will be assumed to use the service.
    only_logs_after : str
        Date after which obtain logs.
    region : str
        AWS region that will be used to fetch the events.

    Attributes
    ----------
    sent_events : int
        The number of events collected and sent to analysisd.
    """

    def __init__(self, reparse, access_key, secret_key, aws_profile,
                 iam_role_arn, only_logs_after, region, aws_log_groups=None,
                 remove_log_streams=None, discard_field=None, discard_regex=None,
                 sts_endpoint=None, service_endpoint=None, iam_role_duration=None):

        self.service_name = 'inspector'
        self.inspector_region = region

        AWSService.__init__(self, reparse=reparse, access_key=access_key, secret_key=secret_key,
                            aws_profile=aws_profile, iam_role_arn=iam_role_arn, only_logs_after=only_logs_after,
                            service_name=self.service_name, region=region, aws_log_groups=aws_log_groups,
                            remove_log_streams=remove_log_streams, discard_field=discard_field,
                            discard_regex=discard_regex, sts_endpoint=sts_endpoint, service_endpoint=service_endpoint,
                            iam_role_duration=iam_role_duration)

        # max DB records for region
        self.retain_db_records = 5
        self.reparse = reparse
        self.sent_events = 0

    def send_describe_findings(self, arn_list: list):
        """
        Collect and send to analysisd the requested findings.

        Parameters
        ----------
        arn_list : list[str]
            The ARN of the findings that should be requested to AWS and sent to analysisd.
        """
        if len(arn_list) != 0:
            response = self.client.describe_findings(findingArns=arn_list)['findings']
            debug(f"+++ Processing {len(response)} events", 3)
            for elem in response:
                if self.event_should_be_skipped(elem):
                    debug(f'+++ The "{self.discard_regex.pattern}" regex found a match in the "{self.discard_field}" '
                          f'field. The event will be skipped.', 2)
                    continue
                self.send_msg(self.format_message(elem))
                self.sent_events += 1

    def get_alerts(self):
        self.init_db(self.sql_create_table.format(table_name=self.db_table_name))
        try:
            initial_date = self.get_last_log_date()
            # reparse logs if this parameter exists
            if self.reparse:
                last_scan = initial_date
            else:
                self.db_cursor.execute(self.sql_find_last_scan.format(table_name=self.db_table_name), {
                    'service_name': self.service_name,
                    'aws_account_id': self.account_id,
                    'aws_region': self.inspector_region})
                last_scan = self.db_cursor.fetchone()[0]
        except TypeError as e:
            # write initial date if DB is empty
            self.db_cursor.execute(self.sql_insert_value.format(table_name=self.db_table_name), {
                'service_name': self.service_name,
                'aws_account_id': self.account_id,
                'aws_region': self.inspector_region,
                'scan_date': initial_date})
            last_scan = initial_date

        date_last_scan = datetime.strptime(last_scan, '%Y-%m-%d %H:%M:%S.%f')
        date_scan = date_last_scan
        if self.only_logs_after:
            date_only_logs = datetime.strptime(self.only_logs_after, "%Y%m%d")
            date_scan = date_only_logs if date_only_logs > date_last_scan else date_last_scan

        # get current time (UTC)
        date_current = datetime.utcnow()
        # describe_findings only retrieves 100 results per call
        response = self.client.list_findings(maxResults=100, filter={'creationTimeRange':
                                                                         {'beginDate': date_scan,
                                                                          'endDate': date_current}})
        debug(f"+++ Listing findings starting from {date_scan}", 2)
        self.send_describe_findings(response['findingArns'])
        # Iterate if there are more elements
        while 'nextToken' in response:
            response = self.client.list_findings(maxResults=100, nextToken=response['nextToken'],
                                                 filter={'creationTimeRange': {'beginDate': date_scan,
                                                                               'endDate': date_current}})
            self.send_describe_findings(response['findingArns'])

        if self.sent_events:
            debug(f"+++ {self.sent_events} events collected and processed in {self.inspector_region}", 1)
        else:
            debug(f'+++ There are no new events in the "{self.inspector_region}" region', 1)

        # insert last scan in DB
        self.db_cursor.execute(self.sql_insert_value.format(table_name=self.db_table_name), {
            'service_name': self.service_name,
            'aws_account_id': self.account_id,
            'aws_region': self.inspector_region,
            'scan_date': date_current})
        # DB maintenance
        self.db_cursor.execute(self.sql_db_maintenance.format(table_name=self.db_table_name), {
            'service_name': self.service_name,
            'aws_account_id': self.account_id,
            'aws_region': self.inspector_region,
            'retain_db_records': self.retain_db_records})
        # close connection with DB
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
    reparse : bool
        Whether to parse already parsed logs or not.
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
                 remove_log_streams, discard_field=None, discard_regex=None, sts_endpoint=None, service_endpoint=None,
                 iam_role_duration=None):

        self.sql_cloudwatch_create_table = """
            CREATE TABLE {table_name} (
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
                (:aws_region,
                :aws_log_group,
                :aws_log_stream,
                :next_token,
                :start_time,
                :end_time);"""

        self.sql_cloudwatch_update = """
            UPDATE
                {table_name}
            SET
                next_token=:next_token,
                start_time=:start_time,
                end_time=:end_time
            WHERE
                aws_region=:aws_region AND
                aws_log_group=:aws_log_group AND
                aws_log_stream=:aws_log_stream;"""

        self.sql_cloudwatch_select = """
            SELECT
                next_token,
                start_time,
                end_time
            FROM
                {table_name}
            WHERE
                aws_region=:aws_region AND
                aws_log_group=:aws_log_group AND
                aws_log_stream=:aws_log_stream"""
        self.sql_cloudwatch_select_logstreams = """
            SELECT
                aws_log_stream
            FROM
                {table_name}
            WHERE
                aws_region=:aws_region AND
                aws_log_group=:aws_log_group
            ORDER BY
                aws_log_stream;"""
        self.sql_cloudwatch_purge = """
            DELETE FROM {table_name}
            WHERE
                aws_region=:aws_region AND
                aws_log_group=:aws_log_group AND
                aws_log_stream=:aws_log_stream;"""

        AWSService.__init__(self, reparse=reparse, access_key=access_key, secret_key=secret_key,
                            aws_profile=aws_profile, iam_role_arn=iam_role_arn, only_logs_after=only_logs_after,
                            region=region, aws_log_groups=aws_log_groups, remove_log_streams=remove_log_streams,
                            service_name='cloudwatchlogs', discard_field=discard_field, discard_regex=discard_regex,
                            iam_role_duration=iam_role_duration, sts_endpoint=sts_endpoint,
                            service_endpoint=service_endpoint)

        self.reparse = reparse
        self.region = region
        self.db_table_name = 'cloudwatch_logs'
        self.log_group_list = [group for group in aws_log_groups.split(",") if group != ""] if aws_log_groups else []
        self.remove_log_streams = remove_log_streams
        self.only_logs_after_millis = int(datetime.strptime(only_logs_after, '%Y%m%d').replace(
            tzinfo=timezone.utc).timestamp() * 1000) if only_logs_after else None
        self.default_date_millis = int(self.default_date.timestamp() * 1000)
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

        if self.reparse:
            debug('Reparse mode ON', 1)

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
                    start_time = self.only_logs_after_millis if self.only_logs_after_millis else self.default_date_millis
                    end_time = None
                    token = None

                    if db_values:
                        if self.reparse:
                            result_before = self.get_alerts_within_range(log_group=log_group, log_stream=log_stream,
                                                                         token=None, start_time=start_time,
                                                                         end_time=None)

                        elif db_values['start_time'] and db_values['start_time'] > start_time:
                            result_before = self.get_alerts_within_range(log_group=log_group, log_stream=log_stream,
                                                                         token=None, start_time=start_time,
                                                                         end_time=db_values['start_time'])

                        if db_values['end_time']:
                            if not self.only_logs_after_millis or db_values['end_time'] > self.only_logs_after_millis:
                                start_time = db_values['end_time'] + 1
                                token = db_values['token']

                    result_after = self.get_alerts_within_range(log_group=log_group, log_stream=log_stream, token=token,
                                                                start_time=start_time, end_time=end_time)

                    db_values = self.update_values(values=db_values, result_before=result_before,
                                                   result_after=result_after)

                    self.save_data_db(log_group=log_group, log_stream=log_stream, values=db_values)

                    if self.remove_log_streams:
                        self.remove_aws_log_stream(log_group=log_group, log_stream=log_stream)

                self.purge_db(log_group=log_group)
        finally:
            debug("committing changes and closing the DB", 1)
            self.close_db()

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
        except botocore.exceptions.ClientError as err:
            debug(f'ERROR: The "remove_aws_log_stream" request failed: {err}', 1)
            sys.exit(16)
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
        sent_events = 0
        response = None
        min_start_time = start_time
        max_end_time = end_time if end_time is not None else start_time

        parameters = {'logGroupName': log_group,
                      'logStreamName': log_stream,
                      'nextToken': token,
                      'startTime': start_time,
                      'endTime': end_time,
                      'startFromHead': True}

        # Request event logs until CloudWatch returns an empty list for the log stream
        while response is None or response['events'] != list():
            debug('Getting CloudWatch logs from log stream "{}" in log group "{}" using token "{}", start_time '
                  '"{}" and end_time "{}"'.format(log_stream, log_group, token, start_time, end_time), 1)

            # Try to get CloudWatch Log events until the request succeeds or the allowed number of attempts is reached
            try:
                response = self.client.get_log_events(
                    **{param: value for param, value in parameters.items() if value is not None})

            except botocore.exceptions.EndpointConnectionError:
                debug(f'WARNING: The "get_log_events" request was denied because the endpoint URL was not '
                      f'available. Attempting again.', 1)
            except botocore.exceptions.ClientError as err:
                debug(f'ERROR: The "get_log_events" request failed: {err}', 1)
                sys.exit(16)

            # Update token
            token = response['nextForwardToken']
            parameters['nextToken'] = token

            debug('+++ Sending events to Analysisd...', 1)
            # Send events to Analysisd
            if response['events']:
                debug('+++ Sending events to Analysisd...', 1)
                for event in response['events']:
                    event_msg = event['message']
                    try:
                        json_event = json.loads(event_msg)
                        if self.event_should_be_skipped(json_event):
                            debug(
                                f'+++ The "{self.discard_regex.pattern}" regex found a match in the "{self.discard_field}" '
                                f'field. The event will be skipped.', 2)
                            continue
                    except ValueError:
                        # event_msg is not a JSON object, check if discard_regex.pattern matches the given string
                        debug(f"+++ Retrieved log event is not a JSON object.", 3)
                        if re.match(self.discard_regex, event_msg):
                            debug(
                                f'+++ The "{self.discard_regex.pattern}" regex found a match. The event will be skipped.',
                                2)
                            continue
                    debug('The message is "{}"'.format(event_msg), 2)
                    debug('The message\'s timestamp is {}'.format(event["timestamp"]), 3)
                    self.send_msg(event_msg, dump_json=False)
                    sent_events += 1

                    if min_start_time is None:
                        min_start_time = event['timestamp']
                    elif event['timestamp'] < min_start_time:
                        min_start_time = event['timestamp']

                    if max_end_time is None:
                        max_end_time = event['timestamp']
                    elif event['timestamp'] > max_end_time:
                        max_end_time = event['timestamp']
                debug(f"+++ Sent {len(response['events'])} events to Analysisd", 1)

            if sent_events:
                debug(f"+++ Sent {sent_events} events to Analysisd", 1)
                sent_events = 0
            else:
                debug(f'+++ There are no new events in the "{log_group}" group', 1)

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
        self.db_cursor.execute(self.sql_cloudwatch_select.format(table_name=self.db_table_name), {
            'aws_region': self.region,
            'aws_log_group': log_group,
            'aws_log_stream': log_stream})
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
            # It's necessary to ensure that we're not comparing None with int
            elif result_after['start_time'] is not None:
                min_start_time = result_after['start_time'] if result_after[
                                                                   'start_time'] < min_start_time else min_start_time

            if max_end_time is None:
                max_end_time = result_after['end_time']
            elif result_after['end_time'] is not None:
                max_end_time = result_after['end_time'] if result_after['end_time'] > max_end_time else max_end_time

        token = result_before['token'] if result_before is not None else None
        token = result_after['token'] if result_after is not None else token

        if values is None:
            return {'token': token, 'start_time': min_start_time, 'end_time': max_end_time}
        else:
            result = {'token': token}

            if values['start_time'] is not None:
                result['start_time'] = min_start_time if min_start_time is not None and min_start_time < values[
                    'start_time'] else values['start_time']
            else:
                result['start_time'] = max_end_time

            if values['end_time'] is not None:
                result['end_time'] = max_end_time if max_end_time is not None and max_end_time > values['end_time'] else \
                    values['end_time']
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
            self.db_cursor.execute(self.sql_cloudwatch_insert.format(table_name=self.db_table_name), {
                'aws_region': self.region,
                'aws_log_group': log_group,
                'aws_log_stream': log_stream,
                'next_token': values['token'],
                'start_time': values['start_time'],
                'end_time': values['end_time']})
        except sqlite3.IntegrityError:
            debug("Some data already exists on DB for that key. Updating their values...", 2)
            self.db_cursor.execute(self.sql_cloudwatch_update.format(table_name=self.db_table_name), {
                'aws_region': self.region,
                'aws_log_group': log_group,
                'aws_log_stream': log_stream,
                'next_token': values['token'],
                'start_time': values['start_time'],
                'end_time': values['end_time']})

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
        debug('Getting log streams for "{}" log group'.format(log_group), 1)

        try:
            # Get all log streams using the token of the previous call to describe_log_streams
            response = self.client.describe_log_streams(logGroupName=log_group)
            log_streams = response['logStreams']
            token = response.get('nextToken')
            while token:
                response = self.client.describe_log_streams(logGroupName=log_group, nextToken=token)
                log_streams.extend(response['logStreams'])
                token = response.get('nextToken')

            for log_stream in log_streams:
                debug('Found "{}" log stream in {}'.format(log_stream['logStreamName'], log_group), 2)
                result_list.append(log_stream['logStreamName'])

            if result_list == list():
                debug('No log streams were found for log group "{}"'.format(log_group), 1)

        except botocore.exceptions.EndpointConnectionError as e:
            print(f'ERROR: {str(e)}')
        except botocore.exceptions.ClientError as err:
            debug(f'ERROR: The "get_log_streams" request failed: {err}', 1)
            sys.exit(16)
        except Exception:
            debug(
                '++++ The specified "{}" log group does not exist or insufficient privileges to access it.'.format(
                    log_group), 0)

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
        self.db_cursor.execute(self.sql_cloudwatch_select_logstreams.format(table_name=self.db_table_name), {
            'aws_region': self.region,
            'aws_log_group': log_group})
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
            self.db_cursor.execute(self.sql_cloudwatch_purge.format(tablename=self.db_table_name), {
                'aws_region': self.region,
                'aws_log_group': log_group,
                'aws_log_stream': log_stream})


class AWSSLSubscriberBucket(WazuhIntegration):
    """
    Class for processing AWS Security Lake events from S3.

    Attributes
    ----------
    access_key : str
        AWS access key id.
    secret_key : str
        AWS secret access key.
    aws_profile : str
        AWS profile.
    iam_role_arn : str
        IAM Role.
    """

    def __init__(self, access_key: str = None, secret_key: str = None, aws_profile: str = None,
                 service_endpoint: str = None, sts_endpoint: str = None, **kwargs):
        WazuhIntegration.__init__(self, access_key=access_key, secret_key=secret_key, aws_profile=aws_profile,
                                  service_name='s3', service_endpoint=service_endpoint, sts_endpoint=sts_endpoint,
                                  **kwargs)

    def obtain_information_from_parquet(self, bucket_path: str, parquet_path: str) -> list:
        """Fetch a parquet file from a bucket and obtain a list of the events it contains.

        Parameters
        ----------
        bucket_path : str
            Path of the bucket to get the parquet file from.
        parquet_path : str
            Relative path of the parquet file inside the bucket.

        Returns
        -------
        events : list
            Events contained inside the parquet file.
        """
        debug(f'Processing file {parquet_path} in {bucket_path}', 2)
        events = []
        try:
            raw_parquet = io.BytesIO(self.client.get_object(Bucket=bucket_path, Key=parquet_path)['Body'].read())
        except Exception as e:
            debug(f'Could not get the parquet file {parquet_path} in {bucket_path}: {e}', 1)
            sys.exit(21)
        pfile = pq.ParquetFile(raw_parquet)
        for i in pfile.iter_batches():
            for j in i.to_pylist():
                events.append(json.dumps(j))
        debug(f'Found {len(events)} events in file {parquet_path}', 2)
        return events

    def process_file(self, message: dict) -> None:
        """Parse an SQS message, obtain the events associated, and send them to Analysisd.

        Parameters
        ----------
        message : dict
            An SQS message received from the queue.
        """
        events_in_file = self.obtain_information_from_parquet(bucket_path=message['bucket_path'],
                                                              parquet_path=message['parquet_path'])
        for event in events_in_file:
            self.send_msg(event, dump_json=False)
        debug(f'{len(events_in_file)} events sent to Analysisd', 2)


class AWSSQSQueue(WazuhIntegration):
    """
    Class for getting AWS SQS Queue notifications.

    Attributes
    ----------
    name: str
        Name of the SQS Queue.
    iam_role_arn : str
        IAM Role.
    access_key : str
        AWS access key id.
    secret_key : str
        AWS secret access key.
    external_id : str
        The name of the External ID to use.
    sts_endpoint : str
        URL for the VPC endpoint to use to obtain the STS token.
    service_endpoint : str
        URL for the endpoint to use to obtain the logs.
    """

    def __init__(self, name: str, iam_role_arn: str, access_key: str = None, secret_key: str = None,
                 external_id: str = None, sts_endpoint=None, service_endpoint=None, **kwargs):
        self._validate_params(external_id=external_id, name=name, iam_role_arn=iam_role_arn)
        self.sqs_name = name
        WazuhIntegration.__init__(self, access_key=access_key, secret_key=secret_key, iam_role_arn=iam_role_arn,
                                  aws_profile=None, external_id=external_id, service_name='sqs',
                                  sts_endpoint=sts_endpoint,
                                  **kwargs)
        self.sts_client = self.get_sts_client(access_key, secret_key)
        self.account_id = self.sts_client.get_caller_identity().get('Account')
        self.sqs_url = self._get_sqs_url()
        self.iam_role_arn = iam_role_arn
        self.asl_bucket_handler = AWSSLSubscriberBucket(external_id=external_id,
                                                        iam_role_arn=self.iam_role_arn,
                                                        service_endpoint=service_endpoint,
                                                        sts_endpoint=sts_endpoint)

    def _validate_params(self, external_id: Optional[str], name: Optional[str], iam_role_arn: Optional[str]):
        """
        Class for getting AWS SQS Queue notifications.
        Parameters
        ----------
        external_id : Optional[str]
            The name of the External ID to use.
        name: Optional[str]
            Name of the SQS Queue.
        iam_role_arn : Optional[str]
            IAM Role.
        """

        if iam_role_arn is None:
            print('ERROR: Used a subscriber but no --iam_role_arn provided.')
            sys.exit(21)
        if name is None:
            print('ERROR: Used a subscriber but no --queue provided.')
            sys.exit(21)
        if external_id is None:
            print('ERROR: Used a subscriber but no --external_id provided.')
            sys.exit(21)

    def _get_sqs_url(self) -> str:
        """Get the URL of the AWS SQS queue

        Returns
        -------
        url : str
            The URL of the AWS SQS queue
        """
        try:
            url = self.client.get_queue_url(QueueName=self.sqs_name,
                                            QueueOwnerAWSAccountId=self.account_id)['QueueUrl']
            debug(f'The SQS queue is: {url}', 2)
            return url
        except botocore.exceptions.ClientError:
            print('ERROR: Queue does not exist, verify the given name')
            sys.exit(20)

    def delete_message(self, message: dict) -> None:
        """Delete message from the SQS queue.

        Parameters
        ----------
        message : dict
            An SQS message recieved from the queue
        """
        try:
            self.client.delete_message(QueueUrl=self.sqs_url, ReceiptHandle=message["handle"])
            debug(f'Message deleted from: {self.sqs_name}', 2)
        except Exception as e:
            debug(f'ERROR: Error deleting message from SQS: {e}', 1)
            sys.exit(21)

    def fetch_messages(self) -> dict:
        """Retrieves one or more messages (up to 10), from the specified queue.

        Returns
        -------
        dict
            A dictionary with a list of messages from the SQS queue.
        """
        try:
            debug(f'Retrieving messages from: {self.sqs_name}', 2)
            return self.client.receive_message(QueueUrl=self.sqs_url, AttributeNames=['All'],
                                               MaxNumberOfMessages=10, MessageAttributeNames=['All'],
                                               WaitTimeSeconds=20)
        except Exception as e:
            debug(f'ERROR: Error receiving message from SQS: {e}', 1)
            sys.exit(21)

    def get_messages(self) -> list:
        """Retrieve parsed messages from the SQS queue.

        Returns
        -------
        messages : list
            Parsed messages from the SQS queue.
        """
        messages = []
        sqs_raw_messages = self.fetch_messages()
        sqs_messages = sqs_raw_messages.get('Messages', [])
        for mesg in sqs_messages:
            body = mesg['Body']
            msg_handle = mesg["ReceiptHandle"]
            message = json.loads(body)
            parquet_path = message["detail"]["object"]["key"]
            bucket_path = message["detail"]["bucket"]["name"]
            messages.append({"parquet_path": parquet_path, "bucket_path": bucket_path,
                             "handle": msg_handle})
        return messages

    def sync_events(self) -> None:
        """
        Get messages from the SQS queue, parse their events, send them to AnalysisD, and delete them from the queue.
        """
        messages = self.get_messages()
        while messages:
            for message in messages:
                self.asl_bucket_handler.process_file(message)
                self.delete_message(message)
            messages = self.get_messages()


################################################################################
# Functions
################################################################################

def handler(signal, frame):
    print("ERROR: SIGINT received.")
    sys.exit(2)


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


def arg_valid_key(arg_string, append_slash=True):
    CHARACTERS_TO_AVOID = "\\{}^%`[]'\"<>~#|"
    XML_CONSTRAINTS = ["&apos;", "&quot;", "&amp;", "&lt;", "&gt;", "&#13;", "&#10;"]

    # Validate against the naming guidelines https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-keys.html
    if any([char in arg_string for char in list(CHARACTERS_TO_AVOID) + XML_CONSTRAINTS]):
        raise argparse.ArgumentTypeError(
            f"'{arg_string}' has an invalid character."
            f" Avoid to use '{CHARACTERS_TO_AVOID}' or '{''.join(XML_CONSTRAINTS)}'."
        )

    if append_slash and arg_string and arg_string[-1] != '/':
        return '{arg_string}/'.format(arg_string=arg_string)
    return arg_string


def aws_logs_groups_valid_key(arg_string):
    return arg_valid_key(arg_string, append_slash=False)


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
        if not re.match(r'^([a-z]{2}(-gov)?)-([a-z]{4,7})-\d$', arg_region):
            raise argparse.ArgumentTypeError(
                f"WARNING: The region '{arg_region}' has not a valid format.'"
            )
        if arg_region.strip():
            final_regions.append(arg_region.strip())
    final_regions = list(set(final_regions))
    final_regions.sort()
    return final_regions


def arg_valid_iam_role_duration(arg_string):
    """Checks if the role session duration specified is a valid parameter.

    Parameters
    ----------
    arg_string: str or None
        The desired session duration in seconds.

    Returns
    -------
    num_seconds: None or int
        The returned value will be None if no duration was specified or if it was an invalid value; elsewhere,
        it will return the number of seconds that the session will last.

    Raises
    ------
    argparse.ArgumentTypeError
        If the number provided is not in the expected range.
    """
    # Session duration must be between 15m and 12h
    # Session duration must be between 15m and 12h
    if arg_string is None:
        return None

    # Validate if the argument is a number
    if not arg_string.isdigit():
        raise argparse.ArgumentTypeError("Invalid session duration specified. Value must be a valid number.")

    # Convert to integer and check range
    num_seconds = int(arg_string)
    if not (900 <= num_seconds <= 3600):
        raise argparse.ArgumentTypeError("Invalid session duration specified. Value must be between 900 and 3600.")

    return num_seconds


def args_valid_iam_role_arn(iam_role_arn):
    """Checks if the IAM role ARN specified is a valid parameter.

    Parameters
    ----------
    iam_role_arn : str
        The IAM role ARN to validate.

    Raises
    ------
    argparse.ArgumentTypeError
        If the ARN provided is not in the expected format.
    """
    pattern = r'^arn:(?P<Partition>[^:\n]*):(?P<Service>[^:\n]*):(?P<Region>[^:\n]*):(?P<AccountID>[^:\n]*):(?P<Ignore>(?P<ResourceType>[^:\/\n]*)[:\/])?(?P<Resource>.*)$'

    if not re.match(pattern, iam_role_arn):
        raise argparse.ArgumentTypeError("Invalid ARN Role specified. Value must be a valid ARN Role.")

    return iam_role_arn


def args_valid_sqs_name(sqs_name):
    """Checks if the SQS name specified is a valid parameter.

    Parameters
    ----------
    sqs_name : str
        The SQS name to validate.

    Raises
    ------
    argparse.ArgumentTypeError
        If the SQS name provided is not in the expected format.
    """
    pattern = r'^[a-zA-Z0-9-_]{1,80}$'

    if not re.match(pattern, sqs_name):
        raise argparse.ArgumentTypeError("Invalid SQS Name specified. Value must be up to 80 characters and the valid "
                                         "values are alphanumeric characters, hyphens (-), and underscores (_)")

    return sqs_name


def arg_valid_bucket_name(arg: str) -> str:
    """Validate the bucket name against the S3 naming rules.
    https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucketnamingrules.html

    Parameters
    ----------
    arg : str
        Argument to validate.

    Returns
    -------
    str
        The bucket name if match with the rules.

    Raises
    ------
    argparse.ArgumentTypeError
        If the bucket name is not valid.
    """
    if not re.match(r'(?!(^xn--|.+-s3alias$|.+--ol-s3$))^[a-z0-9][a-z0-9-.]{1,61}[a-z0-9]$', arg):
        raise argparse.ArgumentTypeError(f"'{arg}' isn't a valid bucket name.")
    return arg


def get_aws_config_params() -> configparser.RawConfigParser:
    """Read and retrieve parameters from aws config file

    Returns
    -------
    configparser.RawConfigParser
        the parsed config
    """
    config = configparser.RawConfigParser()
    config.read(DEFAULT_AWS_CONFIG_PATH)

    return config


def get_script_arguments():
    parser = argparse.ArgumentParser(usage="usage: %(prog)s [options]",
                                     description="Wazuh wodle for monitoring AWS",
                                     formatter_class=argparse.RawTextHelpFormatter)
    # only one must be present (bucket or service)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-b', '--bucket', dest='logBucket', help='Specify the S3 bucket containing AWS logs',
                       action='store', type=arg_valid_bucket_name)
    group.add_argument('-sr', '--service', dest='service', help='Specify the name of the service',
                       action='store')
    group.add_argument('-sb', '--subscriber', dest='subscriber', help='Specify the type of the subscriber',
                       action='store')
    parser.add_argument('-q', '--queue', dest='queue', help='Specify the name of the SQS',
                        type=args_valid_sqs_name, action='store')
    parser.add_argument('-O', '--aws_organization_id', dest='aws_organization_id',
                        help='AWS organization ID for logs', required=False)
    parser.add_argument('-c', '--aws_account_id', dest='aws_account_id',
                        help='AWS Account ID for logs', required=False,
                        type=arg_valid_accountid)
    parser.add_argument('-d', '--debug', action='store', dest='debug', default=0, help='Enable debug')
    parser.add_argument('-a', '--access_key', dest='access_key', default=None,
                        help='S3 Access key credential. '
                             f'{DEPRECATED_MESSAGE.format(name="access_key", release="4.4", url=CREDENTIALS_URL)}')
    parser.add_argument('-k', '--secret_key', dest='secret_key', default=None,
                        help='S3 Access key credential. '
                             f'{DEPRECATED_MESSAGE.format(name="secret_key", release="4.4", url=CREDENTIALS_URL)}')
    # Beware, once you delete history it's gone.
    parser.add_argument('-R', '--remove', action='store_true', dest='deleteFile',
                        help='Remove processed files from the AWS S3 bucket', default=False)
    parser.add_argument('-p', '--aws_profile', dest='aws_profile', help='The name of credential profile to use',
                        default=None)
    parser.add_argument('-x', '--external_id', dest='external_id', help='The name of the External ID to use',
                        default=None)
    parser.add_argument('-i', '--iam_role_arn', dest='iam_role_arn',
                        help='ARN of IAM role to assume for access to S3 bucket',
                        type=args_valid_iam_role_arn,
                        default=None)
    parser.add_argument('-n', '--aws_account_alias', dest='aws_account_alias',
                        help='AWS Account ID Alias', default='')
    parser.add_argument('-l', '--trail_prefix', dest='trail_prefix',
                        help='Log prefix for S3 key',
                        default='', type=arg_valid_key)
    parser.add_argument('-L', '--trail_suffix', dest='trail_suffix',
                        help='Log suffix for S3 key',
                        default='', type=arg_valid_key)
    parser.add_argument('-s', '--only_logs_after', dest='only_logs_after',
                        help='Only parse logs after this date - format YYYY-MMM-DD',
                        default=None, type=arg_valid_date)
    parser.add_argument('-r', '--regions', dest='regions', help='Comma delimited list of AWS regions to parse logs',
                        default='', type=arg_valid_regions)
    parser.add_argument('-e', '--skip_on_error', action='store_true', dest='skip_on_error',
                        help='If fail to parse a file, error out instead of skipping the file')
    parser.add_argument('-o', '--reparse', action='store_true', dest='reparse',
                        help='Parse the log file, even if its been parsed before', default=False)
    parser.add_argument('-t', '--type', dest='type', type=str, help='Bucket type.', default='cloudtrail')
    parser.add_argument('-g', '--aws_log_groups', dest='aws_log_groups', help='Name of the log group to be parsed',
                        default='', type=aws_logs_groups_valid_key)
    parser.add_argument('-P', '--remove-log-streams', action='store_true', dest='deleteLogStreams',
                        help='Remove processed log streams from the log group', default=False)
    parser.add_argument('-df', '--discard-field', type=str, dest='discard_field', default=None,
                        help='The name of the event field where the discard_regex should be applied to determine if '
                             'an event should be skipped.', )
    parser.add_argument('-dr', '--discard-regex', type=str, dest='discard_regex', default=None,
                        help='REGEX value to be applied to determine whether an event should be skipped.', )
    parser.add_argument('-st', '--sts_endpoint', type=str, dest='sts_endpoint', default=None,
                        help='URL for the VPC endpoint to use to obtain the STS token.')
    parser.add_argument('-se', '--service_endpoint', type=str, dest='service_endpoint', default=None,
                        help='URL for the endpoint to use to obtain the logs.')
    parser.add_argument('-rd', '--iam_role_duration', type=arg_valid_iam_role_duration, dest='iam_role_duration',
                        default=None,
                        help='The duration, in seconds, of the role session. Value can range from 900s to the max'
                             ' session duration set for the role.')
    parsed_args = parser.parse_args()

    if parsed_args.iam_role_duration is not None and parsed_args.iam_role_arn is None:
        raise argparse.ArgumentTypeError('Used --iam_role_duration argument but no --iam_role_arn provided.')

    return parsed_args


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
            elif options.type.lower() == 'server_access':
                bucket_type = AWSServerAccess
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
                                 suffix=options.trail_suffix,
                                 delete_file=options.deleteFile,
                                 aws_organization_id=options.aws_organization_id,
                                 region=options.regions[0] if options.regions else None,
                                 discard_field=options.discard_field,
                                 discard_regex=options.discard_regex,
                                 sts_endpoint=options.sts_endpoint,
                                 service_endpoint=options.service_endpoint,
                                 iam_role_duration=options.iam_role_duration
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
                aws_config = get_aws_config_params()

                aws_profile = options.aws_profile or "default"

                if aws_config.has_option(aws_profile, "region"):
                    options.regions.append(aws_config.get(aws_profile, "region"))
                else:
                    debug("+++ Warning: No regions were specified, trying to get events from all regions", 1)
                    options.regions = ALL_REGIONS

            for region in options.regions:
                try:
                    service_type.check_region(region)
                except ValueError:
                    debug(f"+++ ERROR: The region '{region}' is not a valid one.", 1)
                    exit(22)

                debug('+++ Getting alerts from "{}" region.'.format(region), 1)
                service = service_type(reparse=options.reparse,
                                       access_key=options.access_key,
                                       secret_key=options.secret_key,
                                       aws_profile=options.aws_profile,
                                       iam_role_arn=options.iam_role_arn,
                                       only_logs_after=options.only_logs_after,
                                       region=region,
                                       aws_log_groups=options.aws_log_groups,
                                       remove_log_streams=options.deleteLogStreams,
                                       discard_field=options.discard_field,
                                       discard_regex=options.discard_regex,
                                       sts_endpoint=options.sts_endpoint,
                                       service_endpoint=options.service_endpoint,
                                       iam_role_duration=options.iam_role_duration
                                       )
                service.get_alerts()
        elif options.subscriber:
            asl_queue = AWSSQSQueue(external_id=options.external_id, iam_role_arn=options.iam_role_arn,
                                    sts_endpoint=options.sts_endpoint,
                                    service_endpoint=options.service_endpoint,
                                    name=options.queue)
            asl_queue.sync_events()

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
