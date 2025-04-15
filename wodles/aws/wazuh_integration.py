# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import socket
import sqlite3
import sys

try:
    import boto3
except ImportError:
    print('ERROR: boto3 module is required.')
    sys.exit(4)

import aws_tools
import configparser
import copy
import gzip
import io
import json
import operator
import re
import zipfile
import zlib

from botocore import config, exceptions
from datetime import datetime
from datetime import timezone
from os import path

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))
import utils

DEPRECATED_TABLES = {'log_progress', 'trail_progress'}
DEFAULT_GOV_REGIONS = {'us-gov-east-1', 'us-gov-west-1'}
SERVICES_REQUIRING_REGION = {'inspector', 'cloudwatchlogs'}
WAZUH_DEFAULT_RETRY_CONFIGURATION = {aws_tools.RETRY_ATTEMPTS_KEY: 10, aws_tools.RETRY_MODE_BOTO_KEY: 'standard'}
MESSAGE_HEADER = "1:Wazuh-AWS:"


class WazuhIntegration:
    """
    Class with common methods.
    :param access_key: AWS access key id.
    :param secret_key: AWS secret access key.
    :param profile: AWS profile.
    :param iam_role_arn: IAM Role.
    :param service_name: Name of the service (s3 for services which stores logs in buckets).
    :param region: Region of service.
    :param iam_role_duration: The desired duration of the session that is going to be assumed.
    :param external_id: AWS external ID for IAM Role assumption.
    :param skip_on_error: Whether to continue processing logs or stop when an error takes place.
    """

    def __init__(self, access_key, secret_key, profile, iam_role_arn, service_name=None, region=None,
                 discard_field=None, discard_regex=None, sts_endpoint=None,
                 service_endpoint=None, iam_role_duration=None, external_id=None, skip_on_error=False):

        self.skip_on_error = skip_on_error
        self.wazuh_path = utils.find_wazuh_path()
        self.wazuh_version = utils.get_wazuh_version()
        self.wazuh_queue = path.join(self.wazuh_path, "queue", "sockets", "queue")
        self.wazuh_wodle = path.join(self.wazuh_path, "wodles", "aws")

        self.connection_config = self.default_config(profile=profile)
        self.client = self.get_client(access_key=access_key,
                                      secret_key=secret_key,
                                      profile=profile,
                                      iam_role_arn=iam_role_arn,
                                      service_name=service_name,
                                      region=region,
                                      sts_endpoint=sts_endpoint,
                                      service_endpoint=service_endpoint,
                                      iam_role_duration=iam_role_duration,
                                      external_id=external_id
                                      )

        self.discard_field = discard_field
        self.discard_regex = re.compile(fr'{discard_regex}')
        # to fetch logs using this date if no only_logs_after value was provided on the first execution
        self.default_date = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0, tzinfo=timezone.utc)

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
                AWS profile configuration to use.

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

        if path.exists(aws_tools.DEFAULT_AWS_CONFIG_PATH):
            # Create boto Config object
            args['config'] = config.Config()

            # Get User Aws Config
            aws_config = aws_tools.get_aws_config_params()

            # Set profile
            if profile is not None:
                if profile not in aws_config.sections():
                    profile = f"profile {profile}"
            else:
                profile = 'default'

            try:
                # Get profile config dictionary
                profile_config = {option: aws_config.get(profile, option) for option in aws_config.options(profile)}

            except configparser.NoSectionError:
                aws_tools.error(f"No profile named: '{profile}' was found in the user config file")
                aws_tools.debug(
                    f"The region for the '{profile}' must be specified in "
                    f"'~/.aws/config' under the '[{profile}]' section.", 2)
                sys.exit(23)

            # Map Primary Botocore Config parameters with profile config file
            try:
                # Checks for retries config in profile config and sets it if not found to avoid throttling exception
                if aws_tools.RETRY_ATTEMPTS_KEY in profile_config \
                        or aws_tools.RETRY_MODE_CONFIG_KEY in profile_config:
                    retries = {
                        aws_tools.RETRY_ATTEMPTS_KEY: int(profile_config.get(aws_tools.RETRY_ATTEMPTS_KEY, 10)),
                        aws_tools.RETRY_MODE_BOTO_KEY: profile_config.get(aws_tools.RETRY_MODE_CONFIG_KEY, 'standard')
                    }
                    aws_tools.debug(
                        f"Retries parameters found in user profile. Using profile '{profile}' retries configuration",
                        2)

                else:
                    # Set retry config
                    retries = copy.deepcopy(WAZUH_DEFAULT_RETRY_CONFIGURATION)
                    aws_tools.debug(
                        "No retries configuration found in profile config. Generating default configuration for "
                        f"retries: mode: {retries['mode']} - max_attempts: {retries['max_attempts']}",
                        2)

                args['config'].retries = retries

                # Set signature version
                signature_version = profile_config.get('signature_version', 's3v4')
                args['config'].signature_version = signature_version

                # Set profile dictionaries configuration
                aws_tools.set_profile_dict_config(boto_config=args,
                                                  profile=profile,
                                                  profile_config=profile_config)

            except (KeyError, ValueError) as e:
                aws_tools.error('Invalid key or value found in config '.format(e))
                sys.exit(17)

            aws_tools.debug(f"Created Config object using profile: '{profile}' configuration", 2)

        else:
            # Set retries parameters to avoid a throttling exception
            args['config'] = config.Config(retries=copy.deepcopy(WAZUH_DEFAULT_RETRY_CONFIGURATION))
            aws_tools.debug(
                f"Generating default configuration for retries: {aws_tools.RETRY_MODE_BOTO_KEY} "
                f"{args['config'].retries[aws_tools.RETRY_MODE_BOTO_KEY]} - "
                f"{aws_tools.RETRY_ATTEMPTS_KEY} {args['config'].retries[aws_tools.RETRY_ATTEMPTS_KEY]}",
                2)

        return args

    def get_client(self, access_key, secret_key, profile, iam_role_arn, service_name, region=None,
                   sts_endpoint=None, service_endpoint=None, iam_role_duration=None, external_id=None):
        conn_args = {}

        if access_key is not None and secret_key is not None:
            print(aws_tools.DEPRECATED_MESSAGE.format(name="access_key and secret_key", release="4.4",
                                                      url=aws_tools.CREDENTIALS_URL))
            conn_args['aws_access_key_id'] = access_key
            conn_args['aws_secret_access_key'] = secret_key

        if profile is not None:
            conn_args['profile_name'] = profile

            # set region name
        if region and service_name in SERVICES_REQUIRING_REGION:
            conn_args['region_name'] = region
        else:
            # it is necessary to set region_name for GovCloud regions
            conn_args['region_name'] = region if region in DEFAULT_GOV_REGIONS else None

        boto_session = boto3.Session(**conn_args)
        service_name = "logs" if service_name == "cloudwatchlogs" else service_name
        # If using a role, create session using that
        try:
            if iam_role_arn:

                sts_client = boto_session.client(service_name='sts', endpoint_url=sts_endpoint,
                                                 **self.connection_config)
                assume_role_kwargs = {'RoleArn': iam_role_arn, 'RoleSessionName': 'WazuhLogParsing'}
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

        except (exceptions.ClientError, exceptions.NoCredentialsError) as e:
            aws_tools.error("Access error: {}".format(e))
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
            aws_tools.error("Error getting STS client: {}".format(e))
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
            aws_tools.debug(json_msg, 3)
            s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            s.connect(self.wazuh_queue)
            encoded_msg = f"{MESSAGE_HEADER}{json_msg if dump_json else msg}".encode()
            # Logs warning if event is bigger than max size
            if len(encoded_msg) > utils.MAX_EVENT_SIZE:
                aws_tools.debug(f"Event size exceeds the maximum allowed limit of {utils.MAX_EVENT_SIZE} bytes.", 1)
            s.send(encoded_msg)
            s.close()
        except socket.error as e:
            if e.errno == 111:
                aws_tools.error("Wazuh must be running.")
                sys.exit(11)
            elif e.errno == 90:
                aws_tools.error("Message too long to send to Wazuh.  Skipping message...")
                aws_tools.debug('+++ ERROR: Message longer than buffer socket for Wazuh. Consider increasing rmem_max. '
                                'Skipping message...', 1)
            else:
                aws_tools.error("Error sending message to wazuh: {}".format(e))
                sys.exit(13)
        except Exception as e:
            aws_tools.error("Error sending message to wazuh: {}".format(e))
            sys.exit(13)

    def _decompress_gzip(self, raw_object: io.BytesIO):
        """Method that decompress gzip compressed data.

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
            aws_tools.error(f'Invalid gzip file received.')
            if not self.skip_on_error:
                sys.exit(8)

    def _decompress_zip(self, raw_object: io.BytesIO):
        """Method that decompress zip compressed data.

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
            aws_tools.error('Invalid zip file received.')
        if not self.skip_on_error:
            sys.exit(8)

    def decompress_file(self, bucket: str, log_key: str):
        """Method that returns a file stored in a bucket decompressing it if necessary.

        Parameters
        ----------
        bucket : str
            Path of the bucket to get the log file from.
        log_key : str
            Name of the file that should be returned.
        """
        raw_object = io.BytesIO(self.client.get_object(Bucket=bucket, Key=log_key)['Body'].read())
        if log_key[-3:] == '.gz':
            return self._decompress_gzip(raw_object)
        elif log_key[-4:] == '.zip':
            return self._decompress_zip(raw_object)
        elif log_key[-7:] == '.snappy':
            aws_tools.error(f"Couldn't decompress the {log_key} file, snappy compression is not supported.")
            if not self.skip_on_error:
                sys.exit(8)
        else:
            return io.TextIOWrapper(raw_object)


class WazuhAWSDatabase(WazuhIntegration):
    """
    Class with methods for buckets or services instances using db files
    :param db_name: Database name when instantiating buckets or services
    :param access_key: AWS access key id
    :param secret_key: AWS secret access key
    :param profile: AWS profile
    :param iam_role_arn: IAM Role
    :param db_name: Name of the database file
    :param service_name: Name of the service (s3 for services which stores logs in buckets)
    :param region: Region of service
    :param iam_role_duration: The desired duration of the session that is going to be assumed.
    :param external_id: AWS external ID for IAM Role assumption
    """
    def __init__(self, access_key, secret_key, profile, iam_role_arn, db_name,
                 service_name=None, region=None, discard_field=None,
                 discard_regex=None, sts_endpoint=None, service_endpoint=None, iam_role_duration=None,
                 external_id=None, skip_on_error=False):
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

        WazuhIntegration.__init__(self, service_name=service_name,
                                  access_key=access_key,
                                  secret_key=secret_key, profile=profile,
                                  iam_role_arn=iam_role_arn, region=region,
                                  discard_field=discard_field, discard_regex=discard_regex,
                                  sts_endpoint=sts_endpoint, service_endpoint=service_endpoint,
                                  iam_role_duration=iam_role_duration, external_id=external_id,
                                  skip_on_error=skip_on_error)

        # db_name is an instance variable of subclass
        self.db_path = "{0}/{1}.db".format(self.wazuh_wodle, db_name)
        self.db_connector = sqlite3.connect(self.db_path)
        self.db_cursor = self.db_connector.cursor()
        self.check_metadata_version()

    def create_table(self, sql_create_table):
        """
        :param sql_create_table: SQL query to create the table
        """
        try:
            aws_tools.debug('+++ Table does not exist; create', 1)
            self.db_cursor.execute(sql_create_table)
        except Exception as e:
            aws_tools.error("Unable to create SQLite DB: {}".format(e))
            sys.exit(6)

    def init_db(self, sql_create_table):
        """
        :param sql_create_table: SQL query to create the table
        """
        try:
            tables = set(map(operator.itemgetter(0), self.db_cursor.execute(self.sql_find_table_names)))
        except Exception as e:
            aws_tools.error("Unexpected error accessing SQLite DB: {}".format(e))
            sys.exit(5)
        # if table does not exist, create a new table
        if self.db_table_name not in tables:
            self.create_table(sql_create_table)

    def close_db(self):
        self.db_connector.commit()
        self.db_cursor.execute(self.sql_db_optimize)
        self.db_connector.close()

    def check_metadata_version(self):
        try:
            if self.db_cursor.execute(self.sql_find_table, {'name': 'metadata'}).fetchone():
                # The table does not exist; update existing metadata value, if required
                try:
                    metadata_version = self.db_cursor.execute(self.sql_get_metadata_version).fetchone()[0]
                    if metadata_version != self.wazuh_version:
                        self.db_cursor.execute(self.sql_update_version_metadata, {'wazuh_version': self.wazuh_version})
                except (sqlite3.IntegrityError, sqlite3.OperationalError, sqlite3.Error) as err:
                    aws_tools.error(f'Error attempting to update the metadata table: {err}')
                    sys.exit(5)
            else:
                # The table does not exist; create it and insert the metadata value
                try:
                    self.db_cursor.execute(self.sql_create_metadata_table)
                    self.db_cursor.execute(self.sql_insert_version_metadata, {'wazuh_version': self.wazuh_version})
                    self.delete_deprecated_tables()
                except (sqlite3.IntegrityError, sqlite3.OperationalError, sqlite3.Error) as err:
                    aws_tools.error(f'Error attempting to create the metadata table: {err}')
                    sys.exit(5)
            self.db_connector.commit()
        except (sqlite3.IntegrityError, sqlite3.OperationalError, sqlite3.Error) as err:
            aws_tools.error(f'Error attempting to operate with the {self.db_path} database: {err}')
            sys.exit(5)

    def delete_deprecated_tables(self):
        tables = set([t[0] for t in self.db_cursor.execute(self.sql_find_table_names).fetchall()])
        for table in tables.intersection(DEPRECATED_TABLES):
            aws_tools.debug(f"Removing deprecated '{table} 'table from {self.db_path}", 2)
            self.db_cursor.execute(self.sql_drop_table.format(table_name=table))
