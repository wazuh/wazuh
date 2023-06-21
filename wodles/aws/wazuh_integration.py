import socket
import sqlite3
import sys

try:
    import boto3
except ImportError:
    print('ERROR: boto3 module is required.')
    sys.exit(4)
import botocore
import json
import re
from os import path
import operator
from datetime import datetime
from datetime import timezone

import aws_tools

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))
import utils

DEPRECATED_TABLES = {'log_progress', 'trail_progress'}
DEFAULT_GOV_REGIONS = {'us-gov-east-1', 'us-gov-west-1'}
SERVICES_REQUIRING_REGION = {'inspector', 'cloudwatchlogs'}
WAZUH_DEFAULT_RETRY_CONFIGURATION = {'max_attempts': 10, 'mode': 'standard'}
MESSAGE_HEADER = "1:Wazuh-AWS:"


class WazuhIntegration:
    """
    Class with common methods
    :param access_key: AWS access key id
    :param secret_key: AWS secret access key
    :param profile: AWS profile
    :param iam_role_arn: IAM Role
    :param service_name: Name of the service (s3 for services which stores logs in buckets)
    :param region: Region of service
    :param iam_role_duration: The desired duration of the session that is going to be assumed.
    :param external_id: AWS external ID for IAM Role assumption
    """

    def __init__(self, access_key, secret_key, profile, iam_role_arn, service_name=None, region=None,
                 discard_field=None, discard_regex=None, sts_endpoint=None,
                 service_endpoint=None, iam_role_duration=None, external_id=None):

        self.wazuh_path = utils.find_wazuh_path()
        self.wazuh_version = utils.get_wazuh_version()
        self.wazuh_queue = f'{self.wazuh_path}/queue/sockets/queue'
        self.wazuh_wodle = f'{self.wazuh_path}/wodles/aws'

        self.connection_config = self.default_config()
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
    def default_config():
        args = {}
        if not path.exists(aws_tools.DEFAULT_AWS_CONFIG_PATH):
            args['config'] = botocore.config.Config(retries=WAZUH_DEFAULT_RETRY_CONFIGURATION.copy())
            aws_tools.debug(
                f"Generating default configuration for retries: mode {args['config'].retries['mode']} - max_attempts {args['config'].retries['max_attempts']}",
                2)
        else:
            aws_tools.debug(
                f'Found configuration for connection retries in {path.join(path.expanduser("~"), ".aws", "config")}', 2)
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
            s.send(f"{MESSAGE_HEADER}{json_msg if dump_json else msg}".encode())
            s.close()
        except socket.error as e:
            if e.errno == 111:
                print("ERROR: Wazuh must be running.")
                sys.exit(11)
            elif e.errno == 90:
                print("ERROR: Message too long to send to Wazuh.  Skipping message...")
                aws_tools.debug('+++ ERROR: Message longer than buffer socket for Wazuh. Consider increasing rmem_max. '
                                'Skipping message...', 1)
            else:
                print("ERROR: Error sending message to wazuh: {}".format(e))
                sys.exit(13)
        except Exception as e:
            print("ERROR: Error sending message to wazuh: {}".format(e))
            sys.exit(13)


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

        WazuhIntegration.__init__(self, service_name=service_name,
                                  access_key=access_key,
                                  secret_key=secret_key, profile=profile,
                                  iam_role_arn=iam_role_arn, region=region,
                                  discard_field=discard_field, discard_regex=discard_regex,
                                  sts_endpoint=sts_endpoint, service_endpoint=service_endpoint,
                                  iam_role_duration=iam_role_duration, external_id=external_id)

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
            print("ERROR: Unable to create SQLite DB: {}".format(e))
            sys.exit(6)

    def init_db(self, sql_create_table):
        """
        :param sql_create_table: SQL query to create the table
        """
        try:
            tables = set(map(operator.itemgetter(0), self.db_cursor.execute(self.sql_find_table_names)))
        except Exception as e:
            print("ERROR: Unexpected error accessing SQLite DB: {}".format(e))
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
                    print(f'ERROR: Error attempting to update the metadata table: {err}')
                    sys.exit(5)
            else:
                # The table does not exist; create it and insert the metadata value
                try:
                    self.db_cursor.execute(self.sql_create_metadata_table)
                    self.db_cursor.execute(self.sql_insert_version_metadata, {'wazuh_version': self.wazuh_version})
                    self.delete_deprecated_tables()
                except (sqlite3.IntegrityError, sqlite3.OperationalError, sqlite3.Error) as err:
                    print(f'ERROR: Error attempting to create the metadata table: {err}')
                    sys.exit(5)
            self.db_connector.commit()
        except (sqlite3.IntegrityError, sqlite3.OperationalError, sqlite3.Error) as err:
            print(f'ERROR: Error attempting to operate with the {self.db_path} database: {err}')
            sys.exit(5)

    def delete_deprecated_tables(self):
        tables = set([t[0] for t in self.db_cursor.execute(self.sql_find_table_names).fetchall()])
        for table in tables.intersection(DEPRECATED_TABLES):
            aws_tools.debug(f"Removing deprecated '{table} 'table from {self.db_path}", 2)
            self.db_cursor.execute(self.sql_drop_table.format(table_name=table))
