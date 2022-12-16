import csv
import sys
from os import path
from aws_bucket import  AWSLogsBucket
import boto3
import operator
from datetime import datetime
from datetime import timedelta
import botocore
sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))
import aws_s3

class AWSVPCFlowBucket(AWSLogsBucket):
    """
    Represents a bucket with AWS VPC logs
    """

    def __init__(self, **kwargs):
        kwargs['db_table_name'] = 'vpcflow'
        AWSLogsBucket.__init__(self, **kwargs)
        self.service = 'vpcflowlogs'
        self.access_key = kwargs['access_key']
        self.secret_key = kwargs['secret_key']
        self.profile_name = kwargs['aws_profile']
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

        self.sql_find_last_key_processed_of_day = """
            SELECT
                log_key
            FROM
                {table_name}
            WHERE
                bucket_path=:bucket_path AND
                aws_account_id=:aws_account_id AND
                aws_region = :aws_region AND
                flow_log_id = :flow_log_id AND
                created_date = :created_date
            ORDER BY
                log_key DESC
            LIMIT 1;"""

        self.sql_get_date_last_log_processed = """
            SELECT
                created_date
            FROM
                {table_name}
            WHERE
                bucket_path=:bucket_path AND
                aws_account_id=:aws_account_id AND
                aws_region = :aws_region AND
                flow_log_id = :flow_log_id
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

        try:
            ec2_client = boto_session.client(service_name='ec2', **self.connection_config)
        except Exception as e:
            print("Error getting EC2 client: {}".format(e))
            sys.exit(3)

        return ec2_client

    def get_flow_logs_ids(self, access_key, secret_key, region, profile_name=None):
        ec2_client = self.get_ec2_client(access_key, secret_key, region,
                                         profile_name=profile_name)
        flow_logs_ids = list(map(operator.itemgetter('FlowLogId'), ec2_client.describe_flow_logs()['FlowLogs']))
        return flow_logs_ids

    def already_processed(self, downloaded_file, aws_account_id, aws_region, flow_log_id):
        cursor = self.db_cursor.execute(self.sql_already_processed.format(table_name=self.db_table_name), {
            'bucket_path': self.bucket_path,
            'aws_account_id': aws_account_id,
            'aws_region': aws_region,
            'flow_log_id': flow_log_id,
            'log_key': downloaded_file})
        return cursor.fetchone()[0] > 0

    def get_days_since_today(self, date):
        date = datetime.strptime(date, "%Y%m%d")
        # it is necessary to add one day for processing the current day
        delta = datetime.utcnow() - date + timedelta(days=1)
        return delta.days

    def get_date_list(self, aws_account_id, aws_region, flow_log_id):
        num_days = self.get_days_since_today(self.get_date_last_log(aws_account_id, aws_region, flow_log_id))
        date_list_time = [datetime.utcnow() - timedelta(days=x) for x in range(0, num_days)]
        return [datetime.strftime(date, self.date_format) for date in reversed(date_list_time)]

    def get_date_last_log(self, aws_account_id, aws_region, flow_log_id):
        last_date_processed = self.only_logs_after.strftime('%Y%m%d') if \
            self.only_logs_after and self.reparse else None

        if not last_date_processed:
            try:
                query_date_last_log = self.db_cursor.execute(
                    self.sql_get_date_last_log_processed.format(table_name=self.db_table_name), {
                        'bucket_path': self.bucket_path,
                        'aws_account_id': aws_account_id,
                        'aws_region': aws_region,
                        'flow_log_id': flow_log_id})
                # query returns an integer
                db_date = str(query_date_last_log.fetchone()[0])
                if self.only_logs_after:
                    last_date_processed = db_date if datetime.strptime(db_date, '%Y%m%d') > self.only_logs_after else \
                        datetime.strftime(self.only_logs_after, '%Y%m%d')
                else:
                    last_date_processed = db_date
            # if DB is empty
            except (TypeError, IndexError) as e:
                last_date_processed = self.only_logs_after.strftime('%Y%m%d') if self.only_logs_after \
                    else self.default_date.strftime('%Y%m%d')
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
                aws_s3.debug("+++ Working on {} - {}".format(aws_account_id, aws_region), 1)
                # get flow log ids for the current region
                flow_logs_ids = self.get_flow_logs_ids(self.access_key,
                                                       self.secret_key,
                                                       aws_region, profile_name=self.profile_name)
                # for each flow log id
                for flow_log_id in flow_logs_ids:
                    date_list = self.get_date_list(aws_account_id, aws_region, flow_log_id)
                    for date in date_list:
                        self.iter_files_in_bucket(aws_account_id, aws_region, date, flow_log_id)
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
        aws_s3.debug("+++ DB Maintenance", 1)
        try:
            if self.db_count_region(aws_account_id, aws_region, flow_log_id) > self.retain_db_records:
                self.db_cursor.execute(self.sql_db_maintenance.format(table_name=self.db_table_name), {
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

    def build_s3_filter_args(self, aws_account_id, aws_region, date, flow_log_id, iterating=False):
        filter_marker = ''
        if self.reparse:
            filter_marker = self.marker_custom_date(aws_region, aws_account_id,
                                                    datetime.strptime(date, self.date_format))
        else:
            query_last_key_of_day = self.db_cursor.execute(
                self.sql_find_last_key_processed_of_day.format(table_name=self.db_table_name), {
                    'bucket_path': self.bucket_path,
                    'aws_account_id': aws_account_id,
                    'aws_region': aws_region,
                    'flow_log_id': flow_log_id,
                    'created_date': int(date.replace('/', ''))})
            try:
                filter_marker = query_last_key_of_day.fetchone()[0]
            except (TypeError, IndexError) as e:
                # if DB is empty for a region
                filter_marker = self.get_full_prefix(aws_account_id, aws_region) + date

        vpc_prefix = self.get_vpc_prefix(aws_account_id, aws_region, date, flow_log_id)
        filter_args = {
            'Bucket': self.bucket,
            'MaxKeys': 1000,
            'Prefix': vpc_prefix
        }

        # if nextContinuationToken is not used for processing logs in a bucket
        if not iterating:
            filter_args['StartAfter'] = filter_marker
            if self.only_logs_after:
                only_logs_marker = self.marker_only_logs_after(aws_region, aws_account_id)
                filter_args['StartAfter'] = only_logs_marker if only_logs_marker > filter_marker else filter_marker
            aws_s3.debug(f'+++ Marker: {filter_args.get("StartAfter")}', 2)

        return filter_args

    def iter_files_in_bucket(self, aws_account_id, aws_region, date, flow_log_id):
        try:
            bucket_files = self.client.list_objects_v2(
                **self.build_s3_filter_args(aws_account_id, aws_region, date, flow_log_id))

            if 'Contents' not in bucket_files:
                aws_s3.debug("+++ No logs to process for {} flow log ID in bucket: {}/{}".format(flow_log_id,
                                                                                          aws_account_id, aws_region),
                      1)
                return

            for bucket_file in bucket_files['Contents']:
                if not bucket_file['Key']:
                    continue

                if bucket_file['Key'][-1] == '/':
                    # The file is a folder
                    continue

                if self.already_processed(bucket_file['Key'], aws_account_id, aws_region, flow_log_id):
                    if self.reparse:
                        aws_s3.debug("++ File previously processed, but reparse flag set: {file}".format(
                            file=bucket_file['Key']), 1)
                    else:
                        aws_s3.debug("++ Skipping previously processed file: {file}".format(file=bucket_file['Key']), 1)
                        continue

                aws_s3.debug("++ Found new log: {0}".format(bucket_file['Key']), 2)
                # Get the log file from S3 and decompress it
                log_json = self.get_log_file(aws_account_id, bucket_file['Key'])
                self.iter_events(log_json, bucket_file['Key'], aws_account_id)
                # Remove file from S3 Bucket
                if self.delete_file:
                    aws_s3.debug("+++ Remove file from S3 Bucket:{0}".format(bucket_file['Key']), 2)
                    self.client.delete_object(Bucket=self.bucket, Key=bucket_file['Key'])
                self.mark_complete(aws_account_id, aws_region, bucket_file, flow_log_id)
            # Iterate if there are more logs
            while bucket_files['IsTruncated']:
                new_s3_args = self.build_s3_filter_args(aws_account_id, aws_region, date, flow_log_id, True)
                new_s3_args['ContinuationToken'] = bucket_files['NextContinuationToken']
                bucket_files = self.client.list_objects_v2(**new_s3_args)

                if 'Contents' not in bucket_files:
                    aws_s3.debug("+++ No logs to process for {} flow log ID in bucket: {}/{}".format(flow_log_id,
                                                                                              aws_account_id,
                                                                                              aws_region), 1)
                    return

                for bucket_file in bucket_files['Contents']:
                    if not bucket_file['Key']:
                        continue

                    if bucket_file['Key'][-1] == '/':
                        # The file is a folder
                        continue

                    if self.already_processed(bucket_file['Key'], aws_account_id, aws_region, flow_log_id):
                        if self.reparse:
                            aws_s3.debug("++ File previously processed, but reparse flag set: {file}".format(
                                file=bucket_file['Key']), 1)
                        else:
                            aws_s3.debug("++ Skipping previously processed file: {file}".format(file=bucket_file['Key']), 1)
                            continue
                    aws_s3.debug("++ Found new log: {0}".format(bucket_file['Key']), 2)
                    # Get the log file from S3 and decompress it
                    log_json = self.get_log_file(aws_account_id, bucket_file['Key'])
                    self.iter_events(log_json, bucket_file['Key'], aws_account_id)
                    # Remove file from S3 Bucket
                    if self.delete_file:
                        aws_s3.debug("+++ Remove file from S3 Bucket:{0}".format(bucket_file['Key']), 2)
                        self.client.delete_object(Bucket=self.bucket, Key=bucket_file['Key'])
                    self.mark_complete(aws_account_id, aws_region, bucket_file, flow_log_id)

        except botocore.exceptions.ClientError as err:
            aws_s3.debug(f'ERROR: The "iter_files_in_bucket" request failed: {err}', 1)
            sys.exit(16)

        except Exception as err:
            if hasattr(err, 'message'):
                aws_s3.debug("+++ Unexpected error: {}".format(err.message), 2)
            else:
                aws_s3.debug("+++ Unexpected error: {}".format(err), 2)
            print("ERROR: Unexpected error querying/working with objects in S3: {}".format(err))
            sys.exit(7)

    def mark_complete(self, aws_account_id, aws_region, log_file, flow_log_id):
        if self.reparse:
            if self.already_processed(log_file['Key'], aws_account_id, aws_region, flow_log_id):
                aws_s3.debug(
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
                aws_s3.debug("+++ Error marking log {} as completed: {}".format(log_file['Key'], e), 2)

