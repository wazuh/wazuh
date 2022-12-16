import sys
import botocore
import re
from os import path
from datetime import datetime
from datetime import timedelta
from time import mktime

import aws_bucket

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))
import aws_s3


class AWSConfigBucket(aws_bucket.AWSLogsBucket):
    """
    Represents a bucket with AWS Config logs
    """

    def __init__(self, **kwargs):
        kwargs['db_table_name'] = 'config'
        aws_bucket.AWSLogsBucket.__init__(self, **kwargs)
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
            last_date_processed = self.only_logs_after.strftime('%Y%m%d') if self.only_logs_after else \
                self.default_date.strftime('%Y%m%d')
        else:
            try:
                query_date_last_log = self.db_cursor.execute(
                    self.sql_find_last_log_processed.format(table_name=self.db_table_name), {
                        'bucket_path': self.bucket_path,
                        'aws_account_id': aws_account_id,
                        'aws_region': aws_region,
                        'prefix': self.prefix})
                # query returns an integer
                db_date = str(query_date_last_log.fetchone()[0])
                if self.only_logs_after:
                    last_date_processed = db_date if datetime.strptime(db_date, '%Y%m%d') > self.only_logs_after else \
                        datetime.strftime(self.only_logs_after, '%Y%m%d')
                else:
                    last_date_processed = db_date
            # if DB is empty
            except (TypeError, IndexError):
                last_date_processed = self.only_logs_after.strftime('%Y%m%d') if self.only_logs_after \
                    else self.default_date.strftime('%Y%m%d')
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
                aws_s3.debug("+++ Working on {} - {}".format(aws_account_id, aws_region), 1)
                # for processing logs day by day
                date_list = self.get_date_list(aws_account_id, aws_region)
                for date in date_list:
                    self.iter_files_in_bucket(aws_account_id, aws_region, date)
                self.db_maintenance(aws_account_id=aws_account_id, aws_region=aws_region)

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
        return datetime.strftime(datetime.strptime(date, self.date_format), aws_bucket.DB_DATE_FORMAT)

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
        return self._remove_padding_zeros_from_marker(aws_bucket.AWSBucket.marker_only_logs_after(self, aws_region,
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
        return self._remove_padding_zeros_from_marker(aws_bucket.AWSBucket.marker_custom_date(self, aws_region, aws_account_id,
                                                                                   date))

    def build_s3_filter_args(self, aws_account_id, aws_region, date, iterating=False):
        filter_marker = ''
        if self.reparse:
            filter_marker = self.marker_custom_date(aws_region, aws_account_id,
                                                    datetime.strptime(date, self.date_format))
        else:
            created_date = self._format_created_date(date)
            query_last_key_of_day = self.db_cursor.execute(
                self.sql_find_last_key_processed_of_day.format(table_name=self.db_table_name), {
                    'bucket_path': self.bucket_path,
                    'aws_account_id': aws_account_id,
                    'aws_region': aws_region,
                    'created_date': created_date,
                    'prefix': self.prefix})
            try:
                filter_marker = query_last_key_of_day.fetchone()[0]
            except (TypeError, IndexError) as e:
                # if DB is empty for a region
                filter_marker = self.get_full_prefix(aws_account_id, aws_region) + date

        # for getting only logs of the current date
        config_prefix = self.get_full_prefix(aws_account_id, aws_region) + date + '/'

        filter_args = {
            'Bucket': self.bucket,
            'MaxKeys': 1000,
            'Prefix': config_prefix
        }

        # if nextContinuationToken is not used for processing logs in a bucket
        if not iterating:
            try:
                extracted_date = self._extract_date_regex.search(filter_marker).group(0)
                filter_marker_date = datetime.strptime(extracted_date, self.date_format)
            except AttributeError:
                print(f"ERROR: There was an error while trying to extract a date from the file key '{filter_marker}'")
                sys.exit(16)
            else:
                if not self.only_logs_after or self.only_logs_after < filter_marker_date:
                    filter_args['StartAfter'] = filter_marker
                else:
                    filter_args['StartAfter'] = self.marker_only_logs_after(aws_region, aws_account_id)

                aws_s3.debug(f'+++ Marker: {filter_args.get("StartAfter")}', 2)

        return filter_args

    def iter_files_in_bucket(self, aws_account_id, aws_region, date):
        try:
            bucket_files = self.client.list_objects_v2(**self.build_s3_filter_args(aws_account_id, aws_region, date))

            if 'Contents' not in bucket_files:
                aws_s3.debug("+++ No logs to process in bucket: {}/{}".format(aws_account_id, aws_region), 1)
                return

            for bucket_file in bucket_files['Contents']:
                if not bucket_file['Key']:
                    continue

                if bucket_file['Key'][-1] == '/':
                    # The file is a folder
                    continue

                if self.already_processed(bucket_file['Key'], aws_account_id, aws_region):
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
                self.mark_complete(aws_account_id, aws_region, bucket_file)
            # Iterate if there are more logs
            while bucket_files['IsTruncated']:
                new_s3_args = self.build_s3_filter_args(aws_account_id, aws_region, date, True)
                new_s3_args['ContinuationToken'] = bucket_files['NextContinuationToken']
                bucket_files = self.client.list_objects_v2(**new_s3_args)

                if 'Contents' not in bucket_files:
                    aws_s3.debug("+++ No logs to process in bucket: {}/{}".format(aws_account_id, aws_region), 1)
                    return

                for bucket_file in bucket_files['Contents']:
                    if not bucket_file['Key']:
                        continue

                    if bucket_file['Key'][-1] == '/':
                        # The file is a folder
                        continue

                    if self.already_processed(bucket_file['Key'], aws_account_id, aws_region):
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
                    self.mark_complete(aws_account_id, aws_region, bucket_file)

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

    def reformat_msg(self, event):
        aws_bucket.AWSBucket.reformat_msg(self, event)
        if 'configuration' in event['aws']:
            configuration = event['aws']['configuration']

            # Remove unnecessary fields to avoid performance issues
            for key in configuration:
                if type(configuration[key]) is dict and "Content" in configuration[key]:
                    content_list = list(configuration[key]["Content"].keys())
                    configuration[key]["Content"] = content_list

            if 'securityGroups' in configuration:
                security_groups = configuration['securityGroups']
                if isinstance(security_groups, str):
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
                if isinstance(availability_zones, str):
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
                if isinstance(state, str):
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
                if isinstance(iam_profile, str):
                    configuration['iamInstanceProfile'] = {'name': iam_profile}
                elif isinstance(iam_profile, dict):
                    pass
                else:
                    print("WARNING: Could not reformat event {0}".format(event))

        return event

