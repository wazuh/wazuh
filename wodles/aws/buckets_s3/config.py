# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
import re
from os import path
from datetime import datetime
from time import mktime

import aws_bucket

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))
import aws_tools


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
            aws_tools.error(f"There was an error while trying to extract a date from the marker '{marker}'")
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
        return self._remove_padding_zeros_from_marker(
            aws_bucket.AWSBucket.marker_custom_date(self, aws_region, aws_account_id, date))

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
