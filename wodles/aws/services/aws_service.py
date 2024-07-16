# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import copy
import sys
from os import path
from datetime import datetime

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))
import wazuh_integration

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))
import aws_tools

DEFAULT_DATABASE_NAME = "aws_services"
DEFAULT_TABLENAME = "aws_services"

AWS_SERVICE_MSG_TEMPLATE = {'integration': 'aws', 'aws': ''}


class AWSService(wazuh_integration.WazuhAWSDatabase):
    """
    Represents a service which provides events.

    This is an abstract class.

    Parameters
    ----------
    reparse : bool
        Whether to parse already parsed logs or not.
    profile : str
        AWS profile.
    iam_role_arn : str
        IAM Role.
    service_name : str
        Service name to extract logs from.
    only_logs_after : str
        Date after which obtain logs.
    account_alias: str
        AWS account alias.
    region : str
        Region name.
    db_table_name : str
        The name of the table to be created for the given bucket or service.
    discard_field : str
        Name of the event field to apply the regex value on.
    discard_regex : str
        REGEX value to determine whether an event should be skipped.
    sts_endpoint : str
        STS endpoint URL.
    service_endpoint : str
        Service endpoint URL.
    iam_role_duration : str
        The desired duration of the session that is going to be assumed.
    """

    def __init__(self, reparse: bool, profile: str, iam_role_arn: str, service_name: str, only_logs_after: str,
                 account_alias: str, region: str, db_table_name: str = DEFAULT_TABLENAME,
                 discard_field: str = None, discard_regex: str = None, sts_endpoint: str = None,
                 service_endpoint: str = None,
                 iam_role_duration: str = None, **kwargs):
        # DB name
        self.db_name = 'aws_services'
        # Table name
        self.db_table_name = db_table_name

        wazuh_integration.WazuhAWSDatabase.__init__(self, db_name=self.db_name, service_name=service_name,
                                                    profile=profile,
                                                    iam_role_arn=iam_role_arn, region=region,
                                                    discard_field=discard_field, discard_regex=discard_regex,
                                                    sts_endpoint=sts_endpoint, service_endpoint=service_endpoint,
                                                    iam_role_duration=iam_role_duration)
        self.reparse = reparse
        self.region = region
        self.service_name = service_name
        # get sts client (necessary for getting account ID)
        self.sts_client = self.get_sts_client(profile)
        # get account ID
        self.account_id = self.sts_client.get_caller_identity().get('Account')
        self.only_logs_after = only_logs_after
        self.account_alias = account_alias

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

    @staticmethod
    def check_region(region: str) -> None:
        """
        Check if the region is valid.

        Parameters
        ----------
        region : str
            AWS region.
        """
        if region not in aws_tools.ALL_REGIONS:
            raise ValueError(f"Invalid region '{region}'")

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
            msg['createdAt'] = datetime.strftime(msg['createdAt'], '%Y-%m-%dT%H:%M:%SZ')
        # cast updatedAt
        if 'updatedAt' in msg:
            msg['updatedAt'] = datetime.strftime(msg['updatedAt'], '%Y-%m-%dT%H:%M:%SZ')
        formatted_msg = copy.deepcopy(AWS_SERVICE_MSG_TEMPLATE)
        formatted_msg['aws'] = msg
        return formatted_msg
