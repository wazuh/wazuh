# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
from os import path
from datetime import datetime

sys.path.append(path.dirname(path.realpath(__file__)))
import aws_service

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))
import aws_tools


SUPPORTED_REGIONS = (
    'ap-northeast-1', 'ap-northeast-2', 'ap-south-1', 'ap-southeast-2', 'eu-central-1', 'eu-north-1', 'eu-west-1',
    'eu-west-2', 'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2'
)


class AWSInspector(aws_service.AWSService):
    """
    Class for getting AWS Inspector logs

    Parameters
    ----------
    profile : str
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

    def __init__(self, reparse, profile, iam_role_arn, only_logs_after, account_alias, region, aws_log_groups=None,
                 remove_log_streams=None, discard_field=None, discard_regex=None,
                 sts_endpoint=None, service_endpoint=None, iam_role_duration=None, **kwargs):

        aws_service.AWSService.__init__(self, db_table_name=aws_service.DEFAULT_TABLENAME, service_name='inspector',
                                        reparse=reparse, profile=profile, iam_role_arn=iam_role_arn,
                                        only_logs_after=only_logs_after, account_alias=account_alias,
                                        region=region, aws_log_groups=aws_log_groups,
                                        remove_log_streams=remove_log_streams, discard_field=discard_field,
                                        discard_regex=discard_regex, sts_endpoint=sts_endpoint,
                                        service_endpoint=service_endpoint, iam_role_duration=iam_role_duration)

        # max DB records for region
        self.retain_db_records = 5
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
            aws_tools.debug(f"+++ Processing {len(response)} events", 3)
            for elem in response:
                if self.event_should_be_skipped(elem):
                    aws_tools.debug(f'+++ The "{self.discard_regex.pattern}" regex found a match in the '
                                    f'"{self.discard_field}" field. The event will be skipped.', 2)
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
                    'aws_region': self.region})
                last_scan = self.db_cursor.fetchone()[0]
        except TypeError as e:
            # write initial date if DB is empty
            self.db_cursor.execute(self.sql_insert_value.format(table_name=self.db_table_name), {
                'service_name': self.service_name,
                'aws_account_id': self.account_id,
                'aws_region': self.region,
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
        aws_tools.debug(f"+++ Listing findings starting from {date_scan}", 2)
        self.send_describe_findings(response['findingArns'])
        # Iterate if there are more elements
        while 'nextToken' in response:
            response = self.client.list_findings(maxResults=100, nextToken=response['nextToken'],
                                                 filter={'creationTimeRange': {'beginDate': date_scan,
                                                                               'endDate': date_current}})
            self.send_describe_findings(response['findingArns'])

        if self.sent_events:
            aws_tools.debug(f"+++ {self.sent_events} events collected and processed in {self.region}", 1)
        else:
            aws_tools.debug(f'+++ There are no new events in the "{self.region}" region', 1)

        # insert last scan in DB
        self.db_cursor.execute(self.sql_insert_value.format(table_name=self.db_table_name), {
            'service_name': self.service_name,
            'aws_account_id': self.account_id,
            'aws_region': self.region,
            'scan_date': date_current})
        # DB maintenance
        self.db_cursor.execute(self.sql_db_maintenance.format(table_name=self.db_table_name), {
            'service_name': self.service_name,
            'aws_account_id': self.account_id,
            'aws_region': self.region,
            'retain_db_records': self.retain_db_records})
        # close connection with DB
        self.close_db()

    @staticmethod
    def check_region(region: str) -> None:
        """
        Check if the region is supported.

        Parameters
        ----------
        region : str
            AWS region.
        """
        if region not in SUPPORTED_REGIONS:
            raise ValueError(f"Unsupported region '{region}'")
