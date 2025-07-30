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

INSPECTOR_V1_REGIONS = (
    'ap-northeast-1', 'ap-northeast-2', 'ap-south-1', 'ap-southeast-2', 'eu-central-1', 'eu-north-1', 'eu-west-1',
    'eu-west-2', 'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2'
)

INSPECTOR_V2_REGIONS = (
    'af-south-1', 'ap-east-1', 'ap-northeast-3', 'ap-southeast-1', 'ap-southeast-3', 'ap-southeast-4',
    'ap-southeast-5', 'ap-southeast-7', 'ap-south-2', 'ca-central-1', 'ca-west-1', 'eu-west-3', 'eu-central-2',
    'eu-south-1', 'eu-south-2', 'il-central-1', 'me-central-1', 'sa-east-1', 'mx-central-1',
    'ap-northeast-1', 'ap-northeast-2', 'ap-south-1', 'ap-southeast-2', 'eu-central-1', 'eu-north-1', 'eu-west-1',
    'eu-west-2', 'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2'
)


class AWSInspector(aws_service.AWSService):
    """
    Class for getting AWS Inspector logs

    Parameters
    ----------
    access_key : str
        AWS access key id.
    secret_key : str
        AWS secret access key.
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

    def __init__(self, reparse, access_key, secret_key, profile,
                 iam_role_arn, only_logs_after, account_alias, region, aws_log_groups=None,
                 remove_log_streams=None, discard_field=None, discard_regex=None,
                 sts_endpoint=None, service_endpoint=None, iam_role_duration=None, **kwargs):

        aws_service.AWSService.__init__(self, db_table_name=aws_service.DEFAULT_TABLENAME, service_name='inspector',
                                        reparse=reparse, access_key=access_key, secret_key=secret_key,
                                        profile=profile, iam_role_arn=iam_role_arn, only_logs_after=only_logs_after,
                                        account_alias=account_alias, region=region, aws_log_groups=aws_log_groups,
                                        remove_log_streams=remove_log_streams, discard_field=discard_field,
                                        discard_regex=discard_regex, sts_endpoint=sts_endpoint,
                                        service_endpoint=service_endpoint, iam_role_duration=iam_role_duration)

        self.access_key = access_key
        self.secret_key = secret_key
        self.profile = profile
        self.iam_role_arn = iam_role_arn
        self.sts_endpoint = sts_endpoint
        self.service_endpoint = service_endpoint
        self.iam_role_duration = iam_role_duration
        self.region = region

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
        if arn_list:
            response = self.client.describe_findings(findingArns=arn_list)['findings']
            aws_tools.debug(f"+++ [v1] Processing {len(response)} events", 3)
            for elem in response:
                if self.event_should_be_skipped(elem):
                    aws_tools.debug(f'+++ The "{self.discard_regex.pattern}" regex found a match in the '
                                    f'"{self.discard_field}" field. The event will be skipped.', 2)
                    continue
                self.send_msg(self.format_message(elem))
                self.sent_events += 1

    def send_describe_findings_v2(self, client, finding_arns: list):
        """
        Collect and send to analysisd the requested findings from Inspector v2.

        Parameters
        ----------
        finding_arns : list[str]
            The ARNs of the findings that should be requested to AWS and sent to analysisd.
        """
        if not finding_arns:
            return
        # Split into chunks of 10 (Inspector v2 API limit)
        chunk_size = 10
        aws_tools.debug(f"+++ [v2] Processing {len(finding_arns)} events", 3)
        for i in range(0, len(finding_arns), chunk_size):
            chunk = finding_arns[i:i + chunk_size]

            try:
                response = client.batch_get_finding_details(findingArns=chunk)
                findings = response.get('findingDetails', [])

                for finding in findings:
                    if self.event_should_be_skipped(finding):
                        aws_tools.debug(f'+++ The "{self.discard_regex.pattern}" regex found a match in the '
                                        f'"{self.discard_field}" field. The event will be skipped.', 2)
                        continue
                    formatted = self.format_message(finding)
                    self.send_msg(formatted)
                    self.sent_events += 1

            except Exception as e:
                aws_tools.debug(f"+++ Error processing findings: {str(e)}", 1)

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

        if self.region in INSPECTOR_V1_REGIONS:
            aws_tools.debug(f"+++ Listing findings from {date_scan}", 2)
            response = self.client.list_findings(maxResults=100,
                                                 filter={'creationTimeRange': {'beginDate': date_scan,
                                                                               'endDate': date_current}})
            self.send_describe_findings(response['findingArns'])

            while 'nextToken' in response:
                response = self.client.list_findings(maxResults=100,
                                                     nextToken=response['nextToken'],
                                                     filter={'creationTimeRange': {'beginDate': date_scan,
                                                                                   'endDate': date_current}})
                self.send_describe_findings(response['findingArns'])

        if self.region in INSPECTOR_V2_REGIONS:
            self.get_alerts_inspector_v2(date_scan, date_current)

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

    def get_alerts_inspector_v2(self, date_scan, date_current):
        """
        Retrieve and process findings from AWS Inspector v2.

        Parameters
        ----------
        date_scan : datetime
            Start date for retrieving findings.
        date_current : datetime
            End date for retrieving findings.
        """
        client = self.get_client(
            access_key=self.access_key,
            secret_key=self.secret_key,
            profile=self.profile,
            iam_role_arn=self.iam_role_arn,
            service_name='inspector2',
            region=self.region,
            sts_endpoint=self.sts_endpoint,
            service_endpoint=self.service_endpoint,
            iam_role_duration=self.iam_role_duration
        )

        response = client.list_findings(
            maxResults=100,
            filterCriteria={
                'firstObservedAt': [{
                    'startInclusive': date_scan.isoformat(),
                    'endInclusive': date_current.isoformat()
                }]
            }
        )

        finding_arns = [f['findingArn'] for f in response.get('findings', [])]
        self.send_describe_findings_v2(client, finding_arns)

        while 'nextToken' in response:
            response = client.list_findings(
                maxResults=100,
                nextToken=response['nextToken'],
                filterCriteria={
                    'firstObservedAt': [{
                        'startInclusive': date_scan.isoformat(),
                        'endInclusive': date_current.isoformat()
                    }]
                }
            )
            finding_arns = [f['findingArn'] for f in response.get('findings', [])]
            self.send_describe_findings_v2(client, finding_arns)

    @staticmethod
    def check_region(region: str) -> None:
        if region not in INSPECTOR_V1_REGIONS and region not in INSPECTOR_V2_REGIONS:
            raise ValueError(f"Unsupported region '{region}'")

