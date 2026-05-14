# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import csv
import sys
from os import path
from aws_bucket import AWSCustomBucket

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))
import aws_tools


class CiscoUmbrella(AWSCustomBucket):

    def __init__(self, **kwargs):
        kwargs['db_table_name'] = 'cisco_umbrella'
        AWSCustomBucket.__init__(self, **kwargs)
        self.check_prefix = False
        self.date_format = '%Y-%m-%d'

    def load_information_from_file(self, log_key):
        """Load data from a Cisco Umbrella log file."""
        with self.decompress_file(self.bucket, log_key=log_key) as f:
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
                aws_tools.error("Only 'dnslogs', 'proxylogs' or 'iplogs' are allowed for Cisco Umbrella")
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
