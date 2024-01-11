# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
import csv
from os import path
from aws_bucket import AWSBucket, AWSCustomBucket

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))
import aws_tools


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
        kwargs['db_table_name'] = 'alb'
        AWSLBBucket.__init__(self, **kwargs)

    def load_information_from_file(self, log_key):
        """Load data from a ALB access log file."""
        with self.decompress_file(self.bucket, log_key=log_key) as f:
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
                        aws_tools.debug(f"Unable to process correctly ABL log entry, for field {field_to_process}.",
                                        msg_level=1)
                        aws_tools.debug(f"Log Entry: {log_entry}", msg_level=2)

            return tsv_file


class AWSCLBBucket(AWSLBBucket):

    def __init__(self, **kwargs):
        kwargs['db_table_name'] = 'clb'
        AWSLBBucket.__init__(self, **kwargs)

    def load_information_from_file(self, log_key):
        """Load data from a CLB access log file."""
        with self.decompress_file(self.bucket, log_key=log_key) as f:
            fieldnames = (
                "time", "elb", "client_port", "backend_port", "request_processing_time", "backend_processing_time",
                "response_processing_time", "elb_status_code", "backend_status_code", "received_bytes", "sent_bytes",
                "request", "user_agent", "ssl_cipher", "ssl_protocol")
            tsv_file = csv.DictReader(f, fieldnames=fieldnames, delimiter=' ')

            return [dict(x, source='clb') for x in tsv_file]


class AWSNLBBucket(AWSLBBucket):

    def __init__(self, **kwargs):
        kwargs['db_table_name'] = 'nlb'
        AWSLBBucket.__init__(self, **kwargs)

    def load_information_from_file(self, log_key):
        """Load data from a NLB access log file."""
        with self.decompress_file(self.bucket, log_key=log_key) as f:
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
