# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
from os import path
import json
from aws_bucket import AWSBucket, AWSCustomBucket, AWSLogsBucket

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))
import aws_tools

GUARDDUTY_URL = 'https://documentation.wazuh.com/current/amazon/services/supported-services/guardduty.html'
GUARDDUTY_DEPRECATED_MESSAGE = 'The functionality to process GuardDuty logs stored in S3 via Kinesis was deprecated ' \
                               'in {release}. Consider configuring GuardDuty to store its findings directly in an S3 ' \
                               'bucket instead. Check {url} for more information.'


class AWSGuardDutyBucket(AWSCustomBucket):

    def __init__(self, **kwargs):
        kwargs['db_table_name'] = 'guardduty'
        AWSCustomBucket.__init__(self, **kwargs)

        self.service = 'GuardDuty'
        if self.check_guardduty_type():
            self.type = "GuardDutyNative"
            self.empty_bucket_message_template = AWSBucket.empty_bucket_message_template
        else:
            self.type = "GuardDutyKinesis"

    def check_guardduty_type(self):
        try:
            return \
                    'CommonPrefixes' in self.client.list_objects_v2(Bucket=self.bucket, Prefix=f'{self.prefix}AWSLogs',
                                                                    Delimiter='/', MaxKeys=1)
        except Exception as err:
            if hasattr(err, 'message'):
                aws_tools.debug(f"+++ Unexpected error: {err.message}", 2)
            else:
                aws_tools.debug(f"+++ Unexpected error: {err}", 2)
            aws_tools.error(f"Unexpected error querying/working with objects in S3: {err}")
            sys.exit(7)

    def get_service_prefix(self, account_id):
        return AWSLogsBucket.get_service_prefix(self, account_id)

    def get_full_prefix(self, account_id, account_region):
        if self.type == "GuardDutyNative":
            return AWSLogsBucket.get_full_prefix(self, account_id, account_region)
        else:
            return self.prefix

    def get_base_prefix(self):
        if self.type == "GuardDutyNative":
            return AWSLogsBucket.get_base_prefix(self)
        else:
            return self.prefix

    def iter_regions_and_accounts(self, account_id, regions):
        if self.type == "GuardDutyNative":
            AWSBucket.iter_regions_and_accounts(self, account_id, regions)
        else:
            print(GUARDDUTY_DEPRECATED_MESSAGE.format(release="4.5", url=GUARDDUTY_URL))
            self.check_prefix = True
            AWSCustomBucket.iter_regions_and_accounts(self, account_id, regions)

    def send_event(self, event):
        # Send the message (splitted if it is necessary)
        for msg in self.reformat_msg(event):
            self.send_msg(msg)

    def reformat_msg(self, event):
        aws_tools.debug('++ Reformat message', 3)
        if event['aws']['source'] == 'guardduty' and 'service' in event['aws'] and \
                'action' in event['aws']['service'] and \
                'portProbeAction' in event['aws']['service']['action'] and \
                'portProbeDetails' in event['aws']['service']['action']['portProbeAction'] and \
                len(event['aws']['service']['action']['portProbeAction']['portProbeDetails']) > 1:

            port_probe_details = event['aws']['service']['action']['portProbeAction']['portProbeDetails']
            for detail in port_probe_details:
                event['aws']['service']['action']['portProbeAction']['portProbeDetails'] = detail
                yield event
        else:
            AWSBucket.reformat_msg(self, event)
            yield event

    def load_information_from_file(self, log_key):
        if log_key.endswith('.jsonl.gz'):
            with self.decompress_file(self.bucket, log_key=log_key) as f:
                json_list = list(f)
                result = []
                for json_item in json_list:
                    x = json.loads(json_item)
                    result.append(dict(x, source=x['service']['serviceName']))
                return result
        else:
            return AWSCustomBucket.load_information_from_file(self, log_key)
