# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys

sys.path.append(os.path.dirname(os.path.realpath(__file__)))
import aws_bucket
import constants


class AWSCloudTrailBucket(aws_bucket.AWSLogsBucket):
    """
    Represents a bucket with AWS CloudTrail logs
    """

    def __init__(self, **kwargs):
        kwargs['db_table_name'] = 'cloudtrail'
        aws_bucket.AWSLogsBucket.__init__(self, **kwargs)
        self.service = 'CloudTrail'
        self.field_to_load = 'Records'

    def reformat_msg(self, event):
        aws_bucket.AWSBucket.reformat_msg(self, event)
        # Some fields in CloudTrail are dynamic in nature, which causes problems for ES mapping
        # ES mapping expects for a dictionary, if the field is any other type (list or string)
        # turn it into a dictionary
        for field_to_cast in constants.AWS_CLOUDTRAIL_DYNAMIC_FIELDS:
            if field_to_cast in event['aws'] and not isinstance(event['aws'][field_to_cast], dict):
                event['aws'][field_to_cast] = {'string': str(event['aws'][field_to_cast])}

        if 'requestParameters' in event['aws']:
            request_parameters = event['aws']['requestParameters']
            if 'disableApiTermination' in request_parameters:
                disable_api_termination = request_parameters['disableApiTermination']
                if isinstance(disable_api_termination, bool):
                    request_parameters['disableApiTermination'] = {'value': disable_api_termination}
                elif isinstance(disable_api_termination, dict):
                    pass
                else:
                    print("WARNING: Could not reformat event {0}".format(event))

        return event
