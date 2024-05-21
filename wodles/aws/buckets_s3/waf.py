# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
from os import path
import json
from aws_bucket import AWSBucket, AWSCustomBucket, AWSLogsBucket

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))
import aws_tools

WAF_NATIVE = 'WAFNative'
WAF_KINESIS = 'WAFKinesis'
WAF_URL = 'https://documentation.wazuh.com/current/amazon/services/supported-services/waf.html'
WAF_DEPRECATED_MESSAGE = 'The functionality to process WAF logs stored in S3 via Kinesis was deprecated ' \
                           'in {release}. Consider configuring WAF to store its logs directly in an S3 ' \
                           'bucket instead. Check {url} for more information.'


class AWSWAFBucket(AWSCustomBucket):
    standard_http_headers = ['a-im', 'accept', 'accept-charset', 'accept-encoding', 'accept-language',
                             'access-control-request-method', 'access-control-request-headers', 'authorization',
                             'cache-control', 'connection', 'content-encoding', 'content-length', 'content-type',
                             'cookie', 'date', 'expect', 'forwarded', 'from', 'host', 'http2-settings', 'if-match',
                             'if-modified-since', 'if-none-match', 'if-range', 'if-unmodified-since', 'max-forwards',
                             'origin', 'pragma', 'prefer', 'proxy-authorization', 'range', 'referer', 'te', 'trailer',
                             'transfer-encoding', 'user-agent', 'upgrade', 'via', 'warning', 'x-requested-with',
                             'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-proto']

    def __init__(self, **kwargs):
        kwargs['db_table_name'] = 'waf'
        AWSCustomBucket.__init__(self, **kwargs)
        if self.check_waf_type():
            self.service = 'WAFLogs'
            self.type = WAF_NATIVE
        else:
            self.type = WAF_KINESIS

    def check_waf_type(self):
        try:
            return 'CommonPrefixes' in self.client.list_objects_v2(Bucket=self.bucket, Prefix=f'{self.prefix}AWSLogs', Delimiter='/', MaxKeys=1)
        except Exception as err:
            if hasattr(err, 'message'):
                aws_tools.debug(f"+++ Unexpected error: {err.message}", 2)
            else:
                aws_tools.debug(f"+++ Unexpected error: {err}", 2)
            print(f"ERROR: Unexpected error listing S3 objects: {err}")
            sys.exit(7)

    def load_information_from_file(self, log_key):
        """Load data from a WAF log file."""

        def json_event_generator(data):
            while data:
                json_data, json_index = decoder.raw_decode(data)
                data = data[json_index:]
                yield json_data

        content = []
        decoder = json.JSONDecoder()
        with self.decompress_file(self.bucket, log_key=log_key) as f:
            for line in f.readlines():
                try:
                    for event in json_event_generator(line.rstrip()):
                        event['source'] = 'waf'
                        try:
                            headers = {}
                            for element in event['httpRequest']['headers']:
                                name = element["name"]
                                if name.lower() in self.standard_http_headers:
                                    headers[name] = element["value"]
                            event['httpRequest']['headers'] = headers
                        except (KeyError, TypeError):
                            print(f"ERROR: the {log_key} file doesn't have the expected structure.")
                            if not self.skip_on_error:
                                sys.exit(9)
                        content.append(event)

                except json.JSONDecodeError:
                    print("ERROR: Events from {} file could not be loaded.".format(log_key.split('/')[-1]))
                    if not self.skip_on_error:
                        sys.exit(9)

        return json.loads(json.dumps(content))

    def get_service_prefix(self, account_id):
        return AWSLogsBucket.get_service_prefix(self, account_id)
        
    def get_full_prefix(self, account_id, account_region, acl_name=None):
        if self.type == WAF_NATIVE:
            path = self.client.list_objects_v2(Bucket=self.bucket)
            if 'Contents' in path:
                for obj in path['Contents']:
                    log_key = obj['Key']
                parts = log_key.split("/")
                acl_name = parts[parts.index("WAFLogs") + 2]
            return AWSLogsBucket.get_full_prefix(self, account_id, account_region, acl_name)
        else:
            return self.prefix

    def get_base_prefix(self):
        if self.type == WAF_NATIVE:
            return AWSLogsBucket.get_base_prefix(self)
        else:
            return self.prefix

    def iter_regions_and_accounts(self, account_id, regions):
        if self.type is not WAF_NATIVE:
            print(WAF_DEPRECATED_MESSAGE.format(release="5.0", url=WAF_URL))
            self.check_prefix = True
        AWSCustomBucket.iter_regions_and_accounts(self, account_id, regions)      
