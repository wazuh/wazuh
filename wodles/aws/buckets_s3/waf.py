# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import sys
from os import path
from aws_bucket import AWSCustomBucket

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))
import aws_tools


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
                            aws_tools.error(f"The {log_key} file doesn't have the expected structure.")
                            if not self.skip_on_error:
                                sys.exit(9)
                        content.append(event)

                except json.JSONDecodeError:
                    aws_tools.error("Events from {} file could not be loaded.".format(log_key.split('/')[-1]))
                    if not self.skip_on_error:
                        sys.exit(9)

        return json.loads(json.dumps(content))
