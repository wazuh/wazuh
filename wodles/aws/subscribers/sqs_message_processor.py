# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import re
import sys
from os import path
from typing import List

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))
import aws_tools

# Name of a bucket, not an ARN, as S3 writes it in its notifications; legacy buckets may have upper case and underscores
BUCKET_NAME_REGEX = re.compile(r'[A-Za-z0-9._-]{1,255}')
# Directory buckets do not send S3 event notifications, and botocore builds their endpoint from their name
DIRECTORY_BUCKET_SUFFIXES = ('--x-s3', '--xa-s3')


class AWSQueueMessageProcessor:
    """Class in charge of processing the messages retrieved from an AWS SQS queue."""

    def extract_message_info(self, sqs_messages: List[dict]) -> List[dict]:
        messages = []
        for mesg in sqs_messages:
            body = mesg['Body']
            msg_handle = mesg["ReceiptHandle"]
            try:
                message = json.loads(body)
            except (ValueError, RecursionError):
                message_information = {'raw_message': body}
            else:
                aws_tools.debug(f'The message is: {message!r}', 2)
                message_information = self.parse_message(message)
            messages.append({**message_information, "handle": msg_handle, "message_id": mesg.get("MessageId")})
        return messages

    def parse_message(self, message: dict) -> dict:
        raise NotImplementedError

    @staticmethod
    def build_route(message, log_path, bucket_path) -> dict:
        """Return the route to the notified object, or the raw message if the key or bucket is not a valid name."""
        if isinstance(log_path, str) and log_path and isinstance(bucket_path, str) and \
                BUCKET_NAME_REGEX.fullmatch(bucket_path) and not bucket_path.endswith(DIRECTORY_BUCKET_SUFFIXES):
            return {"route": {"log_path": log_path, "bucket_path": bucket_path}}
        return {'raw_message': message}


class AWSS3MessageProcessor(AWSQueueMessageProcessor):
    def parse_message(self, message: dict) -> dict:
        try:
            log_path = message["Records"][0]["s3"]["object"]["key"]
            bucket_path = message["Records"][0]["s3"]["bucket"]["name"]
        except (KeyError, IndexError, TypeError):
            return {'raw_message': message}
        return self.build_route(message, log_path, bucket_path)


class AWSSSecLakeMessageProcessor(AWSQueueMessageProcessor):
    def parse_message(self, message: dict) -> dict:
        try:
            log_path = message["detail"]["object"]["key"]
            bucket_path = message["detail"]["bucket"]["name"]
        except (KeyError, TypeError):
            return {'raw_message': message}
        return self.build_route(message, log_path, bucket_path)
