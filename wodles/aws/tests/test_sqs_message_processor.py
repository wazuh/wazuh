# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest
import json
import sys
import os

sys.path.append(
    os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "subscribers")
)
import sqs_message_processor as sqs


@pytest.mark.parametrize(
    "msg, expected",
    [
        (
            {
                "Records": [
                    {"s3": {"object": {"key": "key"}, "bucket": {"name": "name"}}}
                ]
            },
            {"route": {"log_path": "key", "bucket_path": "name"}},
        ),
        ({"example": "some_value"}, {"raw_message": {"example": "some_value"}}),
    ],
)
def test_aws_s3_message_processor(msg, expected):
    """
    Test AWSS3MessageProcessor parse_message method.
    """
    processor = sqs.AWSS3MessageProcessor()
    assert processor.parse_message(msg) == expected


@pytest.mark.parametrize(
    "msg, expected",
    [
        (
            {"detail": {"object": {"key": "key"}, "bucket": {"name": "name"}}},
            {"route": {"log_path": "key", "bucket_path": "name"}},
        ),
        ({"example": "some_value"}, {"raw_message": {"example": "some_value"}}),
    ],
)
def test_aws_sec_lake_message_processor(msg, expected):
    """
    Test AWSSSecLakeMessageProcessor parse_message method.
    """
    processor = sqs.AWSSSecLakeMessageProcessor()
    assert processor.parse_message(msg) == expected


@pytest.mark.parametrize(
    "sqs_processor, sqs_messages, expected",
    [
        (
            sqs.AWSS3MessageProcessor,
            [
                {
                    "ReceiptHandle": "h1",
                    "Body": {
                        "Records": [
                            {
                                "s3": {
                                    "object": {"key": "key1"},
                                    "bucket": {"name": "name1"},
                                }
                            }
                        ]
                    },
                },
                {
                    "ReceiptHandle": "h2",
                    "Body": {
                        "Records": [
                            {
                                "s3": {
                                    "object": {"key": "key2"},
                                    "bucket": {"name": "name2"},
                                }
                            }
                        ]
                    },
                },
            ],
            [
                {"route": {"log_path": "key1", "bucket_path": "name1"}, "handle": "h1"},
                {"route": {"log_path": "key2", "bucket_path": "name2"}, "handle": "h2"},
            ],
        ),
        (
            sqs.AWSSSecLakeMessageProcessor,
            [
                {
                    "ReceiptHandle": "h1",
                    "Body": {
                        "detail": {
                            "object": {"key": "key1"},
                            "bucket": {"name": "name1"},
                        }
                    },
                },
                {"ReceiptHandle": "h2", "Body": {"example": "some_value"}},
            ],
            [
                {"route": {"log_path": "key1", "bucket_path": "name1"}, "handle": "h1"},
                {"raw_message": {"example": "some_value"}, "handle": "h2"},
            ],
        ),
        (
            sqs.AWSSSecLakeMessageProcessor,
            [
                {
                    "ReceiptHandle": "h1",
                    "Body": {
                        "detail": {
                            "object": {"key": "key1"},
                            "bucket": {"name": "name1"},
                        }
                    },
                },
                {
                    "ReceiptHandle": "h2",
                    "Body": {
                        "detail": {
                            "object": {"key": "key2"},
                            "bucket": {"name": "name2"},
                        }
                    },
                },
            ],
            [
                {"route": {"log_path": "key1", "bucket_path": "name1"}, "handle": "h1"},
                {"route": {"log_path": "key2", "bucket_path": "name2"}, "handle": "h2"},
            ],
        ),
        (
            sqs.AWSS3MessageProcessor,
            [
                {
                    "ReceiptHandle": "h1",
                    "Body": {
                        "Records": [
                            {
                                "s3": {
                                    "object": {"key": "key1"},
                                    "bucket": {"name": "name1"},
                                }
                            }
                        ]
                    },
                },
                {"ReceiptHandle": "h2", "Body": {"example": "some_value"}},
            ],
            [
                {"route": {"log_path": "key1", "bucket_path": "name1"}, "handle": "h1"},
                {"raw_message": {"example": "some_value"}, "handle": "h2"},
            ],
        ),
    ],
)
def test_extract_message_info(sqs_processor, sqs_messages, expected):
    """
    Test extract_message_info method of AWSQueueMessageProcessor subclasses.
    """
    processor = sqs_processor()
    for i, message in enumerate(sqs_messages):
        sqs_messages[i]["Body"] = json.dumps(message["Body"])
    result = processor.extract_message_info(sqs_messages)
    assert result == expected
