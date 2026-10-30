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
from unittest.mock import patch


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
                    "MessageId": "m1",
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
                    "MessageId": "m2",
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
                {"route": {"log_path": "key1", "bucket_path": "name1"}, "handle": "h1", "message_id": "m1"},
                {"route": {"log_path": "key2", "bucket_path": "name2"}, "handle": "h2", "message_id": "m2"},
            ],
        ),
        (
            sqs.AWSSSecLakeMessageProcessor,
            [
                {
                    "ReceiptHandle": "h1",
                    "MessageId": "m1",
                    "Body": {
                        "detail": {
                            "object": {"key": "key1"},
                            "bucket": {"name": "name1"},
                        }
                    },
                },
                {"ReceiptHandle": "h2", "MessageId": "m2", "Body": {"example": "some_value"}},
            ],
            [
                {"route": {"log_path": "key1", "bucket_path": "name1"}, "handle": "h1", "message_id": "m1"},
                {"raw_message": {"example": "some_value"}, "handle": "h2", "message_id": "m2"},
            ],
        ),
        (
            sqs.AWSSSecLakeMessageProcessor,
            [
                {
                    "ReceiptHandle": "h1",
                    "MessageId": "m1",
                    "Body": {
                        "detail": {
                            "object": {"key": "key1"},
                            "bucket": {"name": "name1"},
                        }
                    },
                },
                {
                    "ReceiptHandle": "h2",
                    "MessageId": "m2",
                    "Body": {
                        "detail": {
                            "object": {"key": "key2"},
                            "bucket": {"name": "name2"},
                        }
                    },
                },
            ],
            [
                {"route": {"log_path": "key1", "bucket_path": "name1"}, "handle": "h1", "message_id": "m1"},
                {"route": {"log_path": "key2", "bucket_path": "name2"}, "handle": "h2", "message_id": "m2"},
            ],
        ),
        (
            sqs.AWSS3MessageProcessor,
            [
                {
                    "ReceiptHandle": "h1",
                    "MessageId": "m1",
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
                {"ReceiptHandle": "h2", "MessageId": "m2", "Body": {"example": "some_value"}},
            ],
            [
                {"route": {"log_path": "key1", "bucket_path": "name1"}, "handle": "h1", "message_id": "m1"},
                {"raw_message": {"example": "some_value"}, "handle": "h2", "message_id": "m2"},
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


def s3_notification(key, bucket="name"):
    return {"Records": [{"s3": {"object": {"key": key}, "bucket": {"name": bucket}}}]}


def sec_lake_notification(key, bucket="name"):
    return {"detail": {"object": {"key": key}, "bucket": {"name": bucket}}}


@pytest.mark.parametrize(
    "msg",
    [
        [],
        "x",
        1,
        None,
        {"Records": []},
        {"Records": {}},
        {"Records": "abc"},
        {"Records": [None]},
        {"Records": [{"s3": []}]},
        {"Service": "Amazon S3", "Event": "s3:TestEvent", "Bucket": "name"},
        s3_notification(""),
        s3_notification(123),
        s3_notification("key", bucket=None),
        s3_notification(["key"]),
        s3_notification("key", bucket="arn:aws:s3:xx-fake-9:123456789012:accesspoint/test"),
        s3_notification("key", bucket="not a bucket"),
        s3_notification("key", bucket="x" * 256),
        s3_notification("key", bucket="bucket--use1-az4--x-s3"),
        s3_notification("key", bucket="bucket--usw2-lax1-az1--xa-s3"),
    ],
)
def test_aws_s3_message_processor_returns_raw_message_for_unexpected_formats(msg):
    """Test AWSS3MessageProcessor parse_message returns the raw message, instead of raising, for any message that
    is not a valid S3 object notification."""
    assert sqs.AWSS3MessageProcessor().parse_message(msg) == {"raw_message": msg}


@pytest.mark.parametrize(
    "msg",
    [
        [],
        "x",
        None,
        {"detail": []},
        {"detail": "abc"},
        {"detail": {"object": None, "bucket": {"name": "name"}}},
        sec_lake_notification(""),
        sec_lake_notification({"k": "v"}),
        sec_lake_notification("key", bucket=""),
    ],
)
def test_aws_sec_lake_message_processor_returns_raw_message_for_unexpected_formats(msg):
    """Test AWSSSecLakeMessageProcessor parse_message returns the raw message, instead of raising, for any message
    that is not a valid object notification."""
    assert sqs.AWSSSecLakeMessageProcessor().parse_message(msg) == {"raw_message": msg}


@pytest.mark.parametrize("body", ["x", "", "{", "[" * 100000 + "]" * 100000])
def test_extract_message_info_keeps_processing_the_batch_after_an_invalid_body(body):
    """Test extract_message_info returns the raw body of a message that is not JSON, or too deeply nested to parse,
    and still parses the rest of the batch."""
    sqs_messages = [
        {"ReceiptHandle": "h1", "MessageId": "m1", "Body": body},
        {"ReceiptHandle": "h2", "MessageId": "m2", "Body": json.dumps(s3_notification("key2"))},
    ]

    result = sqs.AWSS3MessageProcessor().extract_message_info(sqs_messages)

    assert result == [
        {"raw_message": body, "handle": "h1", "message_id": "m1"},
        {"route": {"log_path": "key2", "bucket_path": "name"}, "handle": "h2", "message_id": "m2"},
    ]


def test_extract_message_info_prints_message_on_a_single_line(capsys):
    """Test the debug message with the content of a message prints it escaped, since each output line is sent to
    Wazuh as an event."""
    sqs_messages = [{"ReceiptHandle": "h1", "MessageId": "m1", "Body": json.dumps('a\n{"integration": "aws"}')}]

    with patch('sqs_message_processor.aws_tools.debug_level', 2):
        sqs.AWSS3MessageProcessor().extract_message_info(sqs_messages)

    assert all(line.startswith('DEBUG: ') for line in capsys.readouterr().out.splitlines())


@pytest.mark.parametrize("bucket", ["my-bucket", "my.bucket.example.com", "Legacy_Bucket", "x" * 255,
                                    "my-access-point-abcdefghijk-s3alias", "my-ap--ol-s3"])
def test_build_route_accepts_bucket_names(bucket):
    """Test the route keeps the bucket names S3 writes in its notifications, including legacy names."""
    assert sqs.AWSS3MessageProcessor().parse_message(s3_notification("key", bucket=bucket)) == \
        {"route": {"log_path": "key", "bucket_path": bucket}}
