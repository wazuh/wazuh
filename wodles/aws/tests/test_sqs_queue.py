# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
import os
from unittest.mock import patch
import pytest
import json

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '.'))
import aws_utils as utils

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))
import wazuh_integration

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'subscribers'))
import sqs_queue
import sqs_message_processor

import botocore
import gzip
import socket
import urllib3

SAMPLE_RAW_MESSAGE = {'Messages': [{'MessageId': 'string', 'ReceiptHandle': 'string', 'MD5OfBody': 'string',
                                    'Body': '{"detail": {"bucket": {"name": "example-bucket"},"object": {"key": '
                                            '"example-key"}}}', 'Attributes': {'string': 'string'}}]}
SAMPLE_BODY = json.loads(SAMPLE_RAW_MESSAGE['Messages'][0]['Body'])
SAMPLE_MESSAGE = {"handle": SAMPLE_RAW_MESSAGE['Messages'][0]['ReceiptHandle']}
SAMPLE_URL = "sqs-test-url.com"


@patch('wazuh_integration.WazuhIntegration.get_client')
@patch('s3_log_handler.AWSS3LogHandler.__init__', return_value=None)
@patch('sqs_message_processor.AWSQueueMessageProcessor.__init__')
@patch('sqs_queue.AWSSQSQueue._get_sqs_url')
@patch('wazuh_integration.WazuhIntegration.__init__', return_value=None)
def test_aws_sqs_queue_initializes_properly(mock_wazuh_integration, mock_get_sqs_url, mock_message_processor,
                                            mock_bucket_log_handler_init, mock_client):
    """Test if the instances of AWSSQSQueue are created properly."""
    kwargs = utils.get_aws_sqs_queue_parameters(name=utils.TEST_SQS_NAME,
                                                external_id=utils.TEST_EXTERNAL_ID,
                                                service_endpoint=utils.TEST_SERVICE_ENDPOINT,
                                                sts_endpoint=utils.TEST_STS_ENDPOINT,
                                                iam_role_arn=utils.TEST_IAM_ROLE_ARN,
                                                iam_role_duration=utils.TEST_IAM_ROLE_DURATION)
    integration = sqs_queue.AWSSQSQueue(message_processor=mock_message_processor,
                                        bucket_handler=mock_bucket_log_handler_init,
                                        **kwargs)
    mock_wazuh_integration.assert_called_with(integration,
                                              access_key=None, secret_key=None,
                                              iam_role_arn=kwargs["iam_role_arn"],
                                              profile=None,
                                              external_id=kwargs["external_id"],
                                              service_name='sqs',
                                              sts_endpoint=kwargs["sts_endpoint"],
                                              skip_on_error=False,
                                              iam_role_duration=kwargs["iam_role_duration"])

    assert integration.sqs_name == kwargs['name']
    assert integration.iam_role_arn == kwargs['iam_role_arn']
    mock_get_sqs_url.assert_called_once()
    mock_bucket_log_handler_init.assert_called_once()
    # The handler raises the errors of a file instead of exiting, so the queue decides what to do with the message
    assert mock_bucket_log_handler_init.call_args.kwargs['skip_on_error'] is True


# both configs must omit the owner id when resolving the queue URL
@pytest.mark.parametrize('iam_role_arn', [
    utils.TEST_IAM_ROLE_ARN,  # cross-/same-account via assumed role
    None,                     # direct credentials, no role
])
@patch('wazuh_integration.WazuhIntegration.__init__', side_effect=wazuh_integration.WazuhIntegration.__init__)
def test_aws_sqs_queue_get_sqs_url_omits_queue_owner_account_id(mock_wazuh_integration, iam_role_arn):
    """Test '_get_sqs_url' resolves the queue URL without passing QueueOwnerAWSAccountId.

    The SQS client is already scoped to the iam_role_arn target (or to the direct credentials),
    so SQS derives the queue owner from the caller account. Passing an account id would break the
    cross-account case (queue looked up in the manager's account instead of the role's account).
    """
    instance = utils.get_mocked_aws_sqs_queue(iam_role_arn=iam_role_arn)
    # asserting the exact kwargs guarantees QueueOwnerAWSAccountId is not passed
    instance.client.get_queue_url.assert_called_once_with(QueueName=instance.sqs_name)


@patch('sqs_queue.AWSSQSQueue._get_sqs_url', return_value=SAMPLE_URL)
@patch('wazuh_integration.WazuhIntegration.__init__', side_effect=wazuh_integration.WazuhIntegration.__init__)
def test_aws_sqs_queue_delete_message(mock_wazuh_integration, mock_get_url):
    """Test 'delete_message' method sends the given message to SQS."""
    instance = utils.get_mocked_aws_sqs_queue()
    instance.delete_message(SAMPLE_MESSAGE)

    instance.client.delete_message.assert_called_with(QueueUrl=SAMPLE_URL, ReceiptHandle=SAMPLE_MESSAGE["handle"])


@patch('wazuh_integration.WazuhIntegration.__init__', side_effect=wazuh_integration.WazuhIntegration.__init__)
def test_aws_sqs_queue_delete_message_handles_exception_when_deleting_message(mock_wazuh_integration, capsys):
    """Test 'delete_message' handles exceptions raised when trying to delete a message from SQS, printing the reason
    as an error."""
    instance = utils.get_mocked_aws_sqs_queue()
    instance.client.delete_message.side_effect = Exception('expired token')

    with pytest.raises(SystemExit) as e:
        instance.delete_message(SAMPLE_MESSAGE)
    assert e.value.code == utils.UNABLE_TO_FETCH_DELETE_FROM_QUEUE
    assert 'ERROR: Error deleting message from SQS: expired token' in capsys.readouterr().out


@patch('sqs_queue.AWSSQSQueue._get_sqs_url', return_value=SAMPLE_URL)
@patch('wazuh_integration.WazuhIntegration.__init__', side_effect=wazuh_integration.WazuhIntegration.__init__)
def test_aws_sqs_queue_fetch_messages(mock_wazuh_integration, mock_get_url):
    """Test 'fetch_messages' method retrieves one or more messages from the specified queue."""
    instance = utils.get_mocked_aws_sqs_queue()
    mock_receive = instance.client.receive_message
    mock_receive.return_value = SAMPLE_RAW_MESSAGE

    raw_messages = instance.fetch_messages()
    mock_receive.assert_called_with(QueueUrl=instance.sqs_url, AttributeNames=['All'],
                                    MaxNumberOfMessages=10, MessageAttributeNames=['All'],
                                    WaitTimeSeconds=20)
    assert type(raw_messages) is dict


@patch('wazuh_integration.WazuhIntegration.__init__', side_effect=wazuh_integration.WazuhIntegration.__init__)
def test_aws_sqs_queue_fetch_messages_handles_exception_when_getting_messages(mock_wazuh_integration, capsys):
    """Test 'fetch_messages' handles exceptions raised when trying to retrieve messages from SQS, printing the reason
    as an error."""
    instance = utils.get_mocked_aws_sqs_queue()

    mock_receive = instance.client.receive_message
    mock_receive.side_effect = Exception('expired token')

    with pytest.raises(SystemExit) as e:
        instance.fetch_messages()
    assert e.value.code == utils.UNABLE_TO_FETCH_DELETE_FROM_QUEUE
    assert 'ERROR: Error receiving message from SQS: expired token' in capsys.readouterr().out


@patch('sqs_queue.AWSSQSQueue.fetch_messages', return_value=SAMPLE_RAW_MESSAGE)
@patch('wazuh_integration.WazuhIntegration.__init__', side_effect=wazuh_integration.WazuhIntegration.__init__)
def test_aws_sqs_queue_get_messages(mock_wazuh_integration, mock_fetch):
    """Test 'get_messages' method returns parsed messages."""
    instance = utils.get_mocked_aws_sqs_queue()
    mocked_processor_extract = instance.message_processor.extract_message_info
    instance.get_messages()
    mocked_processor_extract.assert_called_with(SAMPLE_RAW_MESSAGE['Messages'])


@patch('wazuh_integration.WazuhIntegration.__init__', side_effect=wazuh_integration.WazuhIntegration.__init__)
def test_aws_sqs_queue_sync_events(mock_wazuh_integration):
    """Test 'sync_events' method gets messages from the SQS queue, sends them to AnalysisD
    and deletes from the queue until it is empty."""
    instance = utils.get_mocked_aws_sqs_queue()

    with patch('sqs_queue.AWSSQSQueue.get_messages',
               side_effect=[[{"route": {"log_path": SAMPLE_BODY["detail"]["object"]["key"],
                              "bucket_path": SAMPLE_BODY["detail"]["bucket"]["name"]},
                              "handle": SAMPLE_MESSAGE["handle"]}], []]),\
            patch('sqs_queue.AWSSQSQueue.delete_message') as mock_delete:
        mock_process = instance.bucket_handler.process_file

        instance.sync_events()

        mock_process.assert_called()
        mock_delete.assert_called()


ROUTE = {'log_path': 'key', 'bucket_path': 'bucket'}
VALID_MESSAGE = {'route': ROUTE, 'handle': 'h1', 'message_id': 'm1'}
S3_TEST_EVENT = {'Service': 'Amazon S3', 'Event': 's3:TestEvent', 'Bucket': 'bucket'}


def client_error(code):
    return botocore.exceptions.ClientError({'Error': {'Code': code, 'Message': 'message'}}, 'GetObject')


def get_queue(skip_on_error=False):
    instance = utils.get_mocked_aws_sqs_queue()
    instance.skip_on_error = skip_on_error
    return instance


def sqs_message(body, number):
    return {'Body': body if isinstance(body, str) else json.dumps(body), 'ReceiptHandle': f'h{number}',
            'MessageId': f'm{number}'}


def s3_notification(key, bucket='bucket'):
    return {'Records': [{'s3': {'object': {'key': key}, 'bucket': {'name': bucket}}}]}


@pytest.mark.parametrize('raw_message', [{'example': 'value'}, 'not json', [], None])
def test_aws_sqs_queue_process_message_deletes_message_without_notification(raw_message, capsys):
    """Test 'process_message' deletes, with a warning, a message that is not an object notification."""
    instance = get_queue()
    message = {'raw_message': raw_message, 'handle': 'h1', 'message_id': 'm1'}

    with patch('sqs_queue.AWSSQSQueue.delete_message') as mock_delete:
        assert instance.process_message(message) is None

    mock_delete.assert_called_once_with(message)
    instance.bucket_handler.process_file.assert_not_called()
    assert capsys.readouterr().out == \
           f'WARNING: Deleting message m1 from the SQS queue: it does not contain an object notification: ' \
           f'{raw_message!r}\n'


def test_aws_sqs_queue_process_message_truncates_deleted_content_in_the_warning(capsys):
    """Test 'process_message' prints only the beginning of a long deleted message, on a single line."""
    instance = get_queue()
    raw_message = {'Type': 'Notification', 'Message': 'x\n' * 1000}

    with patch('sqs_queue.AWSSQSQueue.delete_message'):
        instance.process_message({'raw_message': raw_message, 'handle': 'h1', 'message_id': 'm1'})

    output = capsys.readouterr().out
    assert output.endswith(f"notification: {repr(raw_message)[:200]}\n")
    assert len(output.splitlines()) == 1


def test_aws_sqs_queue_process_message_deletes_s3_test_event_without_warning(capsys):
    """Test 'process_message' deletes the S3 test event without printing a warning."""
    instance = get_queue()
    message = {'raw_message': S3_TEST_EVENT, 'handle': 'h1', 'message_id': 'm1'}

    with patch('sqs_queue.AWSSQSQueue.delete_message') as mock_delete:
        assert instance.process_message(message) is None

    mock_delete.assert_called_once_with(message)
    assert 'WARNING' not in capsys.readouterr().out


def test_aws_sqs_queue_process_message_deletes_processed_message():
    """Test 'process_message' processes the notified object and then deletes the message."""
    instance = get_queue()

    with patch('sqs_queue.AWSSQSQueue.delete_message') as mock_delete:
        assert instance.process_message(VALID_MESSAGE) is None

    instance.bucket_handler.process_file.assert_called_once_with(ROUTE)
    mock_delete.assert_called_once_with(VALID_MESSAGE)


@pytest.mark.parametrize('skip_on_error', [True, False])
@pytest.mark.parametrize('error', [client_error('NoSuchKey'), client_error('NoSuchBucket'),
                                   client_error('InvalidBucketName'), client_error('KeyTooLongError'),
                                   botocore.exceptions.ParamValidationError(report='Invalid bucket name')])
def test_aws_sqs_queue_process_message_deletes_message_when_object_is_unavailable(error, skip_on_error, capsys):
    """Test 'process_message' deletes, with a warning, a message whose object does not exist or has an invalid
    name, whatever the skip_on_error value."""
    instance = get_queue(skip_on_error)
    instance.bucket_handler.process_file.side_effect = error

    with patch('sqs_queue.AWSSQSQueue.delete_message') as mock_delete:
        assert instance.process_message(VALID_MESSAGE) is None

    mock_delete.assert_called_once_with(VALID_MESSAGE)
    assert capsys.readouterr().out.startswith(
        "WARNING: Deleting message m1 from the SQS queue: object 'key' in bucket 'bucket' is not available: ")


CONTENT_ERRORS = [ValueError('invalid content'), KeyError('detail'), IndexError('list index out of range'),
                  EOFError('Compressed file ended before the end-of-stream marker was reached'), MemoryError(),
                  gzip.BadGzipFile('Not a gzipped file'), RuntimeError("generator didn't yield")]
RETRYABLE_ERRORS = [client_error('AccessDenied'), client_error('SlowDown'),
                    botocore.exceptions.EndpointConnectionError(endpoint_url='https://s3'),
                    urllib3.exceptions.ProtocolError('Connection broken'), ConnectionResetError(104, 'reset'),
                    socket.timeout('timed out')]


@pytest.mark.parametrize('skip_on_error, error', [(False, error) for error in RETRYABLE_ERRORS + CONTENT_ERRORS] +
                                                 [(True, error) for error in RETRYABLE_ERRORS])
def test_aws_sqs_queue_process_message_keeps_message_for_a_later_run(skip_on_error, error, capsys):
    """Test 'process_message' keeps the message for a later run, without stopping the module, when its object
    cannot be fetched or processed, unless skip_on_error is set and the error does not come from AWS or the
    connection to it."""
    instance = get_queue(skip_on_error=skip_on_error)
    instance.bucket_handler.process_file.side_effect = error

    with patch('sqs_queue.AWSSQSQueue.delete_message') as mock_delete:
        assert instance.process_message(VALID_MESSAGE) is error

    mock_delete.assert_not_called()
    assert capsys.readouterr().out.startswith(
        "ERROR: Could not process object 'key' in bucket 'bucket', keeping message m1 in the SQS queue for a later "
        "run: ")


@pytest.mark.parametrize('error', CONTENT_ERRORS)
def test_aws_sqs_queue_process_message_deletes_message_on_content_error_with_skip_on_error(error, capsys):
    """Test 'process_message' skips and deletes the message when its object cannot be read or parsed and
    skip_on_error is set."""
    instance = get_queue(skip_on_error=True)
    instance.bucket_handler.process_file.side_effect = error

    with patch('sqs_queue.AWSSQSQueue.delete_message') as mock_delete:
        assert instance.process_message(VALID_MESSAGE) is None

    mock_delete.assert_called_once_with(VALID_MESSAGE)
    assert capsys.readouterr().out.startswith(
        "ERROR: Skipping message m1: could not process object 'key' in bucket 'bucket': ")


@pytest.mark.parametrize('skip_on_error', [True, False])
def test_aws_sqs_queue_process_message_does_not_catch_exits(skip_on_error):
    """Test 'process_message' does not delete the message when processing it stops the module, e.g. because the
    events cannot be sent to Wazuh."""
    instance = get_queue(skip_on_error)
    instance.bucket_handler.process_file.side_effect = SystemExit(utils.SENDING_MESSAGE_SOCKET_ERROR_CODE)

    with patch('sqs_queue.AWSSQSQueue.delete_message') as mock_delete, pytest.raises(SystemExit):
        instance.process_message(VALID_MESSAGE)

    mock_delete.assert_not_called()


@pytest.mark.parametrize('error', [client_error('NoSuchKey'), ValueError('bad\ncontent')])
def test_aws_sqs_queue_process_message_prints_names_on_a_single_line(error, capsys):
    """Test the key, bucket and error printed by 'process_message' cannot add lines to the output, since each output
    line is sent to Wazuh as an event."""
    instance = get_queue(skip_on_error=True)
    route = {'log_path': 'a\n{"integration": "aws"}', 'bucket_path': 'b\nc'}
    instance.bucket_handler.process_file.side_effect = error

    with patch('sqs_queue.AWSSQSQueue.delete_message'):
        instance.process_message({'route': route, 'handle': 'h1', 'message_id': 'm1'})

    assert len(capsys.readouterr().out.splitlines()) == 1


def test_aws_sqs_queue_sync_events_processes_the_rest_of_the_batch_after_invalid_messages():
    """Test 'sync_events' deletes the messages that are not object notifications and processes the others of the
    same batch."""
    instance = get_queue()
    instance.message_processor = sqs_message_processor.AWSS3MessageProcessor()
    batch = [sqs_message('[]', 0), sqs_message('x', 1), sqs_message({'Records': []}, 2), sqs_message(S3_TEST_EVENT, 3),
             sqs_message(s3_notification('key'), 4)]
    instance.client.receive_message.side_effect = [{'Messages': batch}, {}]

    instance.sync_events()

    instance.bucket_handler.process_file.assert_called_once_with(ROUTE)
    assert [c.kwargs['ReceiptHandle'] for c in instance.client.delete_message.call_args_list] == \
           ['h0', 'h1', 'h2', 'h3', 'h4']


def test_aws_sqs_queue_sync_events_stops_when_only_kept_messages_come_back(capsys):
    """Test 'sync_events' ends when a message kept after an error comes back in the same run, instead of retrying
    it while the visibility timeout is shorter than the receive wait, and exits with an error code."""
    instance = get_queue(skip_on_error=True)
    instance.message_processor = sqs_message_processor.AWSS3MessageProcessor()
    instance.bucket_handler.process_file.side_effect = client_error('AccessDenied')
    batch = {'Messages': [sqs_message(s3_notification('key'), 1)]}
    instance.client.receive_message.side_effect = [batch, batch, batch, {}]

    with pytest.raises(SystemExit) as e:
        instance.sync_events()

    assert e.value.code == utils.UNEXPECTED_ERROR_WORKING_WITH_S3
    instance.bucket_handler.process_file.assert_called_once_with(ROUTE)
    instance.client.delete_message.assert_not_called()
    assert instance.client.receive_message.call_count == 2
    assert capsys.readouterr().out.endswith('ERROR: 1 message(s) were kept in the SQS queue for a later run\n')


def test_aws_sqs_queue_sync_events_skips_kept_messages_mixed_with_new_ones():
    """Test 'sync_events' processes new messages received together with a message kept after an error, without
    retrying the kept one in the same run."""
    instance = get_queue(skip_on_error=True)
    instance.message_processor = sqs_message_processor.AWSS3MessageProcessor()
    instance.bucket_handler.process_file.side_effect = [client_error('AccessDenied'), None]
    kept, new = sqs_message(s3_notification('key'), 1), sqs_message(s3_notification('new'), 2)
    instance.client.receive_message.side_effect = [{'Messages': [kept]}, {'Messages': [kept, new]},
                                                   {'Messages': [kept]}, {}]

    with pytest.raises(SystemExit):
        instance.sync_events()

    assert [c.args[0]['log_path'] for c in instance.bucket_handler.process_file.call_args_list] == ['key', 'new']
    assert [c.kwargs['ReceiptHandle'] for c in instance.client.delete_message.call_args_list] == ['h2']
    assert instance.client.receive_message.call_count == 3


@pytest.mark.parametrize('skip_on_error', [True, False])
def test_aws_sqs_queue_sync_events_processes_the_queue_before_reporting_kept_messages(skip_on_error):
    """Test 'sync_events' processes the rest of the queue after a message kept after an error, and then exits with
    an error code."""
    instance = get_queue(skip_on_error=skip_on_error)
    instance.message_processor = sqs_message_processor.AWSS3MessageProcessor()
    instance.bucket_handler.process_file.side_effect = [client_error('AccessDenied'), None]
    batch = [sqs_message(s3_notification('key'), 1), sqs_message(s3_notification('new'), 2)]
    instance.client.receive_message.side_effect = [{'Messages': batch}, {}]

    with pytest.raises(SystemExit) as e:
        instance.sync_events()

    assert e.value.code == utils.UNEXPECTED_ERROR_WORKING_WITH_S3
    assert [c.args[0]['log_path'] for c in instance.bucket_handler.process_file.call_args_list] == ['key', 'new']
    assert [c.kwargs['ReceiptHandle'] for c in instance.client.delete_message.call_args_list] == ['h2']


def test_aws_sqs_queue_sync_events_does_not_exit_when_no_message_was_kept():
    """Test 'sync_events' ends normally when every message was processed or deleted, even if some were skipped."""
    instance = get_queue(skip_on_error=True)
    instance.message_processor = sqs_message_processor.AWSS3MessageProcessor()
    instance.bucket_handler.process_file.side_effect = [ValueError('invalid content'), None]
    batch = [sqs_message(s3_notification('key'), 1), sqs_message('x', 2), sqs_message(s3_notification('new'), 3)]
    instance.client.receive_message.side_effect = [{'Messages': batch}, {}]

    instance.sync_events()

    assert [c.kwargs['ReceiptHandle'] for c in instance.client.delete_message.call_args_list] == ['h1', 'h2', 'h3']


def test_aws_sqs_queue_sync_events_ends_with_kept_messages_without_id():
    """Test 'sync_events' ends when the messages without an ID kept after an error come back."""
    instance = get_queue(skip_on_error=True)
    instance.bucket_handler.process_file.side_effect = client_error('AccessDenied')
    batch = [{'route': ROUTE, 'handle': 'h1', 'message_id': None}]

    with patch('sqs_queue.AWSSQSQueue.get_messages', side_effect=[batch, batch, batch, []]) as mock_get, \
            pytest.raises(SystemExit):
        instance.sync_events()

    instance.bucket_handler.process_file.assert_called_once_with(ROUTE)
    assert mock_get.call_count == 2


UNANSWERED = botocore.exceptions.EndpointConnectionError(endpoint_url='https://s3')


@pytest.mark.parametrize('skip_on_error', [True, False])
def test_aws_sqs_queue_sync_events_stops_after_a_batch_of_unanswered_requests_in_a_row(skip_on_error, capsys):
    """Test 'sync_events' stops the run once the requests for the objects of MAX_CONSECUTIVE_UNANSWERED_REQUESTS
    messages in a row got no answer from AWS, as that points to a problem with every message, instead of receiving
    the whole queue on every run."""
    instance = get_queue(skip_on_error=skip_on_error)
    instance.message_processor = sqs_message_processor.AWSS3MessageProcessor()
    instance.bucket_handler.process_file.side_effect = UNANSWERED
    batches = [{'Messages': [sqs_message(s3_notification(f'key{n}'), n) for n in range(b * 10, b * 10 + 10)]}
               for b in range(3)]
    instance.client.receive_message.side_effect = batches + [{}]

    with pytest.raises(SystemExit) as e:
        instance.sync_events()

    assert e.value.code == utils.UNEXPECTED_ERROR_WORKING_WITH_S3
    assert instance.bucket_handler.process_file.call_count == sqs_queue.MAX_CONSECUTIVE_UNANSWERED_REQUESTS
    assert instance.client.receive_message.call_count == 1
    assert capsys.readouterr().out.endswith(
        'ERROR: Stopping after the requests for the objects of 10 messages in a row got no answer from AWS\n')


@pytest.mark.parametrize('error', [client_error('AccessDenied'), client_error('ExpiredToken'),
                                   client_error('AllAccessDisabled')])
def test_aws_sqs_queue_sync_events_does_not_stop_for_answers_from_aws(error):
    """Test the errors answered by AWS do not stop the run, even many in a row, as they may depend on the bucket named
    in each message: the rest of the queue is processed and the run exits with an error code."""
    instance = get_queue(skip_on_error=True)
    instance.message_processor = sqs_message_processor.AWSS3MessageProcessor()
    instance.bucket_handler.process_file.side_effect = [error] * 12 + [None]
    batch = [sqs_message(s3_notification(f'key{n}', bucket='foreign-bucket'), n) for n in range(12)]
    batch.append(sqs_message(s3_notification('key'), 12))
    instance.client.receive_message.side_effect = [{'Messages': batch[:10]}, {'Messages': batch[10:]}, {}]

    with pytest.raises(SystemExit) as e:
        instance.sync_events()

    assert e.value.code == utils.UNEXPECTED_ERROR_WORKING_WITH_S3
    assert instance.bucket_handler.process_file.call_count == 13
    assert [c.kwargs['ReceiptHandle'] for c in instance.client.delete_message.call_args_list] == ['h12']


def test_aws_sqs_queue_sync_events_does_not_stop_for_files_that_cannot_be_processed():
    """Test the files that cannot be read or parsed do not stop the run, even many in a row, as they do not point to a
    problem with every message: the rest of the queue is processed and the run exits with an error code."""
    instance = get_queue(skip_on_error=False)
    instance.message_processor = sqs_message_processor.AWSS3MessageProcessor()
    instance.bucket_handler.process_file.side_effect = [EOFError('truncated')] * 12 + [None]
    batch = [sqs_message(s3_notification(f'key{n}'), n) for n in range(13)]
    instance.client.receive_message.side_effect = [{'Messages': batch[:10]}, {'Messages': batch[10:]}, {}]

    with pytest.raises(SystemExit) as e:
        instance.sync_events()

    assert e.value.code == utils.UNEXPECTED_ERROR_WORKING_WITH_S3
    assert instance.bucket_handler.process_file.call_count == 13
    assert [c.kwargs['ReceiptHandle'] for c in instance.client.delete_message.call_args_list] == ['h12']


def test_aws_sqs_queue_sync_events_does_not_reset_the_count_on_messages_that_are_not_notifications():
    """Test a message that is not an object notification, which does not reach AWS, does not restart the count of
    requests without an answer in a row."""
    instance = get_queue(skip_on_error=False)
    instance.message_processor = sqs_message_processor.AWSS3MessageProcessor()
    instance.bucket_handler.process_file.side_effect = UNANSWERED
    batch = [sqs_message(s3_notification(f'key{n}'), n) for n in range(9)] + [sqs_message('x', 9),
                                                                             sqs_message(s3_notification('key10'), 10)]
    instance.client.receive_message.side_effect = [{'Messages': batch[:10]}, {'Messages': batch[10:]}, {}]

    with pytest.raises(SystemExit):
        instance.sync_events()

    assert instance.bucket_handler.process_file.call_count == 10
    assert instance.client.receive_message.call_count == 2


def test_aws_sqs_queue_sync_events_counts_unanswered_requests_in_a_row_from_the_last_object_provided():
    """Test a processed message restarts the count of requests without an answer in a row, so isolated errors do not
    stop the run."""
    instance = get_queue(skip_on_error=False)
    instance.message_processor = sqs_message_processor.AWSS3MessageProcessor()
    instance.bucket_handler.process_file.side_effect = [UNANSWERED] * 9 + [None] + [UNANSWERED] * 9
    batch = [sqs_message(s3_notification(f'key{n}'), n) for n in range(19)]
    instance.client.receive_message.side_effect = [{'Messages': batch[:10]}, {'Messages': batch[10:]}, {}]

    with pytest.raises(SystemExit):
        instance.sync_events()

    assert instance.bucket_handler.process_file.call_count == 19
    assert [c.kwargs['ReceiptHandle'] for c in instance.client.delete_message.call_args_list] == ['h9']


def test_aws_sqs_queue_sync_events_stops_at_the_next_receive_when_the_credentials_fail():
    """Test a failure of the credentials, which the queue shares with the buckets, stops the run when the next batch is
    received, without the count of requests without an answer."""
    instance = get_queue(skip_on_error=False)
    instance.message_processor = sqs_message_processor.AWSS3MessageProcessor()
    instance.bucket_handler.process_file.side_effect = client_error('ExpiredToken')
    batches = [{'Messages': [sqs_message(s3_notification(f'key{n}'), n) for n in range(10)]},
               botocore.exceptions.ClientError({'Error': {'Code': 'ExpiredToken', 'Message': 'expired'}},
                                               'ReceiveMessage')]
    instance.client.receive_message.side_effect = batches

    with pytest.raises(SystemExit) as e:
        instance.sync_events()

    assert e.value.code == utils.UNABLE_TO_FETCH_DELETE_FROM_QUEUE
    assert instance.bucket_handler.process_file.call_count == 10
