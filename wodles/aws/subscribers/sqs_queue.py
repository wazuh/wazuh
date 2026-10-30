# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import botocore
import sys
from os import path
from typing import Optional

sys.path.append(path.join(path.dirname(path.realpath(__file__)), '..', 'subscribers'))
import s3_log_handler
import sqs_message_processor

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))
import wazuh_integration

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))
import aws_tools

# A batch of requests in a row without an answer from AWS points to a problem with every message, such as the network or
# the endpoint. An answer from AWS, such as AccessDenied, may depend on the bucket named in the message, so it does not
# count.
MAX_CONSECUTIVE_UNANSWERED_REQUESTS = 10


class AWSSQSQueue(wazuh_integration.WazuhIntegration):
    """Class for getting AWS SQS Queue notifications.

    Attributes
    ----------
    name: str
        Name of the SQS Queue.
    iam_role_arn : str
        IAM Role.
    access_key : str
        AWS access key id.
    secret_key : str
        AWS secret access key.
    external_id : str
        The name of the External ID to use.
    sts_endpoint : str
        URL for the VPC endpoint to use to obtain the STS token.
    service_endpoint : str
        URL for the endpoint to use to obtain the logs.
    message_processor: AWSQueueMessageProcessor
        Class to process received notifications.
    """

    def __init__(self, name: str, iam_role_arn: str, message_processor: sqs_message_processor.AWSQueueMessageProcessor,
                 bucket_handler: s3_log_handler.AWSS3LogHandler,
                 profile: str = None, iam_role_duration: int = None, external_id: str = None,
                 sts_endpoint=None, service_endpoint=None, skip_on_error=False,
                 **kwargs):
        self.sqs_name = name
        wazuh_integration.WazuhIntegration.__init__(self, access_key=None, secret_key=None,
                                                    iam_role_arn=iam_role_arn,
                                                    profile=profile, external_id=external_id, service_name='sqs',
                                                    sts_endpoint=sts_endpoint, skip_on_error=skip_on_error,
                                                    iam_role_duration=iam_role_duration,
                                                    **kwargs)
        self.sqs_url = self._get_sqs_url()
        self.iam_role_arn = iam_role_arn
        self.iam_role_duration = iam_role_duration
        # The queue decides what to do with a message whose file fails, so the handler raises instead of exiting
        self.bucket_handler = bucket_handler(external_id=external_id,
                                             iam_role_arn=self.iam_role_arn,
                                             iam_role_duration=self.iam_role_duration,
                                             service_endpoint=service_endpoint,
                                             sts_endpoint=sts_endpoint,
                                             skip_on_error=True,
                                             profile=profile,
                                             **kwargs)
        self.message_processor = message_processor()

    def _get_sqs_url(self) -> str:
        """Get the URL of the AWS SQS queue.

        Returns
        -------
        url : str
            The URL of the AWS SQS queue
        """
        try:
            url = self.client.get_queue_url(QueueName=self.sqs_name)['QueueUrl']
            aws_tools.debug(f'The SQS queue is: {url}', 2)
            return url
        except botocore.exceptions.ClientError:
            aws_tools.error('Queue does not exist, verify the given name')
            sys.exit(20)

    def delete_message(self, message: dict) -> None:
        """Delete message from the SQS queue.

        Parameters
        ----------
        message : dict
            An SQS message recieved from the queue
        """
        try:
            self.client.delete_message(QueueUrl=self.sqs_url, ReceiptHandle=message["handle"])
            aws_tools.debug(f'Message deleted from queue: {self.sqs_name}', 2)
        except Exception as e:
            aws_tools.error(f'Error deleting message from SQS: {e}')
            sys.exit(21)

    def fetch_messages(self) -> dict:
        """Retrieves one or more messages (up to 10), from the specified queue.

        Returns
        -------
        dict
            A dictionary with a list of messages from the SQS queue.
        """
        try:
            aws_tools.debug(f'Retrieving messages from: {self.sqs_name}', 2)
            return self.client.receive_message(QueueUrl=self.sqs_url, AttributeNames=['All'],
                                               MaxNumberOfMessages=10, MessageAttributeNames=['All'],
                                               WaitTimeSeconds=20)
        except Exception as e:
            aws_tools.error(f'Error receiving message from SQS: {e}')
            sys.exit(21)

    def get_messages(self) -> list:
        """Retrieve parsed messages from the SQS queue.

        Returns
        -------
        messages : list
            Parsed messages from the SQS queue.
        """
        sqs_raw_messages = self.fetch_messages()
        aws_tools.debug(f'The raw message is: {sqs_raw_messages}', 3)
        sqs_messages = sqs_raw_messages.get('Messages', [])

        return self.message_processor.extract_message_info(sqs_messages)

    def process_message(self, message: dict) -> Optional[Exception]:
        """Process a single parsed message and delete it from the queue unless it may succeed in a later run.

        Messages that are not object notifications, or whose object does not exist, are deleted with a warning.
        A message whose object cannot be fetched or processed is kept for a later run, unless skip_on_error is set
        and the error does not come from AWS or the connection to it (e.g. a file that cannot be parsed): then the
        message is skipped and deleted.

        Parameters
        ----------
        message : dict
            A message parsed by the message processor.

        Returns
        -------
        Exception or None
            The error that kept the message in the queue, or None if the message was processed or deleted.
        """
        message_id = message.get('message_id')
        if 'route' not in message:
            raw_message = message.get('raw_message')
            if isinstance(raw_message, dict) and raw_message.get('Event') == 's3:TestEvent':
                aws_tools.debug(f'+++ Deleting S3 test event message {message_id} from the SQS queue', 1)
            else:
                print(f'WARNING: Deleting message {message_id} from the SQS queue: '
                      f'it does not contain an object notification: {raw_message!r:.200}')
                aws_tools.debug(f'+++ Deleted message content: {raw_message!r}', 2)
            self.delete_message(message)
            return None

        route = message['route']
        try:
            self.bucket_handler.process_file(route)
        except Exception as error:
            if s3_log_handler.is_object_unavailable(error):
                print(f'WARNING: Deleting message {message_id} from the SQS queue: object {route["log_path"]!r} '
                      f'in bucket {route["bucket_path"]!r} is not available: {error!r}')
                self.delete_message(message)
                return None
            if not self.skip_on_error or s3_log_handler.is_retryable_error(error):
                aws_tools.error(f'Could not process object {route["log_path"]!r} in bucket {route["bucket_path"]!r}, '
                                f'keeping message {message_id} in the SQS queue for a later run: {error!r}')
                return error
            aws_tools.error(f'Skipping message {message_id}: could not process object {route["log_path"]!r} '
                            f'in bucket {route["bucket_path"]!r}: {error!r}')
        self.delete_message(message)
        return None

    def sync_events(self) -> None:
        """Get messages from the SQS queue, parse their events, send them to AnalysisD, and delete them from the queue.

        When a message was kept in the queue after an error, exit with an error code once the rest of the queue has
        been processed, or as soon as the requests for the objects of MAX_CONSECUTIVE_UNANSWERED_REQUESTS messages in a
        row got no answer from AWS. A message that is not an object notification does not count, as it does not reach
        AWS.
        """
        kept_ids = set()
        kept = consecutive_unanswered = 0
        messages = self.get_messages()
        while messages:
            # A kept message comes back in the same run when the visibility timeout is shorter than the run
            new_messages = [message for message in messages if message.get('message_id') not in kept_ids]
            if not new_messages:
                break
            for message in new_messages:
                error = self.process_message(message)
                if error is not None:
                    kept_ids.add(message.get('message_id'))
                    kept += 1
                if error is not None and s3_log_handler.is_unanswered_error(error):
                    consecutive_unanswered += 1
                    if consecutive_unanswered == MAX_CONSECUTIVE_UNANSWERED_REQUESTS:
                        aws_tools.error(f'Stopping after the requests for the objects of {consecutive_unanswered} '
                                        f'messages in a row got no answer from AWS')
                        sys.exit(7)
                elif 'route' in message:
                    consecutive_unanswered = 0
            messages = self.get_messages()
        if kept:
            aws_tools.error(f'{kept} message(s) were kept in the SQS queue for a later run')
            sys.exit(7)
