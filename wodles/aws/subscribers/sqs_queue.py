# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import botocore
import sys
from os import path

sys.path.append(path.join(path.dirname(path.realpath(__file__)), '..', 'subscribers'))
import s3_log_handler
import sqs_message_processor

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))
import wazuh_integration

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))
import aws_tools


class AWSSQSQueue(wazuh_integration.WazuhIntegration):
    """Class for getting AWS SQS Queue notifications.

    Attributes
    ----------
    name: str
        Name of the SQS Queue.
    iam_role_arn : str
        IAM Role.
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
        wazuh_integration.WazuhIntegration.__init__(self,
                                                    iam_role_arn=iam_role_arn,
                                                    profile=profile, external_id=external_id, service_name='sqs',
                                                    sts_endpoint=sts_endpoint, skip_on_error=skip_on_error,
                                                    iam_role_duration=iam_role_duration,
                                                    **kwargs)
        self.sts_client = self.get_sts_client(None, None, profile)
        self.account_id = self.sts_client.get_caller_identity().get('Account')
        self.sqs_url = self._get_sqs_url()
        self.iam_role_arn = iam_role_arn
        self.iam_role_duration = iam_role_duration
        self.bucket_handler = bucket_handler(external_id=external_id,
                                             iam_role_arn=self.iam_role_arn,
                                             iam_role_duration=self.iam_role_duration,
                                             service_endpoint=service_endpoint,
                                             sts_endpoint=sts_endpoint,
                                             skip_on_error=skip_on_error,
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
            url = self.client.get_queue_url(QueueName=self.sqs_name,
                                            QueueOwnerAWSAccountId=self.account_id)['QueueUrl']
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
            aws_tools.debug(f'ERROR: Error deleting message from SQS: {e}', 1)
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
            aws_tools.debug(f'ERROR: Error receiving message from SQS: {e}', 1)
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

    def sync_events(self) -> None:
        """Get messages from the SQS queue, parse their events, send them to AnalysisD, and delete them from the queue.
        """
        messages = self.get_messages()
        while messages:
            for message in messages:
                try:
                    self.bucket_handler.process_file(message["route"])
                except KeyError:
                    message_without_handle = {k: v for k, v in message.items() if k != 'handle'}
                    aws_tools.debug(f"Processed message {message_without_handle} does not contain the expected format, "
                                    f"omitting message.", 2)
                    continue
                self.delete_message(message)
            messages = self.get_messages()
