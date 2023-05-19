import sys
from os import path
import json
import botocore
from slsubscriberbucket import AWSSLSubscriberBucket

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))
import wazuh_integration

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))
import aws_tools


class AWSSQSQueue(wazuh_integration.WazuhIntegration):
    """
    Class for getting AWS SQS Queue notifications.

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
    """

    def __init__(self, name: str, iam_role_arn: str, access_key: str = None, secret_key: str = None,
                 external_id: str = None, sts_endpoint=None, service_endpoint=None, **kwargs):
        self.sqs_name = name
        wazuh_integration.WazuhIntegration.__init__(self, access_key=access_key, secret_key=secret_key,
                                                    iam_role_arn=iam_role_arn,
                                                    aws_profile=None, external_id=external_id, service_name='sqs',
                                                    sts_endpoint=sts_endpoint,
                                                    **kwargs)
        self.sts_client = self.get_sts_client(access_key, secret_key)
        self.account_id = self.sts_client.get_caller_identity().get('Account')
        self.sqs_url = self._get_sqs_url()
        self.iam_role_arn = iam_role_arn
        self.asl_bucket_handler = AWSSLSubscriberBucket(external_id=external_id,
                                                        iam_role_arn=self.iam_role_arn,
                                                        service_endpoint=service_endpoint,
                                                        sts_endpoint=sts_endpoint)

    def _get_sqs_url(self) -> str:
        """Get the URL of the AWS SQS queue

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
            print('ERROR: Queue does not exist, verify the given name')
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
            aws_tools.debug(f'Message deleted from: {self.sqs_name}', 2)
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
        messages = []
        sqs_raw_messages = self.fetch_messages()
        sqs_messages = sqs_raw_messages.get('Messages', [])
        for mesg in sqs_messages:
            body = mesg['Body']
            msg_handle = mesg["ReceiptHandle"]
            message = json.loads(body)
            parquet_path = message["detail"]["object"]["key"]
            bucket_path = message["detail"]["bucket"]["name"]
            messages.append({"parquet_path": parquet_path, "bucket_path": bucket_path,
                             "handle": msg_handle})
        return messages

    def sync_events(self) -> None:
        """
        Get messages from the SQS queue, parse their events, send them to AnalysisD, and delete them from the queue.
        """
        messages = self.get_messages()
        while messages:
            for message in messages:
                self.asl_bucket_handler.process_file(message)
                self.delete_message(message)
            messages = self.get_messages()
