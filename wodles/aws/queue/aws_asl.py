#!/usr/bin/env python3
import argparse
import boto3
import json
import logging
import os
import socket
import sys
import time
from aws.aws_s3 import WazuhIntegration

logger_name = ':asl_poc:'
logging_date_format = '%Y/%m/%d %I:%M:%S'
log_levels = {0: logging.WARNING,
              1: logging.INFO,
              2: logging.DEBUG}

# logging.basicConfig(filename="aws_asl.log", level=logging.DEBUG)
logger = logging.getLogger(logger_name)
logging_format = logging.Formatter(fmt='%(asctime)s %(name)s - %(levelname)s - %(message)s',
                                   datefmt=logging_date_format)

stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setFormatter(logging_format)

logger.addHandler(stdout_handler)
logger.setLevel(log_levels.get(2, logging.DEBUG))

try:
    import awswrangler as wr
except ImportError:
    logger.error('awswrangler module is required.')
    sys.exit(2)


class AWSSQSQueue(WazuhIntegration):

    def __init__(self, **kwargs):
        self.sqs_queue = kwargs["sqs_queue"]
        self.sqs_client = None
        self.get_sqs_client()
        if kwargs["purge"]:
            self.purge()

    def delete_message(self, message_handle):
        self.sqs_client.delete_message(QueueUrl=self.sqs_queue, ReceiptHandle=message_handle)

    def delete_messages(self, message_handles):
        for message_handle in message_handles:
            self.selete_message(message_handle)

    def __fetch_message(self):
        try:
            logger.debug(f'Retrieving messages from: {self.sqs_queue}')
            msg = self.sqs_client.receive_message(QueueUrl=self.sqs_queue, AttributeNames=['All'], MaxNumberOfMessages=10)
            return msg
        except Exception as e:
            logger.error("Error receiving message from SQS: {}".format(e))
            sys.exit(4)

    def get_messages(self):
        messages = []
        sqs_message = self.__fetch_message()
        sqs_messages = sqs_message.get('Messages', [])
        for mesg in sqs_messages:
            body = mesg['Body']
            msg_handle = mesg["ReceiptHandle"]
            message = json.loads(body)
            parquet_path = message["detail"]["object"]["key"]
            bucket_path = message["detail"]["bucket"]["name"]
            path = "s3://" + bucket_path + "/" + parquet_path
            messages.append({"parquet_location": path, "handle": msg_handle})
        return messages

    def get_sqs_client(self, access_key=None, secret_key=None, region=None, profile_name=None):
        conn_args = {}
        conn_args['region_name'] = region

        if access_key is not None and secret_key is not None:
            conn_args['aws_access_key_id'] = access_key
            conn_args['aws_secret_access_key'] = secret_key
        elif profile_name is not None:
            conn_args['profile_name'] = profile_name

        boto_session = boto3.Session(**conn_args)

        try:
            self.sqs_client = boto_session.client(service_name='sqs')
        except Exception as e:
            logger.error("Error getting SQS client. Check your credentials file: {}".format(e))
            sys.exit(3)

    def sync_events(self):
        messages = self.get_messages()
        #WazuhIntegration()
        self.delete_messages(messages)

    def purge(self): #Check if necessary
        logger.info('Purging SQS queue, please wait a minute..:')
        self.sqs_client.purge_queue(QueueUrl=self.sqs_queue)
        time.sleep(60)  # The message deletion process takes up to 60 seconds.
        logger.debug('SQS queue purged succesfully')

