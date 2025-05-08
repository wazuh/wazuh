# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import csv
import io
import json
import re
import sys

from os import path
from typing import List
from urllib.parse import unquote

try:
    import pyarrow.parquet as pq
except ImportError:
    print('ERROR: pyarrow module is required.')
    sys.exit(10)

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))
import aws_tools

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))
import wazuh_integration


class AWSS3LogHandler:
    def obtain_logs(self, bucket: str, log_path: str) -> list:
        """Fetch a file from a bucket and obtain a list of events from it.

        Parameters
        ----------
        bucket : str
            Bucket to get the file from.
        log_path : str
            Relative path of the file inside the bucket.

        Returns
        -------
        list[dict]
            List of extracted events to send to Wazuh.
        """
        raise NotImplementedError

    def process_file(self, message_body: dict) -> None:
        """Parse an SQS message body, obtain the events associated, and send them to Analysisd.

        Parameters
        ----------
        message_body : dict
            An SQS message received from the queue.
        """
        raise NotImplementedError


class AWSSubscriberBucket(wazuh_integration.WazuhIntegration, AWSS3LogHandler):
    """Class for processing events from AWS S3 buckets.

    Attributes
    ----------
    profile : str
        AWS profile.
    iam_role_arn : str
        IAM Role.
    """
    def __init__(self, service_endpoint: str = None, sts_endpoint: str = None, profile: str = None, **kwargs):
        wazuh_integration.WazuhIntegration.__init__(self, access_key=None,
                                                    secret_key=None,
                                                    profile=profile,
                                                    service_name='s3',
                                                    service_endpoint=service_endpoint,
                                                    sts_endpoint=sts_endpoint,
                                                    **kwargs)

    @staticmethod
    def _process_jsonl(file: io.TextIOWrapper) -> List[dict]:
        """Process JSON objects present in a JSONL file.

        Parameters
        ----------
        file : io.TextIOWrapper
            File object.
        Returns
        -------
        list[dict]
            List of events from the file.
        """
        json_list = list(file)
        result = []
        for json_item in json_list:
            x = json.loads(json_item)
            result.append(dict(x))
        return result

    @staticmethod
    def _json_event_generator(data: str):
        """Obtain events from string of JSON objects.

        Parameters
        ----------
        data : str
            String of JSON data.
        Yields
        -------
        dict
            Extracted JSON event.
        """
        decoder = json.JSONDecoder()
        while data:
            json_data, json_index = decoder.raw_decode(data)
            data = data[json_index:].lstrip()
            yield json_data

    @staticmethod
    def _remove_none_fields(event: dict):
        """Remove None fields from events.

        Parameters
        ----------
        event : dict
            Event to send to Analysisd.
        """
        for key, value in list(event.items()):
            if isinstance(value, dict):
                AWSSubscriberBucket._remove_none_fields(event[key])
            elif value is None:
                del event[key]

    @staticmethod
    def is_csv(file: io.TextIOWrapper) -> bool:
        """Determine if the given file is a CSV according to its headers.

        Parameters
        ----------
        file : io.TextIOWrapper
            File object.

        Returns
        -------
        bool
            Whether a file contains csv data or not.
        """
        # Read the first line (header row) from the file
        header_row = file.readline().strip()
        file.seek(0)
        # Define the regex pattern for invalid CSV header characters
        not_header_pattern = re.compile(r'.*\d+.*')
        # Check if the header row matches the regex pattern
        return not bool(not_header_pattern.match(header_row))

    def obtain_logs(self, bucket: str, log_path: str) -> List[dict]:
        """Fetch a file from a bucket and obtain a list of events from it.

        Parameters
        ----------
        bucket : str
            Bucket to get the file from.
        log_path : str
            Relative path of the file inside the bucket.

        Returns
        -------
        list[dict]
            List of extracted events to send to Wazuh.
        """

        with self.decompress_file(bucket, log_key=log_path) as f:
            try:
                if log_path.endswith('.jsonl.gz'):
                    return self._process_jsonl(file=f)

                return [dict(event.get('detail', event), source="custom")
                        for event in self._json_event_generator(f.read())]

            except (json.JSONDecodeError, AttributeError):
                aws_tools.debug("+++ Log file does not contain JSON objects. Trying with other formats.", 2)
                f.seek(0)
                if self.is_csv(f):
                    aws_tools.debug("+++ Log file is CSV formatted.", 2)
                    try:
                        dialect = csv.Sniffer().sniff(f.readline())
                        f.seek(0)
                        reader = csv.DictReader(f, dialect=dialect)
                        return [dict({k: v for k, v in row.items() if v is not None},
                                     source='custom') for row in reader]
                    except MemoryError:
                        aws_tools.error(f"The size of the {log_path} file exceeds the available memory.")
                        sys.exit(9)
                else:
                    aws_tools.debug("+++ Data in the file does not seem to be CSV. Trying with plain text.", 2)
                    try:
                        return [dict(full_log=event, source="custom") for event in f.read().splitlines()]
                    except OSError:
                        aws_tools.error(f"Data in the file does not seem to be plain text either.")
                        sys.exit(9)

    def process_file(self, message_body: dict) -> None:
        """Parse an SQS message, obtain the events associated, and send them to Analysisd.

        Parameters
        ----------
        message_body : dict
            An SQS message received from the queue.
        """

        log_path = unquote(message_body['log_path'])
        bucket_path = message_body['bucket_path']

        formatted_logs = self.obtain_logs(bucket=bucket_path, log_path=log_path)
        for log in formatted_logs:
            msg = {
                'integration': 'aws',
                'aws': {
                    'log_info': {
                        'log_file': log_path,
                        's3bucket': bucket_path
                    }
                }
            }
            self._remove_none_fields(log)
            if 'full_log' in log:
                # The processed logs origin is a plain text log file
                if re.match(self.discard_regex, log['full_log']):
                    aws_tools.debug(f'+++ The "{self.discard_regex.pattern}" regex found a match. '
                                    f'The event will be skipped.', 2)
                    continue
                else:
                    print(f'WARNING: The "{self.discard_regex.pattern}" regex did not find a match. '
                          f'The event will be processed.')
            elif self.event_should_be_skipped(log):
                aws_tools.debug(f'+++ The "{self.discard_regex.pattern}" regex found a match '
                                f'in the "{self.discard_field}" '
                      f'field. The event will be skipped.', 2)
                continue
            else:
                aws_tools.debug(
                                f'+++ The "{self.discard_regex.pattern}" regex did not find a match in the '
                                f'"{self.discard_field}" field. The event will be processed.', 3)

            msg['aws'].update(log)
            self.send_msg(msg)


class AWSSLSubscriberBucket(wazuh_integration.WazuhIntegration, AWSS3LogHandler):
    """Class for processing AWS Security Lake events from S3.

    Attributes
    ----------
    access_key : str
        AWS access key id.
    secret_key : str
        AWS secret access key.
    profile : str
        AWS profile.
    iam_role_arn : str
        IAM Role.
    """

    def __init__(self, service_endpoint: str = None, sts_endpoint: str = None, profile: str = None, **kwargs):
        wazuh_integration.WazuhIntegration.__init__(self, access_key=None,
                                                    secret_key=None,
                                                    profile=profile,
                                                    service_name='s3',
                                                    service_endpoint=service_endpoint,
                                                    sts_endpoint=sts_endpoint,
                                                    **kwargs)

    def obtain_logs(self, bucket: str, log_path: str) -> list:
        """Fetch a parquet file from a bucket and obtain a list of the events it contains.

        Parameters
        ----------
        bucket : str
            Bucket to get the file from.
        log_path : str
            Relative path of the file inside the bucket.

        Returns
        -------
        events : list
            Events contained inside the parquet file.
        """
        aws_tools.debug(f'Processing file {log_path} in {bucket}', 2)
        events = []
        try:
            raw_parquet = io.BytesIO(self.client.get_object(Bucket=bucket, Key=log_path)['Body'].read())
        except Exception as e:
            aws_tools.debug(f'Could not get the parquet file {log_path} in {bucket}: {e}', 1)
            sys.exit(21)
        pfile = pq.ParquetFile(raw_parquet)
        for i in pfile.iter_batches():
            for j in i.to_pylist():
                events.append(json.dumps(j))
        aws_tools.debug(f'Found {len(events)} events in file {log_path}', 2)
        return events

    def process_file(self, message_body: dict) -> None:
        """Parse an SQS message, obtain the events associated, and send them to Analysisd.

        Parameters
        ----------
        message_body : dict
            An SQS message received from the queue.
        """
        events_in_file = self.obtain_logs(bucket=message_body['bucket_path'],
                                          log_path=message_body['log_path'])
        for event in events_in_file:
            self.send_msg(event, dump_json=False)
        aws_tools.debug(f'{len(events_in_file)} events sent to Analysisd', 2)


class AWSSecurityHubSubscriberBucket(AWSSubscriberBucket):
    """Class for processing events from AWS S3 buckets containing Security Hub related logs."""

    @staticmethod
    def _add_event_type_fields(details: dict, event: dict):
        """Add the corresponding fields into the event if the details contain them.

        Parameters
        ----------
        details : dict
            Source dictionary containing the events from the log file.
        event : dict
            Destination dictionary to be added to the event sent to Wazuh.
        """
        fields = ['findings', 'actionName', 'actionDescription', 'actionDescription', 'insightName', 'insightArn',
                  'resultType', 'insightResults']

        def _action(source: dict, dest: dict, field_name: str) -> None:
            if field_name == 'findings':
                dest.setdefault('finding', source[field_name][0])
            else:
                dest.setdefault(field_name, source[field_name])

        for key in fields:
            if key in details:
                _action(details, event, key)

    def obtain_logs(self, bucket: str, log_path: str) -> List[dict]:
        """Fetch a file from a bucket and obtain a list of events from it.

        Parameters
        ----------
        bucket : str
            Bucket to get the file from.
        log_path : str
            Relative path of the file inside the bucket.

        Returns
        -------
        List[dict]
            List of extracted events to send to Wazuh.
        """
        with self.decompress_file(bucket, log_key=log_path) as f:
            try:
                extracted_events = []
                for event in self._json_event_generator(f.read()):
                    event_detail = event['detail']
                    base_event = dict(source="securityhub", detail_type=event["detail-type"])
                    self._add_event_type_fields(event_detail, base_event)
                    extracted_events.append(base_event)

                return extracted_events

            except (json.JSONDecodeError, AttributeError):
                aws_tools.error(f"Data in the file does not contain JSON objects.")
                sys.exit(9)

    def process_file(self, message_body: dict) -> None:
        """Parse an SQS message, obtain the events associated, and send them to Analysisd.

        Parameters
        ----------
        message_body : dict
            An SQS message received from the queue.
        """
        log_path = message_body['log_path']
        bucket_path = message_body['bucket_path']

        formatted_logs = self.obtain_logs(bucket=bucket_path, log_path=log_path)
        for log in formatted_logs:
            msg = {
                'integration': 'aws',
                'aws': {
                    'log_info': {
                        'log_file': log_path,
                        's3bucket': bucket_path
                    }
                }
            }
            self._remove_none_fields(log)
            if self.event_should_be_skipped(log):
                aws_tools.debug(f'+++ The "{self.discard_regex.pattern}" regex found a match '
                                f'in the "{self.discard_field}" field. The event will be skipped.', 2)
                continue
            else:
                aws_tools.debug(
                    f'+++ The "{self.discard_regex.pattern}" regex did not find a match in the '
                    f'"{self.discard_field}" field. The event will be processed.', 3)

            msg['aws'].update(log)
            self.send_msg(msg)
