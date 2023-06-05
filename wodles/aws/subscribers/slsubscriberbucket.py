import sys
from os import path
import io
import json

try:
    import pyarrow.parquet as pq
except ImportError:
    print('ERROR: pyarrow module is required.')
    sys.exit(10)

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))
import aws_tools

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))
import wazuh_integration


class AWSSLSubscriberBucket(wazuh_integration.WazuhIntegration):
    """
    Class for processing AWS Security Lake events from S3.
    """

    def __init__(self, iam_role_arn: str = None, iam_role_duration: str = None,
                 service_endpoint: str = None, sts_endpoint: str = None, **kwargs):
        wazuh_integration.WazuhIntegration.__init__(self, access_key=None, secret_key=None,
                                                    iam_role_arn=iam_role_arn, iam_role_duration=iam_role_duration,
                                                    profile=None,
                                                    service_name='s3',
                                                    service_endpoint=service_endpoint, sts_endpoint=sts_endpoint,
                                                    **kwargs)

    def obtain_information_from_parquet(self, bucket_path: str, parquet_path: str) -> list:
        """Fetch a parquet file from a bucket and obtain a list of the events it contains.

        Parameters
        ----------
        bucket_path : str
            Path of the bucket to get the parquet file from.
        parquet_path : str
            Relative path of the parquet file inside the bucket.

        Returns
        -------
        events : list
            Events contained inside the parquet file.
        """
        aws_tools.debug(f'Processing file {parquet_path} in {bucket_path}', 2)
        events = []
        try:
            raw_parquet = io.BytesIO(self.client.get_object(Bucket=bucket_path, Key=parquet_path)['Body'].read())
        except Exception as e:
            aws_tools.debug(f'Could not get the parquet file {parquet_path} in {bucket_path}: {e}', 1)
            sys.exit(21)
        pfile = pq.ParquetFile(raw_parquet)
        for i in pfile.iter_batches():
            for j in i.to_pylist():
                events.append(json.dumps(j))
        aws_tools.debug(f'Found {len(events)} events in file {parquet_path}', 2)
        return events

    def process_file(self, message: dict) -> None:
        """Parse an SQS message, obtain the events associated, and send them to Analysisd.

        Parameters
        ----------
        message : dict
            An SQS message received from the queue.
        """
        events_in_file = self.obtain_information_from_parquet(bucket_path=message['bucket_path'],
                                                              parquet_path=message['parquet_path'])
        for event in events_in_file:
            self.send_msg(event, dump_json=False)
        aws_tools.debug(f'{len(events_in_file)} events sent to Analysisd', 2)
