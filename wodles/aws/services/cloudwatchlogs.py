# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import re
import sqlite3
import sys

import botocore
from datetime import datetime
from datetime import timezone
from os import path

sys.path.append(path.dirname(path.realpath(__file__)))
import aws_service

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))
import aws_tools


class AWSCloudWatchLogs(aws_service.AWSService):
    """
    Class for getting AWS Cloudwatch logs

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
    only_logs_after : str
        Date after which obtain logs.
    account_alias: str
        AWS account alias.
    region : str
        Region where the logs are located.
    aws_log_groups : str
        String containing a list of log group names separated by a comma.
    remove_log_streams : bool
        Indicate if log streams should be removed after being fetched.
    db_table_name : str
        Name of the table to be created on aws_service.db.
    only_logs_after_millis : int
        only_logs_after expressed as the number of milliseconds after Jan 1, 1970 00:00:00 UTC.
    reparse : bool
        Whether to parse already parsed logs or not.
    log_group_list : list of str
        List of each log group to be parsed.
    sql_cloudwatch_create_table : str
        Query for the creation of the table.
    sql_cloudwatch_insert : str
        Query to insert the token for a given log stream.
    sql_cloudwatch_update : str
        Query for updating the token, start_time and end_time values.
    sql_cloudwatch_select : str
        Query to obtain the token, start_time and end_time values.
    sql_cloudwatch_select_logstreams : str
        Query to get all logstreams in the DB.
    sql_cloudwatch_purge : str
        Query to delete a row from the DB.
    """

    def __init__(self, reparse, access_key, secret_key, profile,
                 iam_role_arn, only_logs_after, account_alias, region, aws_log_groups,
                 remove_log_streams, discard_field=None, discard_regex=None, sts_endpoint=None, service_endpoint=None,
                 iam_role_duration=None, **kwargs):

        self.sql_cloudwatch_create_table = """
            CREATE TABLE {table_name} (
                    aws_region 'text' NOT NULL,
                    aws_log_group 'text' NOT NULL,
                    aws_log_stream 'text' NOT NULL,
                    next_token 'text',
                    start_time 'integer',
                    end_time 'integer',
                    PRIMARY KEY (aws_region, aws_log_group, aws_log_stream));"""

        self.sql_cloudwatch_insert = """
            INSERT INTO {table_name} (
                aws_region,
                aws_log_group,
                aws_log_stream,
                next_token,
                start_time,
                end_time)
            VALUES
                (:aws_region,
                :aws_log_group,
                :aws_log_stream,
                :next_token,
                :start_time,
                :end_time);"""

        self.sql_cloudwatch_update = """
            UPDATE
                {table_name}
            SET
                next_token=:next_token,
                start_time=:start_time,
                end_time=:end_time
            WHERE
                aws_region=:aws_region AND
                aws_log_group=:aws_log_group AND
                aws_log_stream=:aws_log_stream;"""

        self.sql_cloudwatch_select = """
            SELECT
                next_token,
                start_time,
                end_time
            FROM
                {table_name}
            WHERE
                aws_region=:aws_region AND
                aws_log_group=:aws_log_group AND
                aws_log_stream=:aws_log_stream"""
        self.sql_cloudwatch_select_logstreams = """
            SELECT
                aws_log_stream
            FROM
                {table_name}
            WHERE
                aws_region=:aws_region AND
                aws_log_group=:aws_log_group
            ORDER BY
                aws_log_stream;"""
        self.sql_cloudwatch_purge = """
            DELETE FROM {table_name}
            WHERE
                aws_region=:aws_region AND
                aws_log_group=:aws_log_group AND
                aws_log_stream=:aws_log_stream;"""

        aws_service.AWSService.__init__(self, db_table_name='cloudwatch_logs', service_name='cloudwatchlogs',
                                        reparse=reparse, access_key=access_key, secret_key=secret_key,
                                        profile=profile, iam_role_arn=iam_role_arn, only_logs_after=only_logs_after,
                                        account_alias=account_alias, region=region, discard_field=discard_field,
                                        discard_regex=discard_regex, iam_role_duration=iam_role_duration,
                                        sts_endpoint=sts_endpoint, service_endpoint=service_endpoint)
        self.log_group_list = [group for group in aws_log_groups.split(",") if group != ""] if aws_log_groups else []
        self.remove_log_streams = remove_log_streams
        self.only_logs_after_millis = int(datetime.strptime(only_logs_after, '%Y%m%d').replace(
            tzinfo=timezone.utc).timestamp() * 1000) if only_logs_after else None
        self.default_date_millis = int(self.default_date.timestamp() * 1000)
        aws_tools.debug("only logs: {}".format(self.only_logs_after_millis), 1)

    def get_alerts(self):
        """Iterate over all the log streams for each log group provided by the user in the given region to get their
        logs and send them to analysisd, which will raise alerts if applicable.

        It will avoid getting duplicate events by using the token, start_time and end_time variables stored in the DB.
        Logs with a timestamp lesser that start_time and greater than end_time will be fetched using the
        `get_alerts_within_range` function.

        The log streams will be removed after fetching them if `remove_log_streams` value is True.

        The database will be purged to remove unnecessary records at the end of each log group iteration.
        """
        self.init_db(self.sql_cloudwatch_create_table.format(table_name=self.db_table_name))

        if self.reparse:
            aws_tools.debug('Reparse mode ON', 1)

        try:
            for log_group in self.log_group_list:
                for log_stream in self.get_log_streams(log_group=log_group):
                    aws_tools.debug(
                        'Getting data from DB for log stream "{}" in log group "{}"'.format(log_stream, log_group), 1)
                    db_values = self.get_data_from_db(log_group=log_group, log_stream=log_stream)
                    aws_tools.debug('Token: "{}", start_time: "{}", '
                                    'end_time: "{}"'.format(db_values['token'] if db_values else None,
                                                            db_values['start_time'] if db_values else None,
                                                            db_values['end_time'] if db_values else None), 2)
                    result_before = None
                    start_time = self.only_logs_after_millis if self.only_logs_after_millis else \
                        self.default_date_millis
                    end_time = None
                    token = None

                    if db_values:
                        if self.reparse:
                            result_before = self.get_alerts_within_range(log_group=log_group, log_stream=log_stream,
                                                                         token=None, start_time=start_time,
                                                                         end_time=None)

                        elif db_values['start_time'] and db_values['start_time'] > start_time:
                            result_before = self.get_alerts_within_range(log_group=log_group, log_stream=log_stream,
                                                                         token=None, start_time=start_time,
                                                                         end_time=db_values['start_time'])

                        if db_values['end_time']:
                            if not self.only_logs_after_millis or db_values['end_time'] > self.only_logs_after_millis:
                                start_time = db_values['end_time'] + 1
                                token = db_values['token']

                    result_after = self.get_alerts_within_range(log_group=log_group, log_stream=log_stream, token=token,
                                                                start_time=start_time, end_time=end_time)

                    db_values = self.update_values(values=db_values, result_before=result_before,
                                                   result_after=result_after)

                    self.save_data_db(log_group=log_group, log_stream=log_stream, values=db_values)

                    if self.remove_log_streams:
                        self.remove_aws_log_stream(log_group=log_group, log_stream=log_stream)

                self.purge_db(log_group=log_group)
        finally:
            aws_tools.debug("committing changes and closing the DB", 1)
            self.close_db()

    def remove_aws_log_stream(self, log_group, log_stream):
        """Remove a log stream from a log group in AWS Cloudwatch Logs.

        Parameters
        ----------
        log_group : str
            Name of the group where the log stream is stored
        log_stream : str
            Name of the log stream to be removed
        """
        try:
            aws_tools.debug('Removing log stream "{}" from log group "{}"'.format(log_group, log_stream), 1)
            self.client.delete_log_stream(logGroupName=log_group, logStreamName=log_stream)
        except botocore.exceptions.ClientError as err:
            aws_tools.error(f'The "remove_aws_log_stream" request failed: {err}')
            sys.exit(16)
        except Exception:
            aws_tools.debug('ERROR: Error trying to remove "{}" log stream from "{}" log group.'.format(log_stream, log_group),
                            0)

    def get_alerts_within_range(self, log_group, log_stream, token, start_time, end_time):
        """Get all the logs from a log stream with a timestamp between the range of the provided start and end times and
        send them to Analysisd.

        It will fetch every log from the given log stream using boto3 `get_log_events` until it returns an empty
        response.

        Parameters
        ----------
        log_group : str
            Name of the log group where the log stream is stored
        log_stream : str
            Name of the log stream to get its logs
        token : str or None
            Token to the next set of logs. Obtained from a previous call and stored in DB.
        start_time : int
            The start of the time range, expressed as the number of milliseconds after Jan 1, 1970 00:00:00 UTC.
            Logs with a timestamp equal to this time or later will be fetched.
        end_time : int or None
            The end of the time range, expressed as the number of milliseconds after Jan 1, 1970 00:00:00 UTC.
            Events with a timestamp equal to or later than this time won't be fetched.

        Returns
        -------
        A dict containing the Token for the next set of logs, the timestamp of the first fetched log and the timestamp
        of the latest one.
        """
        sent_events = 0
        response = None
        min_start_time = start_time
        max_end_time = end_time if end_time is not None else start_time

        parameters = {'logGroupName': log_group,
                      'logStreamName': log_stream,
                      'nextToken': token,
                      'startTime': start_time,
                      'endTime': end_time,
                      'startFromHead': True}

        # Request event logs until CloudWatch returns an empty list for the log stream
        while response is None or response['events'] != list():
            aws_tools.debug(
                'Getting CloudWatch logs from log stream "{}" in log group "{}" using token "{}", start_time '
                '"{}" and end_time "{}"'.format(log_stream, log_group, token, start_time, end_time), 1)

            # Try to get CloudWatch Log events until the request succeeds or the allowed number of attempts is reached
            try:
                response = self.client.get_log_events(
                    **{param: value for param, value in parameters.items() if value is not None})

            except botocore.exceptions.EndpointConnectionError:
                aws_tools.debug(f'WARNING: The "get_log_events" request was denied because the endpoint URL was not '
                                f'available. Attempting again.', 1)
                continue  # Needed to make the get_log_events request again
            except botocore.exceptions.ClientError as err:
                aws_tools.error(f'The "get_log_events" request failed: {err}')
                sys.exit(16)

            # Update token
            token = response['nextForwardToken']
            parameters['nextToken'] = token

            # Send events to Analysisd
            if response['events']:
                aws_tools.debug('+++ Sending events to Analysisd...', 1)
                for event in response['events']:
                    event_msg = event['message']
                    json_event = None
                    try:
                        json_event = json.loads(event_msg)
                        if self.event_should_be_skipped(json_event):
                            aws_tools.debug(
                                f'+++ The "{self.discard_regex.pattern}" regex found a match in the "{self.discard_field}" '
                                f'field. The event will be skipped.', 2)
                            continue
                        else:
                            aws_tools.debug(
                                f'+++ The "{self.discard_regex.pattern}" regex did not find a match in the '
                                f'"{self.discard_field}" field. The event will be processed.', 3)
                    except ValueError:
                        # event_msg is not a JSON object, check if discard_regex.pattern matches the given string
                        aws_tools.debug(f"+++ Retrieved log event is not a JSON object.", 3)
                        if re.match(self.discard_regex, event_msg):
                            aws_tools.debug(
                                f'+++ The "{self.discard_regex.pattern}" regex found a match. The event will be skipped.',
                                2)
                            continue
                        else:
                            aws_tools.debug(f'+++ The "{self.discard_regex.pattern}" regex did not find a match. '
                                  f'The event will be processed.', 3)
                    aws_tools.debug('The message is "{}"'.format(event_msg), 2)
                    aws_tools.debug('The message\'s timestamp is {}'.format(event["timestamp"]), 3)
                    self.send_msg(dict({'integration': 'aws', 'source': 'cloudwatch', 'log_group': log_group},
                                       **json_event if json_event else {'message': event_msg}), dump_json=False)
                    sent_events += 1

                    if min_start_time is None:
                        min_start_time = event['timestamp']
                    elif event['timestamp'] < min_start_time:
                        min_start_time = event['timestamp']

                    if max_end_time is None:
                        max_end_time = event['timestamp']
                    elif event['timestamp'] > max_end_time:
                        max_end_time = event['timestamp']

            if sent_events:
                aws_tools.debug(f"+++ Sent {sent_events} events to Analysisd", 1)
                sent_events = 0
            else:
                aws_tools.debug(f'+++ There are no new events in the "{log_group}" group', 1)

        return {'token': token, 'start_time': min_start_time, 'end_time': max_end_time}

    def get_data_from_db(self, log_group, log_stream):
        """Get the token, start time and end time of a log stream stored in DB.

        Parameters
        ----------
        log_group : str
            Name of the log group
        log_stream : str
            Name of the log stream

        Returns
        -------
        A dict containing the token, start_time and end_time of the log stream. None if no data were found in the DB.
        """
        self.db_cursor.execute(self.sql_cloudwatch_select.format(table_name=self.db_table_name), {
            'aws_region': self.region,
            'aws_log_group': log_group,
            'aws_log_stream': log_stream})
        query_result = self.db_cursor.fetchone()
        if query_result:
            return {'token': None if query_result[0] == "None" else query_result[0],
                    'start_time': None if query_result[1] == "None" else query_result[1],
                    'end_time': None if query_result[2] == "None" else query_result[2]}

    def update_values(self, values, result_after, result_before):
        """Update the values for token, start_time and end_time using the results of previous 'get_alerts_within_range'
        executions.

        Parameters
        ----------
        values : dict
            A dict containing the token, start_time and end_time values to be updated.
        result_after : dict
            A dict containing the resulting token, start_time and end_time values of a 'get_alerts_within_range'
            execution.
        result_before : dict
            A dict containing the resulting token, start_time and end_time values of a 'get_alerts_within_range'
            execution.

        Returns
        -------
        A dict containing the last token, minimal start_time and maximum end_value of the provided parameters.
        """
        min_start_time = result_before['start_time'] if result_before else None
        max_end_time = result_before['end_time'] if result_before else None

        if result_after is not None:
            if min_start_time is None:
                min_start_time = result_after['start_time']
            # It's necessary to ensure that we're not comparing None with int
            elif result_after['start_time'] is not None:
                min_start_time = result_after['start_time'] if result_after[
                                                                   'start_time'] < min_start_time else min_start_time

            if max_end_time is None:
                max_end_time = result_after['end_time']
            elif result_after['end_time'] is not None:
                max_end_time = result_after['end_time'] if result_after['end_time'] > max_end_time else max_end_time

        token = result_before['token'] if result_before is not None else None
        token = result_after['token'] if result_after is not None else token

        if values is None:
            return {'token': token, 'start_time': min_start_time, 'end_time': max_end_time}
        else:
            result = {'token': token}

            if values['start_time'] is not None:
                result['start_time'] = min_start_time if min_start_time is not None and min_start_time < values[
                    'start_time'] else values['start_time']
            else:
                result['start_time'] = max_end_time

            if values['end_time'] is not None:
                result['end_time'] = max_end_time if max_end_time is not None and max_end_time > values['end_time'] \
                    else values['end_time']
            else:
                result['end_time'] = max_end_time
            return result

    def save_data_db(self, log_group, log_stream, values):
        """Insert the token, start_time and end_time values into the DB. If the values already exist they will be
        updated instead.

        Parameters
        ----------
        log_group : str
            Name of the log group
        log_stream : str
            Name of the log stream
        values : dict
            Dict containing the token, start_time and end_time.
        """
        aws_tools.debug('Saving data for log group "{}" and log stream "{}".'.format(log_group, log_stream), 1)
        aws_tools.debug('The saved values are "{}"'.format(values), 2)
        try:
            self.db_cursor.execute(self.sql_cloudwatch_insert.format(table_name=self.db_table_name), {
                'aws_region': self.region,
                'aws_log_group': log_group,
                'aws_log_stream': log_stream,
                'next_token': values['token'],
                'start_time': values['start_time'],
                'end_time': values['end_time']})
        except sqlite3.IntegrityError:
            aws_tools.debug("Some data already exists on DB for that key. Updating their values...", 2)
            self.db_cursor.execute(self.sql_cloudwatch_update.format(table_name=self.db_table_name), {
                'aws_region': self.region,
                'aws_log_group': log_group,
                'aws_log_stream': log_stream,
                'next_token': values['token'],
                'start_time': values['start_time'],
                'end_time': values['end_time']})

    def get_log_streams(self, log_group):
        """Get the list of log streams stored in the specified log group.

        Parameters
        ----------
        log_group : str
            Name of the log group to get its log streams

        Returns
        -------
        A list with the name of each log stream for the given log group.
        """

        result_list = list()
        aws_tools.debug('Getting log streams for "{}" log group'.format(log_group), 1)

        try:
            # Get all log streams using the token of the previous call to describe_log_streams
            response = self.client.describe_log_streams(logGroupName=log_group)
            log_streams = response['logStreams']
            token = response.get('nextToken')
            while token:
                response = self.client.describe_log_streams(logGroupName=log_group, nextToken=token)
                log_streams.extend(response['logStreams'])
                token = response.get('nextToken')

            for log_stream in log_streams:
                aws_tools.debug('Found "{}" log stream in {}'.format(log_stream['logStreamName'], log_group), 2)
                result_list.append(log_stream['logStreamName'])

            if result_list == list():
                aws_tools.debug('No log streams were found for log group "{}"'.format(log_group), 1)

        except botocore.exceptions.EndpointConnectionError as e:
            aws_tools.error(f'{str(e)}')
        except botocore.exceptions.ClientError as err:
            aws_tools.error(f'The "get_log_streams" request failed: {err}')
            sys.exit(16)
        except Exception:
            aws_tools.debug(
                '++++ The specified "{}" log group does not exist or insufficient privileges to access it.'.format(
                    log_group), 0)

        return result_list

    def purge_db(self, log_group):
        """Remove from AWS_Service.db any record for log streams that no longer exist on AWS CloudWatch Logs.

        Parameters
        ----------
        log group : str
            Name of the log group to check its log streams
        """
        aws_tools.debug('Purging the BD', 1)
        # Get the list of log streams from DB
        self.db_cursor.execute(self.sql_cloudwatch_select_logstreams.format(table_name=self.db_table_name), {
            'aws_region': self.region,
            'aws_log_group': log_group})
        query_result = self.db_cursor.fetchall()
        log_streams_sql = set()
        for log_stream in query_result:
            log_streams_sql.add(log_stream[0])

        # Get the list of log streams from AWS
        log_streams_aws = set(self.get_log_streams(log_group))

        # Check the difference and remove if applicable
        log_streams_to_purge = log_streams_sql - log_streams_aws
        if log_streams_to_purge != set():
            aws_tools.debug(
                'Data for the following log streams will be removed from {}: "{}"'.format(self.db_table_name,
                                                                                          log_streams_to_purge), 2)
        for log_stream in log_streams_to_purge:
            self.db_cursor.execute(self.sql_cloudwatch_purge.format(table_name=self.db_table_name), {
                'aws_region': self.region,
                'aws_log_group': log_group,
                'aws_log_stream': log_stream})
