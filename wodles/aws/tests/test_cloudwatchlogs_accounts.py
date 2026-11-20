# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sqlite3
import sys
from unittest.mock import patch

import pytest
import boto3
from botocore.exceptions import ClientError, EndpointConnectionError, ReadTimeoutError
from botocore.stub import Stubber

sys.path.append(os.path.dirname(os.path.realpath(__file__)))
import aws_utils as utils
import cloudwatchlogs


ACCOUNT_A = '111111111111'
ACCOUNT_B = '222222222222'
GROUP = '/aws/events/shared'
VALUES_A = {'token': 'token-a', 'start_time': 100, 'end_time': 200}
VALUES_B = {'token': 'token-b', 'start_time': 300, 'end_time': 400}


@pytest.fixture()
def service_factory(tmp_path):
    """Use real, persistent SQLite state and mock only AWS and installation discovery."""
    instances = []

    def create(account, initialize=True, **kwargs):
        with patch('wazuh_integration.WazuhIntegration.get_sts_client') as sts, \
                patch('wazuh_integration.WazuhIntegration.default_config', return_value={}):
            sts.return_value.get_caller_identity.return_value = {'Account': account}
            instance = utils.get_mocked_service(
                class_=cloudwatchlogs.AWSCloudWatchLogs, region=utils.TEST_REGION,
                aws_log_groups=GROUP, **kwargs)
        instance.db_connector = sqlite3.connect(tmp_path / 'aws_services.db')
        instance.db_cursor = instance.db_connector.cursor()
        instances.append(instance)
        if initialize:
            instance.init_db(instance.sql_cloudwatch_create_table.format(table_name=instance.db_table_name))
        return instance

    yield create
    for instance in instances:
        instance.db_connector.close()


def test_cloudwatch_checkpoints_are_isolated_by_account(service_factory):
    """Equal group/stream names must not read or overwrite another account's checkpoint."""
    first = service_factory(ACCOUNT_A)
    first.save_data_db(GROUP, 'shared', VALUES_A)
    first.db_connector.commit()

    second = service_factory(ACCOUNT_B)
    assert second.get_data_from_db(GROUP, 'shared') is None
    second.save_data_db(GROUP, 'shared', VALUES_B)
    second.db_connector.commit()
    assert first.get_data_from_db(GROUP, 'shared') == VALUES_A
    assert second.get_data_from_db(GROUP, 'shared') == VALUES_B

    updated = dict(VALUES_B, end_time=500)
    second.save_data_db(GROUP, 'shared', updated)
    second.db_connector.commit()
    assert first.get_data_from_db(GROUP, 'shared') == VALUES_A
    assert second.get_data_from_db(GROUP, 'shared') == updated


def test_cloudwatch_purge_only_removes_current_account_streams(service_factory):
    """Cleanup must preserve other accounts, regions and log groups."""
    first = service_factory(ACCOUNT_A)
    first.save_data_db(GROUP, 'only-a', VALUES_A)
    first.save_data_db(GROUP, 'shared', VALUES_A)
    first.db_connector.commit()
    second = service_factory(ACCOUNT_B)
    second.save_data_db(GROUP, 'shared', VALUES_B)
    second.save_data_db(GROUP, 'deleted-b', VALUES_B)
    second.save_data_db('/other-group', 'deleted-b', VALUES_B)
    second.region = 'eu-west-1'
    second.save_data_db(GROUP, 'deleted-b', VALUES_B)
    second.region = utils.TEST_REGION
    with patch.object(second, 'get_log_streams', return_value=['shared']):
        second.purge_db(GROUP)
    second.db_connector.commit()

    assert first.get_data_from_db(GROUP, 'only-a') == VALUES_A
    assert first.get_data_from_db(GROUP, 'shared') == VALUES_A
    assert second.get_data_from_db(GROUP, 'shared') == VALUES_B
    assert second.get_data_from_db(GROUP, 'deleted-b') is None
    assert second.get_data_from_db('/other-group', 'deleted-b') == VALUES_B
    second.region = 'eu-west-1'
    assert second.get_data_from_db(GROUP, 'deleted-b') == VALUES_B


@pytest.mark.parametrize('partition', ['aws', 'aws-us-gov', 'aws-cn'])
def test_cloudwatch_uses_assumed_role_account(service_factory, partition):
    """The caller in the source account must not namespace the assumed role's logs."""
    instance = service_factory(ACCOUNT_A, iam_role_arn=f'arn:{partition}:iam::{ACCOUNT_B}:role/Reader')
    assert instance.account_id == ACCOUNT_B


def test_cloudwatch_roles_in_same_account_share_progress(service_factory):
    first = service_factory(ACCOUNT_A, iam_role_arn=f'arn:aws:iam::{ACCOUNT_B}:role/FirstReader')
    first.save_data_db(GROUP, 'shared', VALUES_B)
    first.db_connector.commit()
    second = service_factory(ACCOUNT_A, iam_role_arn=f'arn:aws:iam::{ACCOUNT_B}:role/SecondReader')
    assert second.get_data_from_db(GROUP, 'shared') == VALUES_B


def test_cloudwatch_alternating_collection_does_not_replay(service_factory):
    """Repeated collector invocations for two accounts forward each synthetic event once."""
    forwarded = []
    for account in [ACCOUNT_A, ACCOUNT_B, ACCOUNT_A, ACCOUNT_B, ACCOUNT_A]:
        instance = service_factory(account, only_logs_after='20220101')
        timestamp = instance.only_logs_after_millis + 1000

        def fetch(log_group, log_stream, token, start_time, end_time):
            if start_time <= timestamp and (end_time is None or timestamp < end_time):
                forwarded.append((account, log_stream))
                return {'token': f'{account}-{log_stream}', 'start_time': timestamp, 'end_time': timestamp}
            return None

        with patch.object(instance, 'get_log_streams', return_value=['shared', f'only-{account}']), \
                patch.object(instance, 'get_alerts_within_range', side_effect=fetch):
            instance.get_alerts()

    assert forwarded == [(ACCOUNT_A, 'shared'), (ACCOUNT_A, f'only-{ACCOUNT_A}'),
                         (ACCOUNT_B, 'shared'), (ACCOUNT_B, f'only-{ACCOUNT_B}')]


def test_cloudwatch_collection_with_stubbed_aws_responses(service_factory):
    """Exercise pagination, emission, SQLite and purge together, without AWS calls."""
    forwarded = []
    for cycle, account in enumerate([ACCOUNT_A, ACCOUNT_B, ACCOUNT_A, ACCOUNT_B]):
        instance = service_factory(account, only_logs_after='20220101')
        instance.client = boto3.client('logs', region_name=utils.TEST_REGION,
                                      aws_access_key_id='testing', aws_secret_access_key='testing')
        streams = ['shared', f'only-{account}']
        timestamp = instance.only_logs_after_millis + 1000
        with Stubber(instance.client) as stub, patch.object(instance, 'send_msg') as send:
            stream_response = {'logStreams': [{'logStreamName': name} for name in streams]}
            stub.add_response('describe_log_streams', stream_response, {'logGroupName': GROUP})
            for stream in streams:
                token = f'f/{account}/{stream}'
                parameters = {'logGroupName': GROUP, 'logStreamName': stream, 'startFromHead': True,
                              'startTime': instance.only_logs_after_millis if cycle < 2 else timestamp + 1}
                if cycle < 2:
                    stub.add_response('get_log_events', {
                        'events': [{'timestamp': timestamp, 'message': f'{account}/{stream}'}],
                        'nextForwardToken': token}, parameters)
                parameters = dict(parameters, nextToken=token)
                stub.add_response('get_log_events', {'events': [], 'nextForwardToken': token}, parameters)
            stub.add_response('describe_log_streams', stream_response, {'logGroupName': GROUP})
            instance.get_alerts()
            stub.assert_no_pending_responses()
            forwarded.extend(call.args[0] for call in send.call_args_list)
        instance.client.close()
    assert forwarded == [f'{account}/{stream}' for account in [ACCOUNT_A, ACCOUNT_B]
                         for stream in ['shared', f'only-{account}']]


def test_cloudwatch_new_installation_has_account_key(service_factory):
    instance = service_factory(ACCOUNT_A)
    columns = instance.db_cursor.execute('PRAGMA table_info(cloudwatch_logs)').fetchall()
    assert [row[1] for row in sorted(columns, key=lambda row: row[5]) if row[5]] == [
        'aws_account_id', 'aws_region', 'aws_log_group', 'aws_log_stream']
    assert instance.db_cursor.execute(
        "SELECT name FROM sqlite_master WHERE name='cloudwatch_logs_legacy'").fetchone() is None


def test_cloudwatch_upgrade_preserves_legacy_without_guessing_owner(service_factory):
    first = service_factory(ACCOUNT_A, initialize=False)
    utils.database_execute_script(first.db_connector, 'schema_cloudwatchlogs_legacy_test.sql')
    legacy = first.db_cursor.execute('SELECT * FROM cloudwatch_logs').fetchall()
    # Other services share the same database and must remain untouched.
    first.db_cursor.execute('CREATE TABLE other_service (checkpoint TEXT)')
    first.db_cursor.execute("INSERT INTO other_service VALUES ('keep')")
    first.db_connector.commit()

    with patch('cloudwatchlogs.aws_tools.debug') as debug:
        first.init_db(first.sql_cloudwatch_create_table.format(table_name=first.db_table_name))
    assert any('cloudwatch_logs_legacy' in call.args[0] for call in debug.call_args_list)
    assert first.db_cursor.execute('SELECT * FROM cloudwatch_logs_legacy').fetchall() == legacy
    assert first.db_cursor.execute('SELECT * FROM other_service').fetchall() == [('keep',)]
    assert first.get_data_from_db('test_log_group', 'test_stream') is None
    first.save_data_db(GROUP, 'shared', VALUES_A)
    first.close_db()

    # Restarting must neither repeat the migration nor reuse unowned state for B.
    with patch('cloudwatchlogs.aws_tools.debug') as debug:
        restarted = service_factory(ACCOUNT_A)
    assert not any('cloudwatch_logs_legacy' in call.args[0] for call in debug.call_args_list)
    assert restarted.get_data_from_db(GROUP, 'shared') == VALUES_A
    second = service_factory(ACCOUNT_B)
    assert second.get_data_from_db('test_log_group', 'test_stream') is None
    assert second.get_data_from_db(GROUP, 'shared') is None
    with patch.object(second, 'get_log_streams', return_value=[]):
        second.purge_db('test_log_group')
    assert second.db_cursor.execute('SELECT * FROM cloudwatch_logs_legacy').fetchall() == legacy


def test_cloudwatch_upgrade_rolls_back_on_creation_failure(service_factory):
    instance = service_factory(ACCOUNT_A, initialize=False)
    utils.database_execute_script(instance.db_connector, 'schema_cloudwatchlogs_legacy_test.sql')
    before = instance.db_cursor.execute('SELECT * FROM cloudwatch_logs').fetchall()
    with pytest.raises(sqlite3.OperationalError):
        instance.init_db('INVALID SQL')
    assert instance.db_cursor.execute('SELECT * FROM cloudwatch_logs').fetchall() == before
    assert instance.db_cursor.execute(
        "SELECT name FROM sqlite_master WHERE name='cloudwatch_logs_legacy'").fetchone() is None
    # The same installation can retry after the failure.
    instance.init_db(instance.sql_cloudwatch_create_table.format(table_name=instance.db_table_name))
    assert instance.db_cursor.execute('SELECT * FROM cloudwatch_logs_legacy').fetchall() == before


def test_cloudwatch_upgrade_does_not_overwrite_existing_legacy_backup(service_factory):
    instance = service_factory(ACCOUNT_A, initialize=False)
    utils.database_execute_script(instance.db_connector, 'schema_cloudwatchlogs_legacy_test.sql')
    instance.db_cursor.execute('CREATE TABLE cloudwatch_logs_legacy (checkpoint TEXT)')
    instance.db_cursor.execute("INSERT INTO cloudwatch_logs_legacy VALUES ('keep')")
    instance.db_connector.commit()
    with pytest.raises(sqlite3.OperationalError):
        instance.init_db(instance.sql_cloudwatch_create_table.format(table_name=instance.db_table_name))
    assert instance.db_cursor.execute('SELECT * FROM cloudwatch_logs_legacy').fetchall() == [('keep',)]
    assert instance.db_cursor.execute('SELECT COUNT(*) FROM cloudwatch_logs').fetchone() == (1,)


@pytest.mark.parametrize('only_logs_after', [None, '20220101'])
def test_cloudwatch_upgrade_uses_configured_collection_start(service_factory, only_logs_after):
    instance = service_factory(ACCOUNT_A, initialize=False, only_logs_after=only_logs_after)
    utils.database_execute_script(instance.db_connector, 'schema_cloudwatchlogs_legacy_test.sql')
    # Use the exact old stream name: its checkpoint must not be attributed to A.
    instance.log_group_list = ['test_log_group']
    with patch.object(instance, 'get_log_streams', return_value=['test_stream']), \
            patch.object(instance, 'get_alerts_within_range', return_value=None) as fetch:
        instance.get_alerts()
    fetch.assert_called_once_with(log_group='test_log_group', log_stream='test_stream', token=None,
                                  start_time=instance.only_logs_after_millis or instance.default_date_millis,
                                  end_time=None)


@pytest.mark.parametrize('after_first_page', [False, True])
@pytest.mark.parametrize('failure', [
    EndpointConnectionError(endpoint_url='https://logs.example.invalid'),
    ReadTimeoutError(endpoint_url='https://logs.example.invalid'),
    ClientError({'Error': {'Code': 'AccessDeniedException', 'Message': 'Denied'}}, 'DescribeLogStreams'),
    {'unexpected': 'response'},
], ids=['connection', 'timeout', 'access-denied', 'malformed-response'])
def test_cloudwatch_failed_listing_preserves_checkpoints(service_factory, failure, after_first_page):
    """An unavailable/incomplete inventory must never be treated as deleted streams."""
    instance = service_factory(ACCOUNT_A)
    instance.save_data_db(GROUP, 'keep', VALUES_A)
    instance.db_connector.commit()
    responses = [{'logStreams': [{'logStreamName': 'other'}], 'nextToken': 'next'}] if after_first_page else []
    instance.client.describe_log_streams.side_effect = responses + [failure]
    with pytest.raises(SystemExit) as error:
        instance.purge_db(GROUP)
    assert error.value.code == utils.THROTTLING_ERROR_CODE
    assert instance.get_data_from_db(GROUP, 'keep') == VALUES_A
    instance.close_db()
    restarted = service_factory(ACCOUNT_A)
    assert restarted.get_data_from_db(GROUP, 'keep') == VALUES_A


def test_cloudwatch_upgrade_keeps_original_error_after_sqlite_rollback(service_factory):
    """SQLite can roll back the transaction itself (e.g. SQLITE_FULL or a ROLLBACK trigger)."""
    instance = service_factory(ACCOUNT_A, initialize=False)
    utils.database_execute_script(instance.db_connector, 'schema_cloudwatchlogs_legacy_test.sql')
    before = instance.db_cursor.execute('SELECT * FROM cloudwatch_logs').fetchall()
    instance.db_cursor.executescript('''
        CREATE TABLE migration_failure (value TEXT);
        CREATE TRIGGER abort_migration BEFORE INSERT ON migration_failure
        BEGIN SELECT RAISE(ROLLBACK, 'simulated SQLite transaction rollback'); END;
    ''')
    with pytest.raises(sqlite3.IntegrityError, match='simulated SQLite transaction rollback'):
        instance.init_db("INSERT INTO migration_failure VALUES ('fail')")
    assert not instance.db_connector.in_transaction
    assert instance.db_cursor.execute('SELECT * FROM cloudwatch_logs').fetchall() == before
    assert instance.db_cursor.execute(
        "SELECT name FROM sqlite_master WHERE name='cloudwatch_logs_legacy'").fetchone() is None


def test_cloudwatch_collection_closes_database_after_upgrade_failure(service_factory):
    instance = service_factory(ACCOUNT_A, initialize=False)
    utils.database_execute_script(instance.db_connector, 'schema_cloudwatchlogs_legacy_test.sql')
    instance.db_cursor.execute('CREATE TABLE cloudwatch_logs_legacy (checkpoint TEXT)')
    instance.db_connector.commit()
    with pytest.raises(sqlite3.OperationalError, match='already another table'):
        instance.get_alerts()
    with pytest.raises(sqlite3.ProgrammingError, match='closed database'):
        instance.db_connector.execute('SELECT 1')
    # Failed migration must not leave a renamed/empty replacement table committed.
    restarted = service_factory(ACCOUNT_A, initialize=False)
    assert restarted.db_cursor.execute('SELECT COUNT(*) FROM cloudwatch_logs').fetchone() == (1,)
