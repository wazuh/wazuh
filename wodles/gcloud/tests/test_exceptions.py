# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

# run test: python3 -m pytest gcloud/tests/test_exceptions.py -v --log-cli-level=DEBUG

import logging
import os
import sys

import pytest

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))  # noqa: E501
import exceptions

logger = logging.getLogger(__name__)


def test_unknown_error_errcode_value():
    logger.info(f"UNKNOWN_ERROR_ERRCODE => {exceptions.UNKNOWN_ERROR_ERRCODE}")
    assert exceptions.UNKNOWN_ERROR_ERRCODE == 999


class TestWazuhIntegrationException:
    def test_is_exception_subclass(self):
        assert issubclass(exceptions.WazuhIntegrationException, Exception)
        logger.info("WazuhIntegrationException is a subclass of Exception")

    def test_properties_accessible(self):
        exc = exceptions.WazuhIntegrationInternalError(errcode=1)
        logger.info(f"errcode={exc.errcode}, key={exc.key}, message={exc.message}")
        assert isinstance(exc.errcode, int)
        assert isinstance(exc.key, str)
        assert isinstance(exc.message, str)

    def test_str_includes_key_and_message(self):
        exc = exceptions.WazuhIntegrationInternalError(errcode=1)
        logger.info(f"str(exc) => {str(exc)}")
        assert str(exc) == f'{exc.key}: {exc.message}'


class TestWazuhIntegrationInternalError:
    def test_errcode_1_wazuh_not_running(self):
        exc = exceptions.WazuhIntegrationInternalError(errcode=1)
        logger.info(f"errcode=1 => key={exc.key}, message={exc.message}")
        assert exc.errcode == 1
        assert exc.key == 'GCloudWazuhNotRunning'
        assert exc.message == 'Wazuh must be running'

    def test_errcode_2_socket_error_with_kwargs(self):
        exc = exceptions.WazuhIntegrationInternalError(errcode=2, socket_path='/tmp/test.sock')
        logger.info(f"errcode=2 => message={exc.message}")
        assert exc.errcode == 2
        assert exc.key == 'GCloudSocketError'
        assert '/tmp/test.sock' in exc.message

    def test_errcode_3_socket_send_error(self):
        exc = exceptions.WazuhIntegrationInternalError(errcode=3)
        logger.info(f"errcode=3 => key={exc.key}, message={exc.message}")
        assert exc.errcode == 3
        assert exc.key == 'GCloudSocketSendError'
        assert exc.message == 'Error sending event to Wazuh'

    def test_is_subclass_of_wazuh_integration_exception(self):
        assert issubclass(
            exceptions.WazuhIntegrationInternalError,
            exceptions.WazuhIntegrationException,
        )
        logger.info("WazuhIntegrationInternalError is a subclass of WazuhIntegrationException")


class TestGCloudError:
    def test_errcode_1000_credentials_structure_error(self):
        exc = exceptions.GCloudError(errcode=1000, credentials_file='creds.json')
        logger.info(f"errcode=1000 => key={exc.key}, message={exc.message}")
        assert exc.key == 'GCloudCredentialsStructureError'
        assert 'creds.json' in exc.message

    def test_errcode_1001_credentials_not_found(self):
        exc = exceptions.GCloudError(errcode=1001, credentials_file='missing.json')
        logger.info(f"errcode=1001 => key={exc.key}, message={exc.message}")
        assert exc.key == 'GCloudCredentialsNotFoundError'
        assert 'missing.json' in exc.message

    def test_errcode_1002_integration_type_error(self):
        exc = exceptions.GCloudError(errcode=1002, integration_type='invalid_type')
        logger.info(f"errcode=1002 => key={exc.key}, message={exc.message}")
        assert exc.key == 'GCloudIntegrationTypeError'
        assert 'invalid_type' in exc.message

    def test_errcode_1003_import_error(self):
        exc = exceptions.GCloudError(errcode=1003, package='google-cloud-storage')
        logger.info(f"errcode=1003 => key={exc.key}, message={exc.message}")
        assert exc.key == 'GCloudImportError'
        assert 'google-cloud-storage' in exc.message

    def test_errcode_1100_bucket_not_found(self):
        exc = exceptions.GCloudError(errcode=1100, bucket_name='my-bucket')
        logger.info(f"errcode=1100 => key={exc.key}, message={exc.message}")
        assert exc.key == 'GCloudBucketNotFound'
        assert 'my-bucket' in exc.message

    def test_errcode_1101_bucket_forbidden(self):
        exc = exceptions.GCloudError(errcode=1101, permissions='read', resource_name='my-bucket')
        logger.info(f"errcode=1101 => key={exc.key}")
        assert exc.key == 'GCloudBucketForbidden'
        assert 'read' in exc.message
        assert 'my-bucket' in exc.message

    def test_errcode_1102_num_threads_error(self):
        exc = exceptions.GCloudError(errcode=1102)
        logger.info(f"errcode=1102 => message={exc.message}")
        assert exc.key == 'GCloudBucketNumThreadsError'
    
    def test_errcode_1103_bucket_name_error(self):
        exc = exceptions.GCloudError(errcode=1103)
        logger.info(f"errcode=1103 => message={exc.message}")
        assert exc.key == 'GCloudBucketNameError'
    
    def test_errcode_1104_bucket_last_processed_files_error(self):
        exc = exceptions.GCloudError(errcode=1104, table_name='access_logs', project_id='my-project', bucket_name='my-bucket', prefix='logs/')
        logger.info(f"errcode=1104 => message={exc.message}")
        assert exc.key == 'GCloudBucketLastProcessedFilesError'
        assert 'access_logs' in exc.message
        assert 'my-project' in exc.message
        assert 'my-bucket' in exc.message

    def test_errcode_1200_no_subscription_id(self):
        exc = exceptions.GCloudError(errcode=1200)
        logger.info(f"errcode=1200 => key={exc.key}")
        assert exc.key == 'GCloudPubSubNoSubscriptionID'
    
    def test_errcode_1201_no_project_id(self):
        exc = exceptions.GCloudError(errcode=1201)
        logger.info(f"errcode=1201 => key={exc.key}")
        assert exc.key == 'GCloudPubSubNoProjectID'

    def test_errcode_1202_pubsub_num_threads_error(self):
        exc = exceptions.GCloudError(errcode=1202)
        logger.info(f"errcode=1202 => key={exc.key}")
        assert exc.key == 'GCloudPubSubNumThreadsError'
    
    def test_errcode_1203_pubsub_num_messages_error(self):
        exc = exceptions.GCloudError(errcode=1203)
        logger.info(f"errcode=1203 => key={exc.key}")
        assert exc.key == 'GCloudPubSubNumMessagesError'

    def test_errcode_1204_subscription_error(self):
        exc = exceptions.GCloudError(errcode=1204, subscription='my-sub')
        logger.info(f"errcode=1204 => key={exc.key}, message={exc.message}")
        assert exc.key == 'GCloudPubSubSubscriptionError'
        assert 'my-sub' in exc.message
    
    def test_errcode_1205_project_error(self):
        exc = exceptions.GCloudError(errcode=1205, project='my-project')
        logger.info(f"errcode=1205 => key={exc.key}, message={exc.message}")
        assert exc.key == 'GCloudPubSubProjectError'
        assert 'my-project' in exc.message
    
    def test_errcode_1206_project_error(self):
        exc = exceptions.GCloudError(errcode=1206, permissions='publish')
        logger.info(f"errcode=1206 => key={exc.key}, message={exc.message}")
        assert exc.key == 'GCloudPubSubForbidden'
        assert 'publish' in exc.message

    def test_is_subclass_of_wazuh_integration_exception(self):
        assert issubclass(exceptions.GCloudError, exceptions.WazuhIntegrationException)
        logger.info("GCloudError is a subclass of WazuhIntegrationException")
