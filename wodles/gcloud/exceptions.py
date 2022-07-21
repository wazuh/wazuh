# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

"""This module contains the different exceptions that could be raised
   by the Gcloud package.
"""

import tools


UNKNOWN_ERROR_ERRCODE = 999


class WazuhIntegrationException(Exception):
    """Class that represents an exception for the Wazuh external integrations.

    Parameters
    ----------
    error : int
        Error key.
    kwargs : str
        Values of the error message that should be substituted.
    """
    def __init__(self, errcode: int, **kwargs):
        self._errcode = errcode
        info = self.__class__.ERRORS[errcode]
        self._message = info['message'].format(**kwargs) if kwargs else \
            info['message']
        self._key = info['key']
        super().__init__(f'{self.key}: {self.message}')

    @property
    def errcode(self):
        return self._errcode

    @property
    def key(self):
        return self._key

    @property
    def message(self):
        return self._message


class WazuhIntegrationInternalError(WazuhIntegrationException):
    """Class that represents a critical exception for the Wazuh external integrations."""
    ERRORS = {
        # 1-99 -> Internal errors
        1: {
            'key': 'GCloudWazuhNotRunning',
            'message': 'Wazuh must be running'
        },
        2: {
            'key': 'GCloudSocketError',
            'message': 'Error initializing {socket_path} socket'
        },
        3: {
            'key': 'GCloudSocketSendError',
            'message': 'Error sending event to Wazuh'
        },
    }

class GCloudError(WazuhIntegrationException):
    """Class that represents an error of the GCloud package."""
    ERRORS = {
        # 1000-1099 General errors
        1000: {
            'key': 'GCloudCredentialsStructureError',
            'message': "The '{credentials_file}' credentials file doesn't have the required structure"},
        1001: {
            'key': 'GCloudCredentialsNotFoundError',
            'message': "The '{credentials_file}' file doesn't exist"},
        1002: {
            'key': 'GCloudIntegrationTypeError',
            'message': 'Unsupported gcloud integration type: "{integration_type}".' f'The supported types are {*tools.valid_types,}'},
        1003: {
            'key': 'GCloudImportError',
            'message': "The '{package}' module is required"},

        # 1100-1199 -> GCP Bucket errors
        1100: {
            'key': 'GCloudBucketNotFound',
            'message': "The bucket '{bucket_name}' does not exist"},
        1101: {
            'key': 'GCloudBucketForbidden',
            'message': "The Service Account provided does not have {permissions} permissions to access the '{resource_name}' bucket or it does not exist in the account"},
        1102: {
            'key': 'GCloudBucketNumThreadsError',
            'message': 'The parameter -t/--num_threads only works with the Pub/Sub module.'},
        1103: {
            'key': 'GCloudBucketNameError',
            'message': 'The name of the bucket is required. Use -b <BUCKET_NAME> to specify it.'},
        1104: {
            'key': 'GCloudBucketLastProcessedFilesError',
            'message': 'Database error trying to get the last processed files for table_name={table_name}, project_id={project_id}, bucket_name={bucket_name}, prefix={prefix}'},

        # 1200-1299 -> Pub/Sub errors
        1200: {
            'key': 'GCloudPubSubNoSubscriptionID',
            'message': 'A subscription ID is required. Use -s <SUBSCRIPTION ID> to specify it.'},
        1201: {
            'key': 'GCloudPubSubNoProjectID',
            'message': 'A project ID is required. Use -p <PROJECT ID> to specify it.'},
        1202: {
            'key': 'GCloudPubSubNumThreadsError',
            'message': f'The minimum number of threads is {tools.min_num_threads}. Please check your configuration.'},
        1203: {
            'key':
            'GCloudPubSubNumMessagesError', 'message': f'The minimum number of messages is {tools.min_num_messages}. Please check your configuration.'},
        1204: {
            'key': 'GCloudPubSubSubscriptionError',
            'message': "The '{subscription}' subscription is incorrect or the user credentials are not valid"},
        1205: {
            'key': 'GCloudPubSubProjectError',
            'message': "The '{project}' project ID is incorrect or the user does not have permissions to access to it"},
        1206: {
            'key': 'GCloudPubSubForbidden',
            'message': "The client does not have the {permissions} required permissions"}
    }



