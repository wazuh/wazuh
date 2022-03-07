# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

"""This module contains the different exceptions that could be raised
   by the Gcloud package.
"""

import tools


class GCloudException(Exception):
    """Class that represents a exception of the GCloud package."""
    pass


class GCloudCriticalError(GCloudException):
    """Class that represents a critical exception."""
    pass


class GCloudWazuhNotRunning(GCloudCriticalError):
    """
    Exception that indicates that Wazuh is not running.
    """
    def __init__(self):
        super().__init__('Wazuh must be running')


class GCloudSocketError(GCloudCriticalError):
    """
    Exception that indicates that there was an error occurred
    when initializing the analysid socket.

    Parameters
    ----------
    socket_path : str
        Path of the analysisd socket.
    """
    def __init__(self, socket_path: str):
        super().__init__(f'Error initializing {socket_path} socket')


class GCloudSocketSendError(GCloudCriticalError):
    """
    Exception that indicates that there was an error occurred
    when trying to send a log to the analysid socket.
    """
    def __init__(self, socket_path: str):
        super().__init__('Error sending event to Wazuh')


class GCloudCredentialsStructureError(GCloudException):
    """
    Exception that indicates that the credentials file used doesn't have
    the required structure.

    Parameters
    ----------
    credentials_file : str
        Path of the credentials file.
    """
    def __init__(self, credentials_file: str = ''):
        message = f"The '{credentials_file}' credentials file doesn't have"\
                   "the required structure"
        super().__init__(message)


class GCloudCredentialsNotFoundError(GCloudException):
    """
    Exception that indicates that the credentials file passed doesn't exist.

    Parameters
    ----------
    credentials_file : str
        Path of the credentials file.
    """
    def __init__(self, credentials_file: str = ''):
        message = f"The '{credentials_file}' file doesn't exist"
        super().__init__(message)


class GCloudIntegrationTypeError(GCloudException):
    """
    Exception that indicates that the module was called
    specifying an unsupported integration_type.

    Parameters
    ----------
    integration_type : str
        Integration type specified by the user.
    """
    def __init__(self, integration_type: str):
        message = ('Unsupported gcloud integration type: '
                   f'"{integration_type}". The supported types are'
                   f' {*tools.valid_types,}')
        super().__init__(message)


class GCloudBucketNotFound(GCloudException):
    """
    Exception that indicates that the required bucket doesn't exist.

    Parameters
    ----------
    bucket_name : str
        Bucket that wasn't found.
    """
    def __init__(self, bucket_name: str = ''):
        message = f"The bucket '{bucket_name}' does not exist"
        super().__init__(message)


class GCloudBucketForbidden(GCloudException):
    """
    Exception that indicates that the client doesn't have permissions
    to access the designated resource.

    Parameters
    ----------
    resource_name : str
        Resource that was being accessed.
    permissions : str
        Permissions that the client must have.
    """
    def __init__(self, resource_name: str, permissions: str = ''):
        message = 'The Service Account provided does not have '\
                  f"""{"'" + permissions + "' " if permissions else ""}""" \
                  f"permissions to access the '{resource_name}' bucket " \
                  "or it does not exist in the account"
        super().__init__(message)


class GCloudBucketNumThreadsError(GCloudException):
    """
    Exception that indicates that the Access Logs module was executed
    specifying a number of threads different than 1.
    """
    def __init__(self):
        message = 'The parameter -t/--num_threads only works with the '\
                  'Pub/Sub module.'
        super().__init__(message)


class GCloudBucketNameError(GCloudException):
    """
    Exception that indicates that the Access Logs module was executed
    specifying a number of threads different than 1.
    """
    def __init__(self):
        message = 'The name of the bucket is required. Use -b <BUCKET_NAME> '\
                  'to specify it.'
        super().__init__(message)


class GCloudPubSubNoSubscriptionID(GCloudException):
    """
    Exception that indicates that the Pub/Sub module was executed
    without specifying a subscription ID.
    """
    def __init__(self):
        message = 'A subscription ID is required. Use -s '\
            '<SUBSCRIPTION ID> to specify it.'
        super().__init__(message)


class GCloudPubSubNoProjectID(GCloudException):
    """
    Exception that indicates that the Pub/Sub module was executed
    without specifying a project ID.
    """
    def __init__(self):
        message = 'A project ID is required. Use -p <PROJECT ID> to '\
            'specify it.'
        super().__init__(message)


class GCloudPubSubNumThreadsError(GCloudException):
    """
    Exception that indicates that the Pub/Sub module was executed
    scecifying a wrong number of threads.
    """
    def __init__(self):
        message = f'The minimum number of threads is {tools.min_num_threads}.'\
            ' Please check your configuration.'
        super().__init__(message)


class GCloudPubSubNumMessagesError(GCloudException):
    """
    Exception that indicates that the Pub/Sub module was executed
    scecifying a wrong number of threads.
    """
    def __init__(self):
        message = 'The minimum number of messages is '\
                  f'{tools.min_num_messages}. Please check your configuration.'
        super().__init__(message)


class GCloudPubSubForbidden(GCloudException):
    """
    Exception that indicates that the client doesn't have the
    permissions required to consume PubSub logs.

    Parameters
    ----------
    permissions : str
        The permissions that the client should have.
    """
    def __init__(self, permissions: str = ''):
        if permissions:
            message = f"The client does not have the '{permissions}' "\
                "required permissions"
        else:
            message = 'No permissions for executing the wodle from this '\
                'subscription'
        super().__init__(message)


class GCloudPubSubSubscriptionError(GCloudException):
    """
    Exception that indicates that the subscription ID passed
    to the Pub/Sub module might have an error.

    Parameters
    ----------
    subscription : str
        The subscription specified.
    """
    def __init__(self, subscription: str):
        message = f"The '{subscription}' subscription is incorrect or the "\
            "user credentials are not valid"
        super().__init__(message)


class GCloudPubSubProjectError(GCloudException):
    """
    Exception that indicates that the project ID passed
    to the Pub/Sub module might have an error.

    Parameters
    ----------
    project_id : str
        The project specified.
    """
    def __init__(self, project: str):
        message = f"The '{project}' project ID is incorrect or the "\
            "user does not have permissions to access to it"
        super().__init__(message)
