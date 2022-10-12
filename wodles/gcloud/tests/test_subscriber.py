#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
#
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

"""Unit tests for subscriber module."""

import os
import sys
import pytest
from logging import Logger

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))  # noqa: E501
from pubsub.subscriber import WazuhGCloudSubscriber
import exceptions


def test_get_subscriber(gcloud_subscriber):
    """Check if an instance of WazuhGCloudSubscriber is created properly."""
    expected_attributes = ['logger', 'subscriber', 'subscription_path']

    assert isinstance(gcloud_subscriber, WazuhGCloudSubscriber)

    for attribute in expected_attributes:
        assert hasattr(gcloud_subscriber, attribute)


@pytest.mark.parametrize(
    'credentials_file,logger,project,subscription_id, exception, '
    'exception_name', [
        ('unexistent_file',
         None, 'test_project', 'test_subscription',
         exceptions.GCloudError, 'GCloudCredentialsNotFoundError'),

        ('invalid_credentials_file.json',
         None, 'test_project', 'test_subscription',
         exceptions.GCloudError, 'GCloudCredentialsStructureError')
    ])
def test_subscription_ko(credentials_file: str, logger: Logger,
                         project: str, subscription_id: str,
                         exception: exceptions.WazuhIntegrationException,
                         exception_name: str,
                         test_data_path: str):
    """
    Check that the appropriate exceptions are raised
    when the WazuhGCloudSubscriber constructor is called with
    wrong parameters.

    Parameters
    ----------
    credentials_file : str
        File with the GCP credentials.
    logger : Logger
        Logger used to capture the output of the module.
    project : str
        Name of the project.
    subscription_id : str
        ID of the subscription.
    exception : exceptions.WazuhIntegrationException
        Exception that should be raised by the module.
    exception_name : str
        Key of the exception in the exceptions.py file.
    test_data_path : str
        Path where the data folder is.
    """
    with pytest.raises(exception) as e:
        WazuhGCloudSubscriber(
            credentials_file=test_data_path + credentials_file,
            logger=logger, project=project, subscription_id=subscription_id)
    assert e.value.key == exception_name
