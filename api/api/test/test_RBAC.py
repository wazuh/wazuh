# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
from unittest.mock import patch

import pytest

test_path = os.path.dirname(os.path.realpath(__file__))
test_data_path = os.path.join(test_path, 'data')
###

import api.RBAC.RBAC as rbac
from api.constants import SECURITY_PATH

db_path = os.path.join(SECURITY_PATH, 'RBAC.db')

with rbac.Roles as roles:
    roles.add(name='NewRole', role='NewRoleDefinition')


###

# @pytest.fixture(scope='module')
# def import_api_auth():
#     with patch('api.constants.SECURITY_PATH', new=test_data_path):
#         import api.authentication as auth
#         db_path = os.path.join(test_data_path, 'users.db')
#         secret_path = os.path.join(test_data_path, 'jwt_secret')
#         assert (os.path.exists(db_path))
#         assert (os.path.exists(secret_path))
#         yield auth
#         os.unlink(db_path)
#         os.unlink(secret_path)
#
#
# def test_database_init(import_api_auth):
#     """
#     Checks users db is properly initialized
#     """
#     with import_api_auth.AuthenticationManager() as am:
#         assert(am.check_user('wazuh', 'wazuh'))
#         assert(am.check_user('wazuh-app', 'wazuh-app'))
#
#
# def test_add_user(import_api_auth):
#     """
#     Checks users are added to database
#     """
#     with import_api_auth.AuthenticationManager() as am:
#         # New user
#         am.add_user('newuser', 'passwd')
#         assert(am.check_user('newuser', 'passwd'))
#
#         # Conflicting previously created user
#         assert(not am.add_user('newuser', 'other_passwd'))
#
#
# def test_check_user(import_api_auth):
#     """
#     Checks users are rejected if password does not match
#     """
#     with import_api_auth.AuthenticationManager() as am:
#         assert(not am.check_user('wazuh', 'wrong_pass'))
#
#
# def test_login_user(import_api_auth):
#     """
#     Checks tokens are generated properly
#     """
#     with import_api_auth.AuthenticationManager() as am:
#         token = am.login_user('wazuh', 'wazuh')
#         decoded_token = import_api_auth.decode_token(token)
#         assert(isinstance(decoded_token, dict))
#
#         assert(am.login_user('nonexists', 'pass') is None)
