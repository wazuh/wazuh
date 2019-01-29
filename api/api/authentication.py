# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2


def check_user(user, password, required_scopes=None):
    return user == 'foo' and password == 'bar'


def check_token(token, required_scopes=None):
    return token == 'blablablablabla'
