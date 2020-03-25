# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2


import os
from secrets import token_urlsafe
from shutil import chown
from time import time

from jose import JWTError, jwt
from werkzeug.exceptions import Unauthorized

from api.api_exception import APIException
from api.constants import SECURITY_PATH
from wazuh.rbac import preprocessor
from wazuh.rbac.orm import AuthenticationManager


def check_user(user, password, required_scopes=None):
    """Convenience method to use in openapi specification

    :param user: string Unique username
    :param password: string user password
    :param required_scopes:
    :return:
    """
    with AuthenticationManager() as auth_:
        if auth_.check_user(user, password):
            return {'sub': user,
                    'active': True
                    }


# Set JWT settings
JWT_ISSUER = 'wazuh'
JWT_LIFETIME_SECONDS = 36000
JWT_ALGORITHM = 'HS256'

# Generate secret file to keep safe or load existing secret
_secret_file_path = os.path.join(SECURITY_PATH, 'jwt_secret')
try:
    if not os.path.exists(_secret_file_path):
        JWT_SECRET = token_urlsafe(512)
        with open(_secret_file_path, mode='x') as secret_file:
            secret_file.write(JWT_SECRET)
        # Only if executing as root
        try:
            chown(_secret_file_path, 'root', 'ossec')
        except PermissionError:
            pass
        os.chmod(_secret_file_path, 0o640)
    else:
        with open(_secret_file_path, mode='r') as secret_file:
            JWT_SECRET = secret_file.readline()
except IOError as e:
    raise APIException(2002)


def generate_token(user_id=None, auth_context=None):
    """Generates an encoded jwt token. This method should be called once a user is properly logged on.

    :param user_id: Unique username
    :param auth_context: Authorization context of the current user
    :return: string jwt formatted string
    """
    # Add dummy rbac_policies for developing here
    if auth_context:
        rbac_policies = preprocessor.optimize_resources(auth_context=auth_context)
    else:
        rbac_policies = preprocessor.optimize_resources(user_id=user_id)

    timestamp = int(time())
    payload = {
        "iss": JWT_ISSUER,
        "iat": int(timestamp),
        "exp": int(timestamp + JWT_LIFETIME_SECONDS),
        "sub": str(user_id),
        "rbac_policies": rbac_policies,
        "valid": validation.key
    }

    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token):
    """Decodes a jwt formatted token. Raise an Unauthorized exception in case validation fails.

    :param token: string jwt formatted token
    :return: dict payload ot the token
    """
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if payload['valid'] != validation.key:
            raise Unauthorized
        else:
            return payload
    except JWTError as e:
        raise Unauthorized from e


def get_permissions(header):
    """Extracts RBAC info from JWT token in request header

    :param header: Connexion request header
    :return: RBAC mode (white or black list) and user permissions
    """
    # We strip "Bearer " from the Authorization header of the request to get the token
    jwt_token = header[7:]

    payload = decode_token(jwt_token)

    permissions = payload['rbac_policies']

    return permissions


class TokenValidation:
    def __init__(self, n=int(time())):
        self._key = n

    @property
    def key(self):
        return self._key

    @key.setter
    def key(self, value):
        self._key = value


validation = TokenValidation()
