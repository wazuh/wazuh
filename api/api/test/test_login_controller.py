# coding: utf-8

from __future__ import absolute_import

from flask import json
from six import BytesIO

from api.models.token_response import TokenResponseModel  # noqa: E501
from api.test import BaseTestCase


class TestLoginController(BaseTestCase):
    """LoginController integration test stubs"""

    def test_login_user(self):
        """Test case for login_user

        User/password authentication to get an access token
        """
        response = self.client.open(
            '/token',
            method='GET')
        self.assert200(response,
                       'Response body is : ' + response.data.decode('utf-8'))


if __name__ == '__main__':
    import unittest
    unittest.main()
