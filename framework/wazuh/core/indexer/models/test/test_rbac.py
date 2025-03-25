import base64
from unittest import mock

import pytest
from wazuh.core.indexer.models.rbac import User
from wazuh.core.indexer.utils import HASH_ALGO, ITERATIONS


class TestUser:
    """Validate the correct functionality of the `User` class."""

    model = User
    id = '0191480e-7f67-7fd3-8c52-f49a3176360c'
    name = 'test'
    password = '015fb915771223a3fdd7c0c0a5adcab8'

    @mock.patch('os.urandom')
    @mock.patch('wazuh.core.indexer.utils.pbkdf2_hmac')
    def test__post_init__(self, pbkdf2_hmac_mock, urandom_mock):
        """Check the correct function of `__post_init__` method."""
        salt = b'\xe5\xf3\x8c-\x97\r\xacL\xc2\\9:\xc8 \xe4F'
        hash_value = b'\xfc\x06\xb8\x1c&j\r\xcbP\xbb\xd7\xc4\xa4\x10\xa9:Np\xae\xf3\xc1m\x80\x16`\x96\x0e%g\r}\xb9'

        urandom_mock.return_value = salt
        pbkdf2_hmac_mock.return_value = hash_value

        user = User(raw_password=self.password)
        assert user.password.encode('latin-1') == base64.b64encode(salt + hash_value)

        urandom_mock.assert_called_once_with(16)
        pbkdf2_hmac_mock.assert_called_once_with(HASH_ALGO, self.password.encode('utf-8'), salt, ITERATIONS)

    @pytest.mark.parametrize('password,expected', [(password, True), ('test12345', False)])
    def test_check_password(self, password, expected):
        """Check the correct function of `check_password` method."""
        user = self.model(id=self.id, name=self.name, raw_password=self.password)
        assert user.check_password(password) == expected

    @pytest.mark.parametrize(
        'data,expected',
        [
            (
                {
                    'id': '1',
                    'name': 'test',
                    'password': 'test',
                    'allow_run_as': False,
                    'roles': [{'id': '1'}],
                    'created_at': 0,
                },
                {
                    'id': '1',
                    'name': 'test',
                    'password': 'test',
                    'allow_run_as': False,
                    'roles': [{'id': '1'}],
                    'created_at': 0,
                },
            ),
            (
                {
                    'id': '1',
                    'name': 'test',
                    'password': None,
                },
                {
                    'id': '1',
                    'name': 'test',
                },
            ),
        ],
    )
    def test_to_dict(self, data: dict, expected):
        """Check the correct function if `to_dict` method."""
        user = User(**data)
        assert user.to_dict() == expected
