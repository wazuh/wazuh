import base64
from unittest import mock

import pytest
from wazuh.core.indexer.models.agent import HASH_ALGO, ITERATIONS, Agent


class TestAgent:
    """Test class for the Agent functionality."""

    model = Agent
    id = '0191480e-7f67-7fd3-8c52-f49a3176360c'
    key = '015fb915771223a3fdd7c0c0a5adcab8'
    name = 'test'

    def test_init(self):
        """Check the correct model initialization."""
        with mock.patch.object(self.model, 'hash_key') as hash_key_mock:
            Agent(id=self.id, name=self.name, raw_key=self.key)
            hash_key_mock.assert_called_once_with(self.key)

    @mock.patch('os.urandom')
    @mock.patch('hashlib.pbkdf2_hmac')
    def test_hash_key(self, pbkdf2_hmac_mock, urandom_mock):
        """Check the correct function of `hash_key` method."""
        salt = b'\xe5\xf3\x8c-\x97\r\xacL\xc2\\9:\xc8 \xe4F'
        hash_value = b'\xfc\x06\xb8\x1c&j\r\xcbP\xbb\xd7\xc4\xa4\x10\xa9:Np\xae\xf3\xc1m\x80\x16`\x96\x0e%g\r}\xb9'

        urandom_mock.return_value = salt
        pbkdf2_hmac_mock.return_value = hash_value

        assert Agent.hash_key(self.key) == base64.b64encode(salt + hash_value)

        urandom_mock.assert_called_once_with(16)
        pbkdf2_hmac_mock.assert_called_once_with(HASH_ALGO, self.key.encode('utf-8'), salt, ITERATIONS)

    @pytest.mark.parametrize('key,expected', [(key, True), ('test12345', False)])
    def test_check_key(self, key, expected):
        """Check the correct function of `check_key` method."""
        agent = self.model(id=self.id, name=self.name, raw_key=self.key)
        assert agent.check_key(key) == expected

    @pytest.mark.parametrize(
        'data,expected',
        [
            ({'groups': 'default,test'}, {'groups': 'default,test'}),
            ({'name': 'test'}, {'name': 'test'}),
        ],
    )
    def test_to_dict(self, data: dict, expected):
        """Check the correct function if `to_dict` method."""
        agent = Agent(**data)
        assert agent.to_dict() == expected
