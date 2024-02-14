class CustomException(Exception):
    PREFIX = 'U'
    ERRORS = {}

    def __init__(self, code: int, extra_msg: str = ''):
        self._code = code
        self._message = self.ERRORS[self._code]
        if extra_msg:
            self._message += f' - {extra_msg}'

    def __str__(self):
        return f'({self.PREFIX}{self._code}) {self._message}'


class HAPHelperError(CustomException):
    PREFIX = 'C'
    ERRORS = {100: 'Server status check timed out after adding new servers', 101: 'User configuration is not valid'}


class WazuhError(CustomException):
    PREFIX = 'W'
    ERRORS = {
        99: 'Cannot initialize Wazuh API',
        100: 'Unexpected error trying to connect to the Wazuh API',
        101: 'Unexpected response from the Wazuh API',
        102: 'Invalid credentials for the Wazuh API',
        103: 'The given Wazuh API user does not have permissions to make the request',
        104: 'Too many API requests retries',
    }


class ProxyError(CustomException):
    PREFIX = 'P'
    ERRORS = {
        99: 'Cannot initialize Proxy API',
        100: 'Unexpected error trying to connect to Proxy API',
        101: 'Unexpected response from the Proxy API',
        102: 'Invalid credentials for the Proxy API',
        103: 'Invalid HAProxy Dataplane API specification configured',
        104: 'Cannot detect a valid HAProxy process linked to the Dataplane API',
        105: 'Unexpected response from HAProxy Dataplane API',
    }
