import pytest

from comms_api.models.error import Error

@pytest.mark.parametrize('message,code,status_code,expected', [
    ('value1', 1001, 500, '{"message": "value1", "code": 1001}'),
    ('value2', None, 2, '{"message": "value2", "code": 2}'),
    ('value1', None, 400, '{"message": "value1", "code": 400}'),
])
def test_error_render(message: str, code: int, status_code: int, expected: str):
    """Test Error class `render` method."""
    error = Error(message, code, status_code)
    actual = error.render()

    assert isinstance(actual, str)
    assert expected == actual

def test_error_render_none():
    """Test Error class `render` method with empty parameters."""
    message = 'value'
    expected = '{"message": "' + message + '", "code": 500}'
    error = Error(message)
    actual = error.render()

    assert isinstance(actual, str)
    assert expected == actual
