import pytest

from comms_api.models.error import ErrorResponse


@pytest.mark.parametrize('message,code,status_code,expected', [
    ('value1', 1001, 500, '{"error": {"message": "value1", "code": 1001}}'),
    ('value2', None, 2, '{"error": {"message": "value2", "code": 2}}'),
    ('value1', None, 400, '{"error": {"message": "value1", "code": 400}}'),
])
def test_error_response_render(message: str, code: int, status_code: int, expected: str):
    """Test Error class `render` method."""
    error = ErrorResponse(message, code, status_code)
    actual = error.render()

    assert isinstance(actual, bytes)
    assert expected.encode() == actual


def test_error_response_render_none():
    """Test Error class `render` method with empty parameters."""
    message = 'value'
    expected = '{"error": {"message": "' + message + '", "code": 500}}'
    error = ErrorResponse(message)
    actual = error.render()

    assert isinstance(actual, bytes)
    assert expected.encode() == actual
