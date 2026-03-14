import pytest

from wazuh.core.decorators import dapi_allower


def test_dapi_allower_sync_function():
    """Test the dapi_allower decorator with a synchronous function."""
    @dapi_allower()
    def test_function():
        return "test"

    assert test_function() == "test"
    assert hasattr(test_function, "__wazuh_exposed__")
    assert test_function.__wazuh_exposed__ is True
    assert test_function.__wrapped__() == "test"


def test_dapi_allower_sync_arguments():
    """Test that the decorator preserves positional and keyword arguments."""
    @dapi_allower()
    def test_function(a, b, c=0):
        return a + b + c

    assert test_function(1, 2) == 3
    assert test_function(1, 2, c=3) == 6


@pytest.mark.asyncio
async def test_dapi_allower_async_function():
    """Test the dapi_allower decorator with an asynchronous function."""
    @dapi_allower(is_async=True)
    async def test_function():
        return "async_test"

    result = await test_function()

    assert result == "async_test"
    assert hasattr(test_function, "__wazuh_exposed__")
    assert test_function.__wazuh_exposed__ is True


@pytest.mark.asyncio
async def test_dapi_allower_async_arguments():
    """Test async decorated functions with arguments."""
    @dapi_allower(is_async=True)
    async def test_function(a, b):
        return a * b

    result = await test_function(2, 3)

    assert result == 6
    assert test_function.__wazuh_exposed__ is True


def test_dapi_allower_preserves_metadata():
    """Test that the decorator preserves function metadata."""
    @dapi_allower()
    def test_function():
        """Original docstring."""
        return "ok"

    assert test_function.__name__ == "test_function"
    assert test_function.__doc__ == "Original docstring."


def test_dapi_allower_direct_call():
    """Test using the decorator as a function."""
    def test_function():
        return "test"

    decorated = dapi_allower()(test_function)

    assert decorated() == "test"
    assert hasattr(decorated, "__wazuh_exposed__")
    assert decorated.__wazuh_exposed__ is True