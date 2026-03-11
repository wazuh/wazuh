from wazuh.core.decorators import dapi_allower

def test_dapi_allower():
    """Test the dapi_allower decorator."""
    @dapi_allower
    def test_function():
        return "test"

    assert test_function() == "test"
    assert hasattr(test_function, "__wazuh_exposed__")
    assert test_function.__wazuh_exposed__ is True
