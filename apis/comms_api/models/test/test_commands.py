import pytest

from comms_api.models.commands import CommandsResults
from wazuh.core.indexer.models.commands import Result, Status


async def test_check_status():
    """Verify that the `check_status` model validator works as expected."""
    results = [Result(id='id', status=Status.COMPLETED)]
    CommandsResults(results=results)


async def test_check_status_ko():
    """Verify that the `check_status` model validator raises an exception on an invalid status."""
    results = [Result(id='id', status=Status.SENT)]
    with pytest.raises(ValueError):
        CommandsResults(results=results)

