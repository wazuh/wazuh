import sys
from unittest.mock import MagicMock, patch

import pytest

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators

        del sys.modules['wazuh.rbac.orm']

        from wazuh.tests.util import RBAC_bypasser

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        from wazuh import analysis

@pytest.mark.asyncio
@patch('wazuh.analysis.node_type', 'master')
@patch('wazuh.analysis.send_reload_ruleset_and_get_results')
async def test_reload_ruleset_master_ok(mock_send_reload_ruleset_msg):
    """Test reload_ruleset() works as expected for master node with successful reload."""
    from wazuh.core.results import AffectedItemsWazuhResult
    mock_result = AffectedItemsWazuhResult()
    mock_result.affected_items.append({'name': 'test-node', 'msg': 'ok'})
    mock_result.total_affected_items = 1
    mock_result._failed_items = {}
    mock_send_reload_ruleset_msg.return_value = mock_result

    result = await analysis.reload_ruleset()
    assert isinstance(result, analysis.AffectedItemsWazuhResult)
    assert result.total_affected_items == 1
    assert result.failed_items == {}


@pytest.mark.asyncio
@patch('wazuh.analysis.node_type', 'master')
@patch('wazuh.analysis.send_reload_ruleset_and_get_results')
async def test_reload_ruleset_master_nok(mock_send_reload_ruleset_msg):
    """Test reload_ruleset() for master node with error in reload."""
    from wazuh.core.results import AffectedItemsWazuhResult
    mock_result = AffectedItemsWazuhResult()
    mock_result._failed_items = {'test-node': {'error': 1914}}
    mock_result._total_failed_items = 1
    mock_send_reload_ruleset_msg.return_value = mock_result

    result = await analysis.reload_ruleset()
    assert isinstance(result, analysis.AffectedItemsWazuhResult)
    assert result.total_failed_items == 1


@pytest.mark.asyncio
@patch('wazuh.analysis.node_type', 'worker')
@patch('wazuh.analysis.local_client.LocalClient')
async def test_reload_ruleset_worker_ok(mock_local_client):
    """Test reload_ruleset() works as expected for worker node with successful reload."""
    # Patch set_reload_ruleset_flag to be async and return a dict with 'success'
    from wazuh.core.results import AffectedItemsWazuhResult

    async def async_set_reload_ruleset_flag(lc):
        return {'success': True}

    with patch('wazuh.analysis.set_reload_ruleset_flag', side_effect=async_set_reload_ruleset_flag):
        result = await analysis.reload_ruleset()
        assert isinstance(result, analysis.AffectedItemsWazuhResult)
        assert result.total_affected_items == 1
        assert result.failed_items == {}


@pytest.mark.asyncio
@patch('wazuh.analysis.node_type', 'worker')
@patch('wazuh.analysis.local_client.LocalClient')
async def test_reload_ruleset_worker_nok(mock_local_client):
    """Test reload_ruleset() for worker node with error in reload."""
    from wazuh.core.results import AffectedItemsWazuhResult
    from wazuh.core.exception import WazuhError

    async def async_set_reload_ruleset_flag(lc):
        raise WazuhError(1914)

    with patch('wazuh.analysis.set_reload_ruleset_flag', side_effect=async_set_reload_ruleset_flag):
        result = await analysis.reload_ruleset()
        assert isinstance(result, analysis.AffectedItemsWazuhResult)
        assert result.total_failed_items == 1
