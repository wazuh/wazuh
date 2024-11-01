import pytest

from comms_api.core.utils import parse_agent_metadata
from wazuh.core.indexer.models.events import AgentMetadata


@pytest.mark.parametrize('agent_id, user_agent, agent_groups, expected', [
    (
        'ac5f7bed-363a-4095-bc19-5c1ebffd1be0',
        'test endpoint v5.0.0',
        '',
        AgentMetadata(
            id='ac5f7bed-363a-4095-bc19-5c1ebffd1be0',
            groups=[],
            name='test',
            type='endpoint',
            version='v5.0.0'
        )
    ),
    (
        'ac5f7bed-363a-4095-bc19-5c1ebffd1be0',
        'test2 lambda v5.0.1',
        'default,group1,group2',
        AgentMetadata(
            id='ac5f7bed-363a-4095-bc19-5c1ebffd1be0',
            groups=['default', 'group1', 'group2'],
            name='test2',
            type='lambda',
            version='v5.0.1'
        )
    ),
])
def test_parse_agent_metadata(agent_id, user_agent, agent_groups, expected):
    """Check that the `parse_agent_metadata` function works as expected."""
    agent_metadata = parse_agent_metadata(agent_id, user_agent, agent_groups)

    assert agent_metadata == expected
