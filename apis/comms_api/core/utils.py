
from wazuh.core.exception import WazuhError
from wazuh.core.indexer.models.events import AgentMetadata


def parse_agent_metadata(agent_id: str, user_agent: str, agent_groups: str) -> AgentMetadata:
    """Parse the agent metadata from the different HTTP headers values.
    
    Parameters
    ----------
    agent_id : str
        Agent ID.
    user_agent : str
        User-Agent HTTP header value.
    agent_groups : str
        Agent-Groups HTTP header value.

    Returns
    -------
    AgentMetadata
        Agent metadata.    
    """
    values = user_agent.split(' ', 2)
    if len(values) != 3:
        raise WazuhError(1764)
    
    name = values[0]
    type = values[1]
    version = values[2]
    groups = agent_groups.split(',') if agent_groups != '' else []

    return AgentMetadata(
        id=agent_id,
        groups=groups,
        name=name,
        type=type,
        version=version
    )
