from wazuh.core.indexer.models.commands import Command, Status, CommandAgent


def test_command_from_dict():
    """Validate the correct functionality of the `Command.from_dict` method."""
    agent_id = 'agent_id'
    args = ['/bin/bash', '-c']
    id = 'id'
    info = 'info'
    status = 'pending'
    data = {'agent': {'id': agent_id}, 'args': args, 'info': info, 'status': status}
    command = Command().from_dict(id, data)

    assert command.agent == CommandAgent(id=agent_id)
    assert command.args == args
    assert command.id == id
    assert command.info == info
    assert command.status == Status.PENDING
