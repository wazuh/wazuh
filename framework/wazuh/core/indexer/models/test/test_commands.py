from wazuh.core.indexer.models.commands import Command, Status, Source, Type


def test_command_from_dict():
    """Validate the correct functionality of the `Command.from_dict` method."""
    target_id = 'agent_id'
    target_type = Type.AGENT
    args = ['/bin/bash', '-c']
    document_id = 'id'
    info = 'info'
    status = 'pending'
    timeout = 100
    source = Source.SERVICES
    data = {
        'target': {'id': target_id, 'type': target_type},
        'action': {'args': args},
        'result': {'info': info},
        'status': status,
        'timeout': timeout,
        'source': source,
    }
    command = Command().from_dict(document_id, data)

    assert command.document_id == document_id
    assert command.target.id == target_id
    assert command.target.type == target_type
    assert command.action.args == args
    assert command.result.info == info
    assert command.status == Status.PENDING
    assert command.timeout == timeout
    assert command.source == source
