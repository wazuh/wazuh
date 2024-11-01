from wazuh.core.indexer.models.commands import Action, Command, Result, Status, Source, Target, TargetType


def test_command_from_dict():
    """Validate the correct functionality of the `Command.from_dict` method."""
    document_id = 'id'
    status = 'pending'
    timeout = 100
    data = {
        'target': {'id': 'agent_id', 'type': TargetType.AGENT.value},
        'action': {'name': 'restart', 'args': ['/bin/bash', '-c'], 'version': 'v5.0.0'},
        'result': {'message': 'message'},
        'status': status,
        'timeout': timeout,
        'source': Source.SERVICES.value,
    }
    command = Command().from_dict(document_id, data)

    assert command.document_id == document_id
    assert command.target == Target(**data['target'])
    assert command.action == Action(**data['action'])
    assert command.result == Result(**data['result'])
    assert command.status == Status.PENDING
    assert command.timeout == timeout
    assert command.source == Source.SERVICES
