# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

"""Agent tasks over the real socket."""

import time


def test_create_and_take_over_the_socket(client):
    created = client.create_agent_task('001', payload={'reason': 'test'})
    assert created.status_code == 200
    task_id = created.json()['task_id']

    taken = client.take_pending('001')
    assert taken.status_code == 200

    tasks = taken.json()['tasks']
    assert len(tasks) == 1
    assert tasks[0]['task_id'] == task_id
    assert tasks[0]['task_type'] == 'agent_restart'
    # Handed back as an object, not as a string containing one.
    assert tasks[0]['payload'] == {'reason': 'test'}


def test_a_task_is_handed_out_once(client):
    client.create_agent_task('001')

    assert len(client.take_pending('001').json()['tasks']) == 1

    # Marking on read is the preserved behaviour: delivery is the caller's job, and remoted keeps
    # its own retry list for what it could not hand over.
    assert client.take_pending('001').json()['tasks'] == []


def test_the_same_request_twice_is_one_task(client):
    create_time = int(time.time())

    first = client.create_agent_task('001', create_time=create_time)
    second = client.create_agent_task('001', create_time=create_time)

    assert first.json()['task_id'] == second.json()['task_id']
    assert len(client.take_pending('001').json()['tasks']) == 1


def test_tasks_are_scoped_to_their_agent(client):
    client.create_agent_task('001')
    client.create_agent_task('002')

    assert len(client.take_pending('001').json()['tasks']) == 1
    assert len(client.take_pending('002').json()['tasks']) == 1


def test_bulk_creation_is_one_request(client):
    now = int(time.time())
    tasks = [
        {'agent_id': f'{i:03d}', 'task_type': 'agent_restart', 'create_time': now, 'payload': {}}
        for i in range(1, 51)
    ]

    response = client.create_agent_tasks(tasks)
    assert response.status_code == 200

    results = response.json()['results']
    assert len(results) == 50
    assert all(r['created'] for r in results)

    # Every one is retrievable, so the batch really was written rather than merely acknowledged.
    for i in range(1, 51):
        assert len(client.take_pending(f'{i:03d}').json()['tasks']) == 1


def test_a_malformed_entry_rejects_the_whole_batch(client):
    now = int(time.time())
    response = client.create_agent_tasks([
        {'agent_id': '001', 'task_type': 'agent_restart', 'create_time': now, 'payload': {}},
        {'agent_id': '002', 'create_time': now, 'payload': {}},  # no task_type
    ])

    assert response.status_code == 400

    # Validated before anything is written, so a bad entry cannot leave half a fleet restarted.
    assert client.take_pending('001').json()['tasks'] == []


def test_an_oversized_payload_is_refused(client):
    response = client.create_agent_task('001', payload={'blob': 'x' * (2 * 1024 * 1024)})
    assert response.status_code == 413


def test_a_future_timestamp_is_refused(client):
    response = client.create_agent_task('001', create_time=int(time.time()) + 86400)
    assert response.status_code == 400
    assert response.json()['message'] == 'Timestamp is in the future'


def test_invalid_json_is_refused(client):
    raw = client._client.post('http://localhost/v1/tasks', content='{not json',
                              headers={'Content-Type': 'application/json'})
    assert raw.status_code == 400
    assert raw.json()['error'] == 'invalid_json'


def test_an_unknown_route_is_a_404(client):
    assert client.post('/v1/nope', {}).status_code == 404


def test_the_liveness_probe_answers(client):
    response = client.health()
    assert response.status_code == 200
    assert response.json()['status'] == 'ok'


def test_agent_tasks_survive_a_restart(module, client):
    client.create_agent_task('001')
    client.close()

    module.restart()

    with module.client() as after:
        # The database is the point: a task created before the restart is still there afterwards.
        assert len(after.take_pending('001').json()['tasks']) == 1
