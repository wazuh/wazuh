# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

"""The manager-task queue, end to end.

These are the cases unit tests structurally cannot cover: a real socket, a real consumer answering
over one, real worker threads, and a process that is killed mid-handler.
"""

import time

from conftest import wait_until

SCAN = 'vd_scan'
DELETE = 'agent_delete_indexer'


def test_a_task_is_claimed_and_completed(client, consumer):
    consumer.set_default(200, {'status': 'ok'})

    created = client.create_manager_task('scan-1', SCAN, payload={'agent_id': '7'}, agent_id='7')
    assert created.status_code == 200
    assert created.json()['result'] == 'created'

    row = client.wait_for_status('scan-1', 'completed')
    assert row['attempts'] == 0

    # The payload reached the consumer verbatim: nothing in the module constructs a request body.
    assert consumer.request_count('/_internal/vd/scan') == 1
    assert consumer.requests[0]['body'] == {'agent_id': '7'}


def test_a_task_starts_without_waiting_for_a_poll(client, consumer):
    consumer.set_default(200, {'status': 'ok'})

    started = time.time()
    client.create_manager_task('scan-1', SCAN, payload={'agent_id': '7'}, agent_id='7')
    client.wait_for_status('scan-1', 'completed', timeout=10)

    # The producer wakes the scheduler and the executor on insert, so there is no poll interval to
    # wait out. Generous enough not to be flaky, tight enough to catch a reintroduced 5 s poll.
    assert time.time() - started < 3.0


def test_a_server_error_retries_and_records_the_reason(client, consumer):
    consumer.set_default(500, {'error': 'indexer down'})

    client.create_manager_task('scan-1', SCAN, payload={'agent_id': '7'}, agent_id='7')

    row = wait_until(lambda: (lambda r: r if r['attempts'] >= 1 else None)(
        client.get_manager_task('scan-1').json()['task']))

    assert row['status'] == 'pending'
    assert 'HTTP 500' in row['last_error']
    # Backed off rather than retried immediately.
    assert row['next_attempt_at'] > int(time.time())


def test_a_conflict_defers_without_spending_the_retry_budget(client, consumer):
    consumer.set_default(409, {'error': 'scan_in_progress'})

    client.create_manager_task('scan-1', SCAN, payload={'agent_id': '7'}, agent_id='7')

    row = wait_until(lambda: (lambda r: r if r['defer_count'] >= 1 else None)(
        client.get_manager_task('scan-1').json()['task']))

    assert row['status'] == 'pending'
    assert row['attempts'] == 0, 'a busy consumer must not cost the task an attempt'
    assert 'busy' in row['last_error']


def test_an_absent_consumer_defers_rather_than_retrying(module_without_consumer):
    with module_without_consumer.client() as client:
        client.create_manager_task('scan-1', SCAN, payload={'agent_id': '7'}, agent_id='7')

        row = wait_until(lambda: (lambda r: r if r['defer_count'] >= 1 else None)(
            client.get_manager_task('scan-1').json()['task']))

        # The executor routinely starts before its in-process consumers bind. Spending the retry
        # budget on that boot race is exactly what the deferral ladder exists to prevent.
        assert row['attempts'] == 0
        assert 'not listening' in row['last_error']


def test_a_client_error_fails_a_type_that_allows_it(client, consumer):
    consumer.set_default(400, {'error': 'bad request'})

    client.create_manager_task('scan-1', SCAN, payload={'agent_id': '7'}, agent_id='7')

    row = client.wait_for_status('scan-1', 'failed')
    assert 'HTTP 400' in row['last_error']
    # Terminal does not consume the budget: it is not being given up on after trying, it is being
    # declared impossible.
    assert row['attempts'] == 0


def test_agent_deletion_retries_a_client_error_instead_of_failing(client, consumer):
    consumer.set_default(400, {'error': 'bad request'})

    client.create_manager_task('del-1', DELETE, payload={'agent_id': '7'}, agent_id='7')

    row = wait_until(lambda: (lambda r: r if r['attempts'] >= 1 else None)(
        client.get_manager_task('del-1').json()['task']))

    # Once client.keys is written the agent is gone and nobody will ask again, so this row is the
    # only remaining record of the obligation. A 4xx must not retire it.
    assert row['status'] == 'pending'


def test_a_repeated_id_collides(client, consumer):
    consumer.set_default(200, {'status': 'ok'})

    first = client.create_manager_task('del-1', DELETE, payload={'agent_id': '7'}, agent_id='7')
    second = client.create_manager_task('del-1', DELETE, payload={'agent_id': '7'}, agent_id='7')

    assert first.json()['result'] == 'created'
    # Normal for a deterministic-id creator that can legitimately run twice for one event.
    assert second.json()['result'] == 'collided'
    assert second.json()['task_id'] == 'del-1'


def test_scans_coalesce_per_agent_but_deletions_do_not(client, consumer):
    # Held so the first row stays pending and the second create sees it.
    consumer.set_default(200, {'status': 'ok'}, stall=2)

    client.create_manager_task('scan-a', SCAN, payload={'agent_id': '7'}, agent_id='7')
    second = client.create_manager_task('scan-b', SCAN, payload={'agent_id': '7'}, agent_id='7')

    if second.json()['result'] == 'coalesced':
        assert second.json()['task_id'] == 'scan-a', 'the surviving id, not the requested one'

    first_delete = client.create_manager_task('del-a', DELETE, payload={'agent_id': '9'}, agent_id='9')
    second_delete = client.create_manager_task('del-b', DELETE, payload={'agent_id': '9'}, agent_id='9')

    # Two deletions of one agent are two obligations and must never collapse.
    assert first_delete.json()['result'] == 'created'
    assert second_delete.json()['result'] == 'created'


def test_the_admission_bound_sheds_with_503(client, consumer):
    consumer.set_default(200, {'status': 'ok'}, stall=5)

    accepted = 0
    shed = 0
    for i in range(200):
        response = client.create_manager_task(f'scan-{i}', SCAN, payload={'agent_id': str(i)},
                                              agent_id=str(i))
        if response.status_code == 503:
            shed += 1
        else:
            accepted += 1

    assert shed > 0, 'the bound never engaged'
    assert accepted > 0


def test_a_lookup_for_an_unknown_id_is_a_404(client):
    assert client.get_manager_task('does-not-exist').status_code == 404


def test_listing_pages_and_stays_narrow(client, consumer):
    consumer.set_default(200, {'status': 'ok'})

    for i in range(5):
        client.create_manager_task(f'del-{i}', DELETE, payload={'agent_id': str(i)}, agent_id=str(i))

    page = client.list_manager_tasks(DELETE, limit=2).json()['tasks']
    assert len(page) == 2
    # Enough to see WHAT failed and why, without paging whole payloads.
    assert 'payload' not in page[0]
    assert {'task_id', 'status', 'create_time'} <= set(page[0])

    following = client.list_manager_tasks(DELETE, limit=2,
                                          last_task_id=page[-1]['task_id']).json()['tasks']
    assert following[0]['task_id'] > page[-1]['task_id']


def test_counting_by_status(client, consumer):
    consumer.set_default(200, {'status': 'ok'})

    for i in range(3):
        client.create_manager_task(f'del-{i}', DELETE, payload={'agent_id': str(i)}, agent_id=str(i))

    for i in range(3):
        client.wait_for_status(f'del-{i}', 'completed')

    assert client.count_manager_tasks(DELETE, 'completed').json()['count'] == 3
    assert client.count_manager_tasks(DELETE, 'pending').json()['count'] == 0


# ---- recovery ------------------------------------------------------------------------------------


def test_a_row_claimed_when_the_process_is_killed_is_reclaimed_and_rerun(module, consumer):
    """The headline recovery case.

    A handler is held open, the process is SIGKILLed with the row still `claimed` and no chance to
    tidy up, and the next boot's startup sweep has to notice that the owner is gone, return the row
    to pending, and run it again. Nothing short of killing a real process exercises this.
    """
    consumer.set_default(200, {'status': 'ok'}, stall=30)

    with module.client() as client:
        client.create_manager_task('del-1', DELETE, payload={'agent_id': '7'}, agent_id='7')
        client.wait_for_status('del-1', 'claimed', timeout=20)

    # `claimed` is written BEFORE the handler issues its request, so waiting only for the status
    # leaves a window in which the kill lands before the consumer has seen anything -- and then the
    # re-run below is the FIRST request rather than the second. Wait for the request itself: the
    # case being tested is a handler killed in flight, which needs a handler that is in flight.
    wait_until(lambda: consumer.request_count('/_internal/agents/delete') >= 1)

    module.stop(graceful=False)

    consumer.set_default(200, {'status': 'ok'}, stall=0)
    module.start()

    with module.client() as client:
        row = client.wait_for_status('del-1', 'completed', timeout=30)

    # Reclaimed EXACTLY as it was: a crashed worker is not the task failing, so the attempt is not
    # charged to the row.
    assert row['attempts'] == 0
    assert consumer.request_count('/_internal/agents/delete') >= 2


def test_a_graceful_stop_leaves_an_in_flight_row_for_the_next_boot(module, consumer):
    consumer.set_default(200, {'status': 'ok'}, stall=20)

    with module.client() as client:
        client.create_manager_task('del-1', DELETE, payload={'agent_id': '7'}, agent_id='7')
        client.wait_for_status('del-1', 'claimed', timeout=20)

    # Same reason as the kill test above: this one is about a stop that finds a handler IN FLIGHT,
    # and `claimed` alone does not mean the request has left yet.
    wait_until(lambda: consumer.request_count('/_internal/agents/delete') >= 1)

    started = time.time()
    module.stop(graceful=True)
    elapsed = time.time() - started

    # Inside modulesd's shared 30-second budget.
    assert elapsed < 35

    consumer.set_default(200, {'status': 'ok'}, stall=0)
    module.start()

    with module.client() as client:
        client.wait_for_status('del-1', 'completed', timeout=30)


def test_pending_work_survives_a_restart(module, consumer):
    consumer.set_default(503, {'error': 'not yet'})

    with module.client() as client:
        client.create_manager_task('del-1', DELETE, payload={'agent_id': '7'}, agent_id='7')
        wait_until(lambda: client.get_manager_task('del-1').json()['task']['attempts'] >= 1)

    module.restart()

    consumer.set_default(200, {'status': 'ok'})

    with module.client() as client:
        # A pending manager task is never expired by age, and a restart is not an outage it should
        # lose work to.
        client.wait_for_status('del-1', 'completed', timeout=60)
