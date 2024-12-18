import asyncio
import json
import logging
from typing import List

from fastapi import Request
from starlette.requests import ClientDisconnect

from comms_api.models.events import StatefulEvents
from wazuh.core.engine import get_engine_client
from wazuh.core.exception import WazuhError
from wazuh.core.indexer.base import IndexerKey
from wazuh.core.batcher.client import BatcherClient
from wazuh.core.batcher.mux_demux import MuxDemuxQueue, Packet
from wazuh.core.indexer.models.events import AgentMetadata, Header, Operation, TaskResult

HTTP_STATUS_OK = 200
HTTP_STATUS_PARTIAL_CONTENT = 206


async def send_stateful_events(events: StatefulEvents, batcher_queue: MuxDemuxQueue) -> List[TaskResult]:
    """Post new events to the batcher.

    Parameters
    ----------
    events : StatefulEvents
        Stateful events.
    batcher_queue : MuxDemuxQueue
        Queue used by the BatcherClient for processing.

    Returns
    -------
    List[TaskResult]
        List of results from the bulk tasks.
    """
    batcher_client = BatcherClient(queue=batcher_queue)
    return await send_events(events=events, batcher_client=batcher_client)


async def send_stateless_events(request: Request) -> None:
    """Send new events to the engine.

    Parameters
    ----------
    request : Request
        Incoming HTTP request.
    
    Raises
    ------
    WazuhError(2708)
        If the client closed the request before the server could process the stream.
    """
    try:
        async with get_engine_client() as engine_client:
            await engine_client.events.send(request.stream())
    except ClientDisconnect:
        raise WazuhError(2708)


async def parse_stateful_events(request: Request) -> StatefulEvents:
    """Parse stateful events body stream into an object.
    
    Parameters
    ----------
    request : Request
        Incoming HTTP request.
    
    Raises
    ------
    WazuhError(2708)
        If the client closed the request before the server could process the stream.
    WazuhError(2709)
        Invalid request body structure.
    
    Returns
    -------
    StatefulEvents
        Object containing the agent metadata, headers and events.
    """
    i: int = 0
    headers: List[Header] = []
    data: List[dict] = []

    try:
        async for chunk in request.stream():
            if len(chunk) == 0:
                continue

            parts = chunk.splitlines()

            if len(parts) < 2:
                raise WazuhError(2709)

            for part in parts:
                if len(part) == 0:
                    continue

                if i == 0:
                    agent_metadata = AgentMetadata.model_validate_json(part)
                elif i % 2 == 0:
                    data.append(json.loads(part))
                else:
                    header = Header.model_validate_json(part)
                    headers.append(header)
                    if header.operation == Operation.DELETE:
                        # Skip the counter increment, we don't expect event data after this header
                        continue

                i += 1
    except ClientDisconnect:
        raise WazuhError(2708)
    except json.JSONDecodeError as e:
        raise WazuhError(2709, extra_message=str(e))

    return StatefulEvents(agent_metadata=agent_metadata, headers=headers, data=data)


async def send_events(events: StatefulEvents, batcher_client: BatcherClient) -> List[TaskResult]:
    """Send events to the batcher.

    Parameters
    ----------
    events : StatefulEvents
        Stateful events.
    batcher_client : BatcherClient
        Client responsible for sending the events to the batcher and managing responses.

    Returns
    -------
    List[TaskResult]
        Indexer response for each one of the bulk tasks.
    """
    packet = Packet()
    i: int = 0

    # Sends the events to the batcher
    for header in events.headers:
        data = None
        if header.operation != Operation.DELETE:
            data = events.data[i]
            i += 1

        packet.build_and_add_item(agent_metadata=events.agent_metadata, header=header, data=data)

    batcher_client.send_event(packet)
    task = asyncio.create_task(
        (lambda u: batcher_client.get_response(u))(packet.id)
    )

    # Wait for all of them and create response
    tasks_results = await task
    return parse_tasks_results([item.content for item in tasks_results.items])


def parse_tasks_results(tasks_results: List[dict]) -> List[TaskResult]:
    """Parse tasks results.
    
    Parameters
    ----------
    tasks_results : List[dict]
        Tasks results dictionary list.
    
    Returns
    -------
    results : List[TaskResult]
        Tasks results object list.
    """
    results: List[TaskResult] = []

    for r in tasks_results:
        status = r[IndexerKey.STATUS]
        if status >= HTTP_STATUS_OK and status <= HTTP_STATUS_PARTIAL_CONTENT:
            task_result = TaskResult(
                index=r[IndexerKey._INDEX],
                id=r[IndexerKey._ID],
                result=r[IndexerKey.RESULT],
                status=status
            )
        else:
            if IndexerKey.ERROR not in r:
                error_reason = r[IndexerKey.RESULT]
            else:
                error_reason = r[IndexerKey.ERROR][IndexerKey.REASON]
                    
            task_result = TaskResult(
                index=r[IndexerKey._INDEX],
                id=r[IndexerKey._ID],
                result=error_reason,
                status=status,
            )

        results.append(task_result)

    return results
