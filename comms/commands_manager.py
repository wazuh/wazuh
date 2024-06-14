import json
import multiprocessing
from redis import Redis
from time import sleep
from typing import List
import sys

from redis_client import create_redis_client


def main(agent_ids: List[str]):
    client = create_redis_client()

    try:
        send_commands(client, agent_ids)

        while True:
            sleep(10)
            send_commands(client, agent_ids)
    except Exception as e:
        print(f"Internal error: {e}")
        exit(1)

def send_commands(redis_client: Redis, agent_ids: List[str]):
    print("Generating new command", file=sys.stderr)
    command = {"id": "1", "type": "restart"}
    str_command = json.dumps(command)

    bulk = redis_client.pipeline(transaction=True)

    for uuid in agent_ids:
        bulk.rpush(uuid, str_command)

    bulk.execute()

def generate_commands(agent_ids: str):
    if not agent_ids:
        ## Mock ID to send the command to at least one agent
        agent_ids = "018fe477-31c8-7580-ae4a-e0b36713eb05"

    print(f"Agent IDs: {agent_ids}", file=sys.stderr)

    p = multiprocessing.Process(target=main, args=[agent_ids.split(",")])
    p.start()
