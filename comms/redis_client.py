from redis import ConnectionPool, Redis, UnixDomainSocketConnection
import sys

SOCKET_PATH = "/run/redis.sock"


def create_redis_client() -> Redis:
    pool = ConnectionPool(connection_class=UnixDomainSocketConnection, path=SOCKET_PATH)
    client = Redis(connection_pool=pool)

    # TODO: use uvicorn logger
    print(f'Creating redis client on socket {SOCKET_PATH}', file=sys.stderr)

    active = client.ping()
    if not active:
        raise Exception("Unable to connect to the redis server")

    return client
