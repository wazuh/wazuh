import sys

from opensearchpy import AsyncOpenSearch

INDEX_NAME = "agents_list"


def create_indexer_client():
    host = "wazuh-indexer"
    port = 9200
    auth = ('admin', 'SecretPassword1%') # For testing purposes only

    print(f'Creating indexer client on host {host} and port {port}', file=sys.stderr)

    # TODO: configure SSL certificates
    return AsyncOpenSearch(
        hosts=[{'host': host, 'port': port}],
        http_compress=True,
        http_auth=auth,
        use_ssl=False,
        verify_certs=False,
        ssl_assert_hostname=False,
        ssl_show_warn=False,
    )
