import sys

from opensearchpy import OpenSearch

INDEX_NAME = "agents_list"


def create_indexer_client():
    host = "wazuh-indexer"
    port = 9200
    auth = ('admin', 'SecretPassword1%')

    print(f'Creating indexer client on host {host} and port {port}', file=sys.stderr)

    # TODO: configure SSL certificates
    return OpenSearch(
        hosts=[{'host': host, 'port': port}],
        http_compress=True,  # enables gzip compression for request bodies
        http_auth=auth,  # For testing only.
        use_ssl=True,
        verify_certs=False,
        ssl_assert_hostname=False,
        ssl_show_warn=False,
    )
