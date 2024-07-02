import sys

from opensearchpy import OpenSearch
from datetime import datetime

AGENTS_INDEX_NAME = "agents_list"
TRACES_INDEX_NAME = "comms_api_traces"
METRICS_INDEX_NAME = "comms_api_metrics"


class IndexerClient:
    def __init__(self):
        self.host = "wazuh-indexer"
        self.port = 9200
        self.auth = ('admin', 'SecretPassword1%')  # For testing purposes only
        self.indexer_client = self.create_indexer_client(self.host, self.port, self.auth)

    @staticmethod
    def create_indexer_client(host, port, auth):
        print(f'Creating indexer client on host {host} and port {port}', file=sys.stderr)

        # TODO: configure SSL certificates
        return OpenSearch(
            hosts=[{'host': host, 'port': port}],
            http_compress=True,
            http_auth=auth,
            use_ssl=False,
            verify_certs=False,
            ssl_assert_hostname=False,
            ssl_show_warn=False,
        )

    def get_document(self, index_name, doc_id):
        """Wrapper"""
        return self.indexer_client.get(index=index_name, id=doc_id)

    def create_index(self, index_name: str = None):
        index_body = {
            'settings': {
                'index': {
                    'number_of_shards': 4
                }
            }
        }

        if not self.indexer_client.indices.exists(index=index_name):
            self.indexer_client.indices.create(
                index_name,
                body=index_body
            )
            print(f"Created index {index_name}", file=sys.stderr)

    def send_metrics(self, metrics_data, index_name: str = METRICS_INDEX_NAME):
        current_time = str(datetime.now())
        for metrics in metrics_data:
            print(f"Metric {metrics['scope']['name']}", file=sys.stderr)
            for metric in metrics['metrics']:
                print(f"Sending metric {metric['name']}", file=sys.stderr)
                try:
                    self.indexer_client.index(
                        index=index_name,
                        id=metric['name'] + current_time,
                        # TODO: Enhance common metrics body
                        body={
                            'unit': metric['unit'],
                            'data': metric['data']
                        },
                        op_type='create'
                    )
                    indexed_metric = self.get_document(index_name=index_name, doc_id=metric['name'])
                    print(f"Obtained metric {indexed_metric}", file=sys.stderr)
                except Exception as e:
                    raise e

    def send_spans(self):
        pass


indexer_client = IndexerClient()
