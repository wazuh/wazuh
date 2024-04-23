from opensearchpy import OpenSearch
from urllib.parse import urlparse
from wazuh.manager import read_ossec_conf
from wazuh import agent

import json
import logging
import sys
import time

# Logger parameters
LOGGING_MSG_FORMAT = '%(asctime)s vuln-stated: %(levelname)s: %(message)s'
LOGGING_DATE_FORMAT = '%Y/%m/%d %H:%M:%S'
LOG_LEVELS = {0: logging.WARNING,
              1: logging.INFO,
              2: logging.DEBUG}

DEFAULT_CLUSTER_NAME= 'wazuh'
TEMPLATE_PATH = '/var/ossec/templates/vd_states_template.json'
VD_INDEX_BASE_NAME = 'wazuh-states-vulnerabilities'


def set_logger():
    """Set the logger configuration."""
    logging.basicConfig(level=LOG_LEVELS.get(logging.DEBUG, logging.INFO), format=LOGGING_MSG_FORMAT,
                        datefmt=LOGGING_DATE_FORMAT)
    logging.getLogger('vuln-stated').setLevel(LOG_LEVELS.get(logging.DEBUG, logging.WARNING))


def create_indexer_client(config: dict):
    # For the production development it will be important to check if the `vulnerability-detection` section
    # is enabled.
    indexer_config = config['indexer']

    # Parse the first defined indexer node.
    # TODO: what should we do if there are many hosts and many ssl certificates?
    indexer_url = urlparse(indexer_config['hosts'][0])

    # Provide a CA bundle if you use intermediate CAs with your root CA.
    ca_certs_path = indexer_config['ssl']['certificate_authorities'][0]['ca'][0]
    client_cert_path = indexer_config['ssl']['certificate'][0]
    client_key_path = indexer_config['ssl']['key'][0]

    logging.info(f'Creating client on host {indexer_url.hostname} and port {indexer_url.port}')

    # Create the client with SSL/TLS enabled, but hostname verification disabled.
    return OpenSearch(
        hosts=[{'host': indexer_url.hostname, 'port': indexer_url.port}],
        http_compress=True,  # enables gzip compression for request bodies
        http_auth=('admin', 'SecretPassword'),  # For testing only.
        client_cert=client_cert_path,
        client_key=client_key_path,
        use_ssl=True,
        verify_certs=True,
        ssl_assert_hostname=False,
        ssl_show_warn=False,
        ca_certs=ca_certs_path
    )


def create_index(client: OpenSearch, index_name: str):
    logging.info('Creating consolidated index')
    try:
        with open(TEMPLATE_PATH, 'r') as f:
            template = f.read()
            template_body = json.loads(template)

        # Replace index pattern to match indices from different cluster and nodes
        template_body['index_patterns'] = f'{VD_INDEX_BASE_NAME}*'
        # TODO: without deleting the priority it fails with "unknown key [priority] in the template". Validate with the indexer team
        del template_body['priority']
        client.indices.put_template(name=index_name, body=template_body)

        index_body = template_body['template']
        client.indices.create(index=index_name, body=index_body)
    except Exception as e:
        logging.error(f"Error during index creation: {e}")


def consolidate_agents_vd_state(data: list) -> list:
    # TODO: here we should filter the information gathered from the different indices and consolidated it in such a way
    # that we end up with the latest information only.
    return data


if __name__ == "__main__":
    set_logger()

    config = read_ossec_conf().to_dict()['affected_items'][0]

    if not config['vulnerability-detection']['enabled']:
        logging.info('Vulnerability detection is disabled. Exiting...')
        sys.exit(0)

    client = create_indexer_client(config)
    if not client.ping():
        logging.error('Couldn\'t connect to the indexer')

    cluster_name = config['cluster']['name']
    consolidated_index_name = f'{VD_INDEX_BASE_NAME}-{cluster_name}'

    # Create consolidated index if it not exists yet
    if not client.indices.exists(consolidated_index_name):
        create_index(client, consolidated_index_name)

    select = ['id', 'node_name', 'lastKeepAlive']
    query = 'lastKeepAlive<30s'
    index_regex = VD_INDEX_BASE_NAME+'*'

    while True:
        # Ask wazuh-db the id and node of all agents whose last-keepalive is less than 30s
        # Obtain IDs and last keep alive from agents
        agents = agent.get_agents(select=select, q=query).to_dict()['affected_items']
        logging.info(f"{len(agents)} agents obtained")

        # Get the indices where the agents' VD state is stored
        indices = client.indices.get(index=index_regex)

        # Option 1: consolidating the information manually
        data = []
        for index in indices:
            hits = client.search(index=index)['hits']
            data.append(hits)

        consolidated_data = consolidate_agents_vd_state(data)
        client.indices.create(index=consolidated_index_name, body=consolidated_data)

        # Option 2: combine documents from all the indices into one.
        # https://opensearch.org/docs/latest/im-plugin/reindex-data/#combine-one-or-more-indexes
        # The number of shards of the source and destination indexes must be the same.
        # body = {
        #     'conflicts': 'proceed',
        #     'source': {
        #         'index': indices
        #     },
        #     'dest': {
        #         'index': consolidated_index_name
        #     }
        # }
        # client.reindex(body=body)

        time.sleep(10)
