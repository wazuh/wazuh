from opensearchpy import OpenSearch
from urllib.parse import urlparse
from wazuh.manager import read_ossec_conf
from wazuh.agent import get_agents

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
    indexer_config = config['indexer']

    # Parse the first defined indexer node.
    # TODO: if the first host is not reacheable, try to connecto to the other ones. If there are none, raise an error
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
        # TODO: without deleting the priority it fails with "unknown key [priority] in the template".
        # Validate with the indexer team
        del template_body['priority']
        client.indices.put_template(name=index_name, body=template_body)

        index_body = template_body['template']
        client.indices.create(index=index_name, body=index_body)
    except Exception as e:
        logging.error(f"Error during index creation: {e}")


def consolidate_agent_vd_state(documents: list, agent_id: str, node_name: str) -> list:
    # TODO: create a Document class to simplify information access and manipulation?
    consolidated_documents = []
    for idx, document in enumerate(documents):
        # Discard documents that belong to other agents or were indexed in other nodes. node_name is always the name of
        # the node the agent is currently connected to.
        agent = document['_source']['agent']
        if agent['id'] != agent_id or agent['ephemeral_id'] != node_name:
            continue

        # Remove the node name from the document ID. Include it in the source just to put it in the body later.
        document_id = remove_node_name(document['_id'])
        document['_source']['_id'] = document_id

        # If a document exists, it is updated; if it does not exist, a new document is indexed with the parameters
        # specified in the doc field
        consolidated_documents.append({'doc': document['_source'], 'doc_as_upsert': True})
        documents.pop(idx)

    return consolidated_documents


def remove_node_name(document_id: str) -> str:
    parts = document_id.split('_')
    document_id = parts[1] + '_' + parts[3]
    return document_id


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

    # Create consolidated index if it doesn't exist yet
    if not client.indices.exists(consolidated_index_name):
        create_index(client, consolidated_index_name)

    select = ['id', 'node_name']
    query = 'lastKeepAlive<30s'
    index_regex = consolidated_index_name+'*'

    while True:
        # Ask wazuh-db the id and node_name of all agents whose lastKeepAlive is less than 30s
        agents = get_agents(select=select, q=query).to_dict()['affected_items']
        if len(agents) == 0:
            logging.info(f"No agents found. Skipping...")
            time.sleep(10)
            continue

        logging.info(f"Found {len(agents)} agent/s")

        # Get the indices where the agents' VD state is stored
        #
        # TODO: we could avoid this request call by obtaining the cluster information from `cluster.get_nodes_info`
        # which uses the local client and construct the indices names ourselves.
        indices = client.indices.get(index=index_regex)
        logging.info(f"Found {len(indices)} indices matching the expression")

        # Collect the documents from all the indices
        documents = client.search(index=','.join(indices))['hits']['hits']
        if len(documents) == 0:
            logging.info(f"No documents found. Skipping...")
            time.sleep(10)
            continue

        logging.info(f"Found {len(documents)} documents")

        # Filter the documents agent by agent and discard the older ones
        consolidated_documents = []
        for a in agents:
            agent_id = a['id']
            logging.info(f"Consolidating agent {agent_id} vulnerability state")

            consolidated_docs = consolidate_agent_vd_state(documents, agent_id, a['node_name'])
            consolidated_documents.extend(consolidated_docs)

        # The body takes multiple actions and metadata separated by newlines.
        # See https://opensearch.org/docs/latest/api-reference/document-apis/bulk/#request-body
        body = ''
        for d in consolidated_documents:
            # TODO: find a cleaner way of getting the document ID rather than including it in the object and deleting it.
            body += '{"update":{"_index":"' + consolidated_index_name  + '","_id":"' + d['doc']['_id'] + '"}}\n'
            del d['doc']['_id']
            body += json.dumps(d)
            body += '\n'

        logging.info(f'Updating documents. Request body: {body}')
        # We are sending all the consolidated documents in a single request, shall we split them into multiple ones?
        response = client.bulk(index=consolidated_index_name, body=body)
        logging.info(f'Response: {response}')

        time.sleep(10)
