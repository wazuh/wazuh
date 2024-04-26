from opensearchpy import OpenSearch
from urllib.parse import urlparse
from wazuh.manager import read_ossec_conf
from wazuh.agent import get_agents

import json
import logging
import sys
import time
import re

# Logger parameters
LOGGING_MSG_FORMAT = '%(asctime)s vuln-stated: %(levelname)s: %(message)s'
LOGGING_DATE_FORMAT = '%Y/%m/%d %H:%M:%S'
LOG_LEVELS = {0: logging.WARNING,
              1: logging.INFO,
              2: logging.DEBUG}

DEFAULT_CLUSTER_NAME = 'wazuh'
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


def consolidate_agent_vd_state(dictionary: dict, consolidated_documents: list, documents: list,
                               agent_ids: list) -> list:
    # TODO: create a Document class to simplify information access and manipulation?
    # TODO: do every 24 hours
    for doc in consolidated_documents:
        consolidated_agent_id = doc['_source']['agent']['id']

        if consolidated_agent_id not in agent_ids:
            logging.debug('Agent not exists')
            dictionary['to_delete'].append(doc['_id'])
            continue

    for document in documents:
        continue_outer_loop = False
        document_id = remove_node_name(document['_id'])
        agent = document['_source']['agent']

        for doc in consolidated_documents:
            if doc['_id'] == document_id:
                logging.debug('Continue outer loop')
                continue_outer_loop = True
                break

            id_regex = re.match(fr'{agent["id"]}_.*_{document["_source"]["vulnerability"]["id"]}', doc['_id'])
            if id_regex:
                logging.debug('Matched document regex')
                dictionary['to_delete'].append(doc['_id'])
                break

        if continue_outer_loop:
            continue

        dictionary['to_add'].append({'id': document_id, 'source': document['_source']})


def remove_node_name(document_id: str) -> str:
    return document_id[document_id.find('_') + 1:]


def build_request_body(consolidated_index_name: str, dictionary: dict) -> str:
    body = ''
    for document_id in dictionary['to_delete']:
        body += '{"delete":{"_index":"' + consolidated_index_name + '","_id":"' + document_id + '"}}\n'

    for document in dictionary['to_add']:
        body += '{"create":{"_index":"' + consolidated_index_name + '","_id":"' + document['id'] + '"}}\n'
        body += json.dumps(document['source'])
        body += '\n'

    return body


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
    created_consolidated_index = False
    if not client.indices.exists(consolidated_index_name):
        create_index(client, consolidated_index_name)
        created_consolidated_index = True

    select = ['id']
    query = 'lastKeepAlive<30s'
    index_regex = consolidated_index_name + '-*'

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

        consolidated_documents = []
        if not created_consolidated_index:
            consolidated_documents = client.search(index=consolidated_index_name)['hits']['hits']
            logging.info(f"Found {len(consolidated_documents)} consolidated documents")

        # Filter the documents agent by agent and discard the older ones
        dictionary = {'to_add': [], 'to_delete': []}
        agent_ids = [a['id'] for a in agents]
        consolidate_agent_vd_state(dictionary, consolidated_documents, documents, agent_ids)

        # The body takes multiple actions and metadata separated by newlines.
        # See https://opensearch.org/docs/latest/api-reference/document-apis/bulk/#request-body
        body = build_request_body(consolidated_index_name, dictionary)
        if body != '':
            logging.info(f'Updating documents. Request body: {body}')
            response = client.bulk(index=consolidated_index_name, body=body)
            logging.info(f'Response: {response}')
        else:
            logging.info('Consolidated index already up-to-date. Sleeping...')

        time.sleep(10)
