from opensearchpy import OpenSearch
from urllib.parse import urlparse
from wazuh.manager import read_ossec_conf
from wazuh import agent

import logging
import time

# Logger parameters
LOGGING_MSG_FORMAT = '%(asctime)s vuln-stated: %(levelname)s: %(message)s'
LOGGING_DATE_FORMAT = '%Y/%m/%d %H:%M:%S'
LOG_LEVELS = {0: logging.WARNING,
              1: logging.INFO,
              2: logging.DEBUG}

VD_INDEX_NAME = 'wazuh-states-vulnerabilities'


def set_logger():
    """Set the logger configuration."""
    logging.basicConfig(level=LOG_LEVELS.get(logging.DEBUG, logging.INFO), format=LOGGING_MSG_FORMAT,
                        datefmt=LOGGING_DATE_FORMAT)
    logging.getLogger('vuln-stated').setLevel(LOG_LEVELS.get(logging.DEBUG, logging.WARNING))


def obtain_indexer_conf():
    ossec_conf_vd = read_ossec_conf(section='indexer').to_dict()['affected_items'][0]['indexer']

    # For the production development it will be important to check if the `vulnerability-detection` section
    # is enabled.

    indexer_url = urlparse(ossec_conf_vd['hosts'][0])  # Parses the first defined indexer node.

    host = indexer_url.hostname
    port = indexer_url.port
    # Provide a CA bundle if you use intermediate CAs with your root CA.
    ca_certs_path = ossec_conf_vd['ssl']['certificate_authorities'][0]['ca'][0]
    client_cert_path = ossec_conf_vd['ssl']['certificate'][0]
    client_key_path = ossec_conf_vd['ssl']['key'][0]

    return {'host': host, 'port': port, 'ca_certs_path': ca_certs_path,
            'client_cert_path': client_cert_path, 'client_key_path': client_key_path}


def create_indexer_client(indexer_conf):
    host = indexer_conf['host']
    port = indexer_conf['port']
    # Create the client with SSL/TLS enabled, but hostname verification disabled.
    logging.info(f"Creating client on Host {host} and port {port}")
    return OpenSearch(
        hosts=[{'host': host, 'port': port}],
        http_compress=True,  # enables gzip compression for request bodies
        http_auth=('admin', 'SecretPassword'),  # For testing only.
        client_cert=indexer_conf['client_cert_path'],
        client_key=indexer_conf['client_key_path'],
        use_ssl=True,
        verify_certs=True,
        ssl_assert_hostname=False,
        ssl_show_warn=False,
        ca_certs=indexer_conf['ca_certs_path']
    )


# Create index template and new index
# Obtain indexer template from /var/ossec/templates/vd_states_template.json?
# def create_index(client):
#     try:
#         client.indices.put_template(name='wazuh-states-vulnerabilities')
#         client.indices.create(VD_INDEX_NAME, body=index_body)
#     except Exception as e:
#         logging.error("Error during template and index creation: {e}")


if __name__ == "__main__":
    set_logger()

    indexer_configuration = obtain_indexer_conf()
    client = create_indexer_client(indexer_configuration)

    # create_index(client)
    while True:
        # Ask wazuh-db the id and node of all agents whose last-keepalive is less than 30s
        # Obtain IDs and last keep alive from agents
        agents = agent.get_agents(select=["id", "lastKeepAlive"], q="id!=000").to_dict()['affected_items'] # TODO: add condition for keep alive difference less than 30 seconds?
        logging.info(f"{len(agents)} agents id and last keep alive obtained")

        # Ask the indexer, index by index, for the VD states of all agents who are reporting to each worker vd index
        # TODO: Needed: list of indinces with the prefix....

        # Using (if possible) the reindex API, index all the information gathered in the previous step in `vd-state`.
        # All fields that may change should be hashed and stored in the document ID.
        time.sleep(10)
