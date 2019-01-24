#!/usr/bin/env python3

import connexion

from api import encoder
from wazuh import Wazuh, WazuhException
from wazuh.cluster.cluster import read_config


def main():
    app = connexion.App(__name__, specification_dir='./swagger/')
    app.app.json_encoder = encoder.JSONEncoder
    app.add_api('swagger.yaml', arguments={'title': 'Wazuh API'})
    app.run(port=8080)


if __name__ == '__main__':

    wazuh = Wazuh(ossec_path='/var/ossec')
    cluster_config = read_config()
    executable_name = "Wazuh API"
    master_ip = cluster_config['nodes'][0]
    if cluster_config['node_type'] != 'master' and cluster_config['disabled'] == 'no':
        raise WazuhException(3019, {"EXECUTABLE_NAME": executable_name, "MASTER_IP": master_ip})
    main()
