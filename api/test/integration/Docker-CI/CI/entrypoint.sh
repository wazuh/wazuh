#!/usr/bin/env bash

sleep 5

pytest -vv /wazuh/api/test/integration/test_agentsGET_endpoints.tavern.yaml
pytest -vv /wazuh/api/test/integration/test_agentsPOST_endpoints.tavern.yaml
pytest -vv /wazuh/api/test/integration/test_agentsPUT_endpoints.tavern.yaml
pytest -vv /wazuh/api/test/integration/test_agentsDELETE_endpoints.tavern.yaml
...
...