#!/usr/bin/env bash

sed -i 's,"mode": "white","mode": "black",g' /var/ossec/framework/python/lib/python3.7/site-packages/api-4.0.0-py3.7.egg/api/configuration.py
sed -i "s:    # policies = RBAChecker.run_testing():    policies = RBAChecker.run_testing():g" /var/ossec/framework/python/lib/python3.7/site-packages/wazuh-4.0.0-py3.7.egg/wazuh/rbac/preprocessor.py
permissions='[{"actions":["lists:read"],"resources":["list:path:etc/lists/amazon/aws-eventnames","list:path:etc/lists/audit-keys"],"effect":"deny"}]'
awk -v var="${permissions}" '{sub(/testing_policies = \[\]/, "testing_policies = " var)}1' /var/ossec/framework/python/lib/python3.7/site-packages/wazuh-4.0.0-py3.7.egg/wazuh/rbac/auth_context.py >> /var/ossec/framework/python/lib/python3.7/site-packages/wazuh-4.0.0-py3.7.egg/wazuh/rbac/auth_context1.py
cat /var/ossec/framework/python/lib/python3.7/site-packages/wazuh-4.0.0-py3.7.egg/wazuh/rbac/auth_context1.py > /var/ossec/framework/python/lib/python3.7/site-packages/wazuh-4.0.0-py3.7.egg/wazuh/rbac/auth_context.py
