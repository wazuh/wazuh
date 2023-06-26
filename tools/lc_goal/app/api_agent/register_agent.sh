#!/bin/bash


TOKEN=$(curl -u wazuh:wazuh -k -X POST "https://172.17.0.2:55000/security/user/authenticate?raw=true")

echo $TOKEN

request="$(curl -k -X POST -d '{"name":"api_agent"}' "https://172.17.0.2:55000/agents?pretty=true" -H "Content-Type:application/json" -H "Authorization: Bearer $TOKEN")"

echo "Request= $request"
echo $request|jq .

