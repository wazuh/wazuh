#!/usr/bin/env bash

USERNAME="admin"
PASSWORD="admin"
INDEXER_URL="https://wazuh-indexer:9200"
CONTENT_TYPE="Content-Type: application/json"
POLICIES=("agents_all" "agents_read" "agents_create" "security_all" "users_all" "users_modify_run_as")
POLICIES_JSON=$(jq -c -n '$ARGS.positional' --args "${POLICIES[@]}")

echo "Waiting for the indexer to be up..."

while [[ "$(curl -ksu $USERNAME:$PASSWORD -o /dev/null -w ''%{http_code}'' $INDEXER_URL)" != "200" ]]; do sleep 5; done

echo "Creating default RBAC resources..."

# Create default policies
COUNT=1
for policy in ${POLICIES[@]}; do
    curl -X POST -H "$CONTENT_TYPE" -ksu $USERNAME:$PASSWORD -w "\n" $INDEXER_URL/wazuh-policies/_doc/$COUNT -d'
    {
        "policy": {
            "id": "'$COUNT'",
            "name": "'$policy'",
            "resources": ["*:*:*"],
            "effect": "allow",
            "level": 0,
            "created_at": 0
        }
    }'
    (( COUNT++ ))
done

# Create admin role
curl -X POST -H "$CONTENT_TYPE" -ksu $USERNAME:$PASSWORD -w "\n" $INDEXER_URL/wazuh-roles/_doc/1 -d'
{
    "role": {
        "id": "1",
        "name": "administrator",
        "policies": '$POLICIES_JSON',
        "rules": [],
        "level": 0,
        "created_at": 0
    }
}'

# Create wazuh user
curl -X POST -H "$CONTENT_TYPE" -ksu $USERNAME:$PASSWORD -w "\n" $INDEXER_URL/wazuh-users/_doc/1 -d'
{
    "user": {
        "id": "1",
        "name": "wazuh",
        "password": "9UwarPXx85C67NpZPnkBKMM1By19GWSUnmAwyOP51EQC3ml4tM8CM9a1TFw0JRjs",
        "allow_run_as": true,
        "roles": ["administrator"],
        "created_at": 0
    }
}'
