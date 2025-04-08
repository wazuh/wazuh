#!/usr/bin/env bash

INDEXER_USERNAME="admin"
INDEXER_PASSWORD="admin"
INDEXER_URL="https://wazuh-indexer:9200"
CONTENT_TYPE="Content-Type: application/json"

echo "Waiting for the indexer to be up..."

while [[ "$(curl -ksu $INDEXER_USERNAME:$INDEXER_PASSWORD -o /dev/null -w ''%{http_code}'' $INDEXER_URL)" != "200" ]]; do sleep 5; done

echo "Creating RBAC admin user..."

# Create wazuh user
curl -X POST -H "$CONTENT_TYPE" -ksu $INDEXER_USERNAME:$INDEXER_PASSWORD -w "\n" $INDEXER_URL/wazuh-internal-users/_doc/1 -d'
{
    "user": {
        "id": "1",
        "name": "wazuh",
        "password": "9UwarPXx85C67NpZPnkBKMM1By19GWSUnmAwyOP51EQC3ml4tM8CM9a1TFw0JRjs",
        "allow_run_as": true,
        "created_at": 0,
        "roles": [
            {
                "name": "administrator",
                "level": 0,
                "policies": [
                    {
                        "name": "agents_all",
                        "actions": ["agent:read", "agent:delete", "agent:modify_group", "agent:reconnect", "agent:restart"],
                        "resources": ["*:*:*"],
                        "effect": "allow",
                        "level": 0
                    },
                    {
                        "name": "groups_all",
                        "actions": ["group:read", "group:delete", "group:update_config", "group:modify_assignments"],
                        "resources": ["*:*:*"],
                        "effect": "allow",
                        "level": 0
                    }
                ],
                "rules": []
            }
        ]
    }
}'
